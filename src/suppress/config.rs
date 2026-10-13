//! The `--config` file: a TOML document holding suppression entries.
//!
//! ```toml
//! version = 1
//!
//! [[suppress]]
//! rule = "sensitive-key"          # required; a known rule code
//! key = "docs/examples/id_rsa"    # exactly one of key (exact) or prefix
//! reason = "Public example key"   # required, non-blank
//! expires = 2027-01-31            # optional; a TOML date or a "YYYY-MM-DD" string
//! bucket = "my-bucket"            # optional; only applies when scanning this bucket
//! ```
//!
//! Loaded only from an explicit `--config` path, never discovered. Every
//! problem with the file is a [`LakeScanError::Usage`] naming the file and,
//! where there is one, the offending `[[suppress]]` entry (by 1-based
//! position and line) — an audit should refuse to start on a config it
//! cannot fully understand rather than silently ignore part of it.

use std::fmt;
use std::path::Path;

use serde::Deserialize;
use toml::Spanned;

use super::date::Date;
use crate::error::LakeScanError;
use crate::model::RuleId;

/// The most `[[suppress]]` entries one file may hold. This cap, together
/// with the per-field caps below, is what bounds the suppressor's memory.
pub const MAX_ENTRIES: usize = 10_000;

/// The longest `key` or `prefix` accepted: S3's own key-length limit, so a
/// longer one could never match anything.
const MAX_KEY_BYTES: usize = 1024;

/// The longest `reason` accepted.
const MAX_REASON_BYTES: usize = 1024;

/// The longest `bucket` accepted: S3's own bucket-name limit.
const MAX_BUCKET_BYTES: usize = 63;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    version: i64,
    #[serde(default)]
    suppress: Vec<Spanned<RawEntry>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    rule: String,
    key: Option<String>,
    prefix: Option<String>,
    reason: String,
    /// A `toml::Value` rather than a typed field, so both an unquoted TOML
    /// date and a quoted string are accepted and validated in one place.
    expires: Option<toml::Value>,
    bucket: Option<String>,
}

/// Which keys an entry covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    /// Exactly this key.
    Key(String),
    /// Every key starting with this prefix; `""` covers every key.
    Prefix(String),
}

impl Pattern {
    /// Whether this pattern covers `key`.
    #[must_use]
    pub fn matches(&self, key: &str) -> bool {
        match self {
            Self::Key(exact) => exact == key,
            Self::Prefix(prefix) => key.starts_with(prefix.as_str()),
        }
    }
}

impl fmt::Display for Pattern {
    /// `key "…"` or `prefix "…"`, the value `Debug`-quoted so control
    /// characters in a config string cannot reach a terminal raw.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(key) => write!(f, "key {key:?}"),
            Self::Prefix(prefix) => write!(f, "prefix {prefix:?}"),
        }
    }
}

/// One validated `[[suppress]]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The rule whose findings this entry suppresses.
    pub rule: RuleId,
    /// The keys it covers.
    pub pattern: Pattern,
    /// Why the suppression exists; never blank.
    pub reason: String,
    /// The last date (UTC) the entry applies on, if it expires.
    pub expires: Option<Date>,
    /// The only bucket the entry applies to, if restricted.
    pub bucket: Option<String>,
}

/// A validated config file: its entries, in file order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    entries: Vec<Entry>,
}

impl Config {
    /// Reads and validates the config file at `path`.
    ///
    /// # Errors
    /// Returns [`LakeScanError::Usage`] if the file cannot be read or fails
    /// any check in [`Config::parse`].
    pub fn load(path: &Path) -> Result<Self, LakeScanError> {
        let origin = path.display().to_string();
        let text = std::fs::read_to_string(path)
            .map_err(|err| LakeScanError::Usage(format!("cannot read config {origin}: {err}")))?;
        Self::parse(&text, &origin)
    }

    /// Validates config `text`; `origin` names it in error messages.
    ///
    /// # Errors
    /// Returns [`LakeScanError::Usage`] for invalid TOML; a `version` other
    /// than 1; an unknown field; more than [`MAX_ENTRIES`] entries; or an
    /// entry with an unknown rule code, a blank reason, both or neither of
    /// `key` and `prefix`, a malformed `expires` date, or an over-long
    /// field.
    pub fn parse(text: &str, origin: &str) -> Result<Self, LakeScanError> {
        let raw: RawConfig = toml::from_str(text).map_err(|err| toml_error(&err, text, origin))?;

        if raw.version != 1 {
            return Err(LakeScanError::Usage(format!(
                "config {origin}: version must be 1, found {}",
                raw.version
            )));
        }
        if raw.suppress.len() > MAX_ENTRIES {
            return Err(LakeScanError::Usage(format!(
                "config {origin}: {} [[suppress]] entries; at most {MAX_ENTRIES} are allowed",
                raw.suppress.len()
            )));
        }

        let entries = raw
            .suppress
            .into_iter()
            .enumerate()
            .map(|(index, spanned)| {
                // Only the offset is kept per entry: the line number is
                // derived on failure, so validating a large file stays
                // linear in its size.
                let offset = spanned.span().start;
                validate(spanned.into_inner()).map_err(|problem| {
                    LakeScanError::Usage(format!(
                        "config {origin}: [[suppress]] entry #{} (line {}): {problem}",
                        index + 1,
                        line_of(text, offset)
                    ))
                })
            })
            .collect::<Result<_, _>>()?;

        Ok(Self { entries })
    }

    /// The entries, in file order.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Consumes the config, yielding its entries in file order.
    #[must_use]
    pub fn into_entries(self) -> Vec<Entry> {
        self.entries
    }
}

/// Turns one raw entry into an [`Entry`], or describes what is wrong with
/// it.
fn validate(raw: RawEntry) -> Result<Entry, String> {
    let RawEntry {
        rule,
        key,
        prefix,
        reason,
        expires,
        bucket,
    } = raw;

    let rule_id = RuleId::ALL
        .into_iter()
        .find(|candidate| candidate.code() == rule)
        .ok_or_else(|| {
            let known: Vec<&str> = RuleId::ALL.iter().map(|r| r.code()).collect();
            format!("unknown rule {rule:?} (known rules: {})", known.join(", "))
        })?;

    let pattern = match (key, prefix) {
        (Some(key), None) => Pattern::Key(key),
        (None, Some(prefix)) => Pattern::Prefix(prefix),
        (Some(_), Some(_)) => return Err("set exactly one of key or prefix, not both".to_owned()),
        (None, None) => return Err("set exactly one of key or prefix".to_owned()),
    };
    let (Pattern::Key(value) | Pattern::Prefix(value)) = &pattern;
    if value.len() > MAX_KEY_BYTES {
        return Err(format!(
            "key or prefix is {} bytes; at most {MAX_KEY_BYTES} (S3's key limit)",
            value.len()
        ));
    }

    if reason.trim().is_empty() {
        return Err("reason must not be blank".to_owned());
    }
    if reason.len() > MAX_REASON_BYTES {
        return Err(format!(
            "reason is {} bytes; at most {MAX_REASON_BYTES}",
            reason.len()
        ));
    }

    let expires = expires.map(|value| parse_expires(&value)).transpose()?;

    if let Some(bucket) = &bucket
        && (bucket.is_empty() || bucket.len() > MAX_BUCKET_BYTES)
    {
        return Err(format!(
            "bucket {bucket:?} is not a valid bucket name (1 to {MAX_BUCKET_BYTES} bytes)"
        ));
    }

    Ok(Entry {
        rule: rule_id,
        pattern,
        reason,
        expires,
        bucket,
    })
}

/// Accepts an unquoted TOML local date (`2027-01-31`) or a quoted
/// `"YYYY-MM-DD"` string; anything else, including a date with a time or
/// offset, is malformed.
fn parse_expires(value: &toml::Value) -> Result<Date, String> {
    let parsed = match value {
        toml::Value::String(text) => Date::parse(text),
        toml::Value::Datetime(datetime) => match datetime.date {
            Some(date) if datetime.time.is_none() && datetime.offset.is_none() => {
                Date::new(date.year, date.month, date.day)
            }
            _ => None,
        },
        _ => None,
    };
    parsed.ok_or_else(|| format!("expires {value} is not a valid date (expected YYYY-MM-DD)"))
}

/// One line describing a TOML or schema error: the file, the line, the
/// `[[suppress]]` entry it falls in (if any), and toml's own message.
fn toml_error(err: &toml::de::Error, text: &str, origin: &str) -> LakeScanError {
    let message = err.message().trim();
    let Some(offset) = err.span().map(|span| span.start) else {
        return LakeScanError::Usage(format!("config {origin}: {message}"));
    };
    let entry = entry_containing(text, offset)
        .map(|n| format!(", [[suppress]] entry #{n}"))
        .unwrap_or_default();
    LakeScanError::Usage(format!(
        "config {origin}: line {}{entry}: {message}",
        line_of(text, offset)
    ))
}

/// The 1-based line `offset` falls on.
fn line_of(text: &str, offset: usize) -> usize {
    text.bytes()
        .take(offset)
        .filter(|&byte| byte == b'\n')
        .count()
        + 1
}

/// The 1-based number of the `[[suppress]]` table `offset` falls inside,
/// if any: the count of `[[suppress]]` headers starting before it.
fn entry_containing(text: &str, offset: usize) -> Option<usize> {
    let mut start = 0;
    let mut count = 0;
    for line in text.split_inclusive('\n') {
        if start > offset {
            break;
        }
        let header = line.trim().split('#').next().unwrap_or("").trim();
        if header.replace(' ', "") == "[[suppress]]" {
            count += 1;
        }
        start += line.len();
    }
    (count > 0).then_some(count)
}

#[cfg(test)]
mod tests {
    use super::{Config, Entry, MAX_ENTRIES, Pattern};
    use crate::error::LakeScanError;
    use crate::model::RuleId;
    use crate::suppress::date::Date;

    fn parse(text: &str) -> Result<Config, LakeScanError> {
        Config::parse(text, "test.toml")
    }

    /// The usage message for `text`, or `None` if it parsed (or failed in
    /// some other way).
    fn rejection(text: &str) -> Option<String> {
        match parse(text) {
            Err(LakeScanError::Usage(message)) => Some(message),
            _ => None,
        }
    }

    fn assert_rejected(text: &str, expected_fragments: &[&str]) {
        let message = rejection(text);
        for fragment in expected_fragments {
            assert!(
                message.as_ref().is_some_and(|m| m.contains(fragment)),
                "expected a usage error containing {fragment:?}, got {message:?}"
            );
        }
        assert!(
            message.as_ref().is_some_and(|m| !m.contains('\n')),
            "usage error should be one line: {message:?}"
        );
    }

    #[test]
    fn a_valid_file_parses_every_field() -> Result<(), LakeScanError> {
        let config = parse(
            r#"
version = 1

[[suppress]]
rule = "sensitive-key"
key = "docs/examples/id_rsa"
reason = "Public example key used in our docs"
expires = 2027-01-31
bucket = "my-bucket"

[[suppress]]
rule = "zero-byte-object"
prefix = ""
reason = "Placeholders are expected here"
"#,
        )?;

        assert_eq!(
            config.entries(),
            [
                Entry {
                    rule: RuleId::SensitiveKey,
                    pattern: Pattern::Key("docs/examples/id_rsa".to_owned()),
                    reason: "Public example key used in our docs".to_owned(),
                    expires: Date::new(2027, 1, 31),
                    bucket: Some("my-bucket".to_owned()),
                },
                Entry {
                    rule: RuleId::ZeroByteObject,
                    pattern: Pattern::Prefix(String::new()),
                    reason: "Placeholders are expected here".to_owned(),
                    expires: None,
                    bucket: None,
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn a_file_with_no_entries_is_valid() -> Result<(), LakeScanError> {
        assert_eq!(parse("version = 1\n")?.entries().len(), 0);
        Ok(())
    }

    #[test]
    fn quoted_and_unquoted_dates_are_equivalent() -> Result<(), LakeScanError> {
        let entry = |expires: &str| {
            format!(
                "version = 1\n[[suppress]]\nrule = \"sensitive-key\"\nkey = \"k\"\n\
                 reason = \"r\"\nexpires = {expires}\n"
            )
        };
        let unquoted = parse(&entry("2027-01-31"))?;
        let quoted = parse(&entry("\"2027-01-31\""))?;
        assert_eq!(unquoted, quoted);
        assert_eq!(
            unquoted.entries().first().and_then(|e| e.expires),
            Date::new(2027, 1, 31)
        );
        Ok(())
    }

    #[test]
    fn a_version_other_than_one_is_rejected() {
        assert_rejected("version = 2\n", &["test.toml", "version must be 1"]);
        assert_rejected("version = 0\n", &["version must be 1"]);
        assert_rejected("", &["version"]);
    }

    #[test]
    fn unknown_fields_are_rejected_naming_the_entry() {
        assert_rejected(
            "version = 1\n\n[[suppress]]\nrule = \"sensitive-key\"\nkey = \"k\"\nreason = \"r\"\n\n\
             [[suppress]]\nrule = \"sensitive-key\"\nkey = \"k\"\nreson = \"typo\"\n",
            &["entry #2", "line 11", "reson"],
        );
        assert_rejected("version = 1\nverison = 1\n", &["line 2", "verison"]);
    }

    #[test]
    fn an_unknown_rule_code_is_rejected() {
        assert_rejected(
            "version = 1\n[[suppress]]\nrule = \"sensitive-keys\"\nkey = \"k\"\nreason = \"r\"\n",
            &["entry #1", "line 2", "unknown rule \"sensitive-keys\""],
        );
    }

    #[test]
    fn a_blank_or_missing_reason_is_rejected() {
        assert_rejected(
            "version = 1\n[[suppress]]\nrule = \"sensitive-key\"\nkey = \"k\"\nreason = \"  \"\n",
            &["entry #1", "reason must not be blank"],
        );
        assert_rejected(
            "version = 1\n[[suppress]]\nrule = \"sensitive-key\"\nkey = \"k\"\n",
            &["entry #1", "reason"],
        );
    }

    #[test]
    fn both_or_neither_key_and_prefix_is_rejected() {
        assert_rejected(
            "version = 1\n[[suppress]]\nrule = \"sensitive-key\"\nkey = \"k\"\nprefix = \"p\"\n\
             reason = \"r\"\n",
            &["entry #1", "not both"],
        );
        assert_rejected(
            "version = 1\n[[suppress]]\nrule = \"sensitive-key\"\nreason = \"r\"\n",
            &["entry #1", "exactly one of key or prefix"],
        );
    }

    #[test]
    fn malformed_dates_are_rejected() {
        for expires in [
            "\"2027-02-30\"",
            "\"31/01/2027\"",
            "\"tomorrow\"",
            "2027-02-30",
            "2027-01-31T00:00:00Z",
            "2027-01-31T00:00:00",
            "20270131",
        ] {
            let text = format!(
                "version = 1\n[[suppress]]\nrule = \"sensitive-key\"\nkey = \"k\"\n\
                 reason = \"r\"\nexpires = {expires}\n"
            );
            assert!(
                rejection(&text).is_some(),
                "expires = {expires} should fail"
            );
        }
    }

    #[test]
    fn more_than_the_maximum_number_of_entries_is_rejected() -> Result<(), LakeScanError> {
        let entry = "[[suppress]]\nrule = \"sensitive-key\"\nkey = \"k\"\nreason = \"r\"\n";
        let at_cap = format!("version = 1\n{}", entry.repeat(MAX_ENTRIES));
        assert_eq!(parse(&at_cap)?.entries().len(), MAX_ENTRIES);

        let over_cap = format!("version = 1\n{}", entry.repeat(MAX_ENTRIES + 1));
        assert_rejected(&over_cap, &["10001", "at most 10000"]);
        Ok(())
    }

    #[test]
    fn invalid_toml_is_rejected_with_a_line_number() {
        assert_rejected("version = 1\n[[suppress]\n", &["test.toml", "line 2"]);
    }

    #[test]
    fn a_missing_file_is_a_usage_error() {
        let result = Config::load(std::path::Path::new("/nonexistent/lakescan.toml"));
        assert!(
            matches!(result, Err(LakeScanError::Usage(message)) if message.contains("cannot read config"))
        );
    }
}
