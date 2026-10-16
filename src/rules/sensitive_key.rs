//! `sensitive-key`: flags keys whose basename or path looks like a
//! credential or secret file, judged purely from the key string — this rule
//! never reads object contents, only the listing metadata it was given.
//!
//! All matching is ASCII case-insensitive and allocates nothing: splitting
//! on `/` walks the existing `&str` lazily, and prefix/suffix checks use
//! `str::get` with checked arithmetic rather than direct indexing, so a
//! multibyte key that happens to be the wrong length for a given pattern is
//! reported as "no match" instead of panicking on a non-UTF-8-boundary
//! slice.

use super::EvalContext;
use crate::model::{ObjectMeta, Severity};

/// Basenames that are a credential/secret file on their own, regardless of
/// extension.
const HIGH_EXACT_BASENAMES: &[&str] = &[
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".htpasswd",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
];

/// A basename prefix that is High on its own (`.env.production`), except
/// for [`ENV_TEMPLATE_EXCEPTIONS`].
const HIGH_ENV_PREFIX: &str = ".env.";

/// `.env.`-prefixed basenames that are templates, not real secrets, and so
/// are exempt from the [`HIGH_ENV_PREFIX`] match.
const ENV_TEMPLATE_EXCEPTIONS: &[&str] = &[".env.example", ".env.sample", ".env.template"];

/// Basename suffixes that are High on their own.
const HIGH_SUFFIXES: &[&str] = &[".tfstate", ".tfstate.backup", ".ppk", ".kdbx"];

/// `(directory, basename)`: High when the basename sits directly inside a
/// path segment named the directory (`.aws/credentials`, the AWS CLI's
/// shared credentials file).
const HIGH_IN_DIRECTORY: (&str, &str) = (".aws", "credentials");

/// Basename suffixes that are Medium.
const MEDIUM_SUFFIXES: &[&str] = &[".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"];

/// Path segments whose mere presence anywhere in the key is Medium: tool
/// directories that normally hold secrets.
const MEDIUM_SEGMENTS: &[&str] = &[".git", ".ssh"];

pub(super) fn check(object: &ObjectMeta, _ctx: &EvalContext) -> Option<Severity> {
    let key = object.key.as_str();
    let basename = key.rsplit('/').next().unwrap_or(key);

    if is_high(key, basename) {
        return Some(Severity::High);
    }
    if is_medium(key, basename) {
        return Some(Severity::Medium);
    }
    None
}

fn is_high(key: &str, basename: &str) -> bool {
    if matches_any_exact(HIGH_EXACT_BASENAMES, basename) {
        return true;
    }

    if starts_with_ignore_ascii_case(basename, HIGH_ENV_PREFIX)
        && !matches_any_exact(ENV_TEMPLATE_EXCEPTIONS, basename)
    {
        return true;
    }

    if ends_with_any_ignore_ascii_case(HIGH_SUFFIXES, basename) {
        return true;
    }

    let (directory, name) = HIGH_IN_DIRECTORY;
    basename.eq_ignore_ascii_case(name) && preceding_segment_is(key, directory)
}

fn is_medium(key: &str, basename: &str) -> bool {
    ends_with_any_ignore_ascii_case(MEDIUM_SUFFIXES, basename)
        || any_segment_matches(key, MEDIUM_SEGMENTS)
}

/// `true` if `value` case-insensitively equals any of `candidates`.
fn matches_any_exact(candidates: &[&str], value: &str) -> bool {
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

/// Case-insensitive `starts_with`. Safe on any UTF-8 input: `str::get`
/// returns `None` (never panics) for a range that would land outside the
/// string or off a char boundary, and that is treated as "no match".
fn starts_with_ignore_ascii_case(haystack: &str, prefix: &str) -> bool {
    haystack
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// Case-insensitive `ends_with`. See [`starts_with_ignore_ascii_case`] for
/// why this never panics; the length subtraction is checked for the same
/// reason (a suffix longer than the haystack must not underflow).
fn ends_with_ignore_ascii_case(haystack: &str, suffix: &str) -> bool {
    let Some(start) = haystack.len().checked_sub(suffix.len()) else {
        return false;
    };
    haystack
        .get(start..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

fn ends_with_any_ignore_ascii_case(suffixes: &[&str], haystack: &str) -> bool {
    suffixes
        .iter()
        .any(|suffix| ends_with_ignore_ascii_case(haystack, suffix))
}

/// `true` if the path segment immediately before the key's basename equals
/// `expected`, case-insensitively. `false` if the key has no such segment
/// (no `/` at all, or only one segment).
fn preceding_segment_is(key: &str, expected: &str) -> bool {
    let mut segments_from_end = key.rsplit('/');
    segments_from_end.next(); // the basename itself; skip it.
    segments_from_end
        .next()
        .is_some_and(|segment| segment.eq_ignore_ascii_case(expected))
}

/// `true` if any `/`-delimited segment of `key` case-insensitively matches
/// one of `candidates`.
fn any_segment_matches(key: &str, candidates: &[&str]) -> bool {
    key.split('/').any(|segment| {
        candidates
            .iter()
            .any(|candidate| segment.eq_ignore_ascii_case(candidate))
    })
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::check;
    use crate::model::{ObjectMeta, Severity, StorageClass};

    /// An `EvalContext` for tests that don't care about time.
    fn ctx() -> super::EvalContext {
        super::EvalContext {
            now: SystemTime::UNIX_EPOCH,
        }
    }

    fn object_with_key(key: &str) -> ObjectMeta {
        ObjectMeta {
            key: key.to_owned(),
            size: 123,
            last_modified: SystemTime::UNIX_EPOCH,
            etag: "etag".to_owned(),
            storage_class: StorageClass::Standard,
        }
    }

    fn severity_for(key: &str) -> Option<Severity> {
        check(&object_with_key(key), &ctx())
    }

    #[test]
    fn exact_high_basenames_match_regardless_of_path() {
        for name in [
            ".env",
            ".netrc",
            ".npmrc",
            ".pypirc",
            ".git-credentials",
            ".htpasswd",
            "id_rsa",
            "id_dsa",
            "id_ecdsa",
            "id_ed25519",
        ] {
            assert_eq!(severity_for(name), Some(Severity::High), "bare {name}");
            assert_eq!(
                severity_for(&format!("a/b/{name}")),
                Some(Severity::High),
                "nested {name}"
            );
        }
    }

    #[test]
    fn exact_high_basenames_match_case_insensitively() {
        assert_eq!(severity_for("ID_RSA"), Some(Severity::High));
        assert_eq!(severity_for(".ENV"), Some(Severity::High));
        assert_eq!(
            severity_for("config/.Git-Credentials"),
            Some(Severity::High)
        );
    }

    #[test]
    fn env_dot_prefixed_basenames_are_high_except_the_template_exceptions() {
        assert_eq!(severity_for(".env.local"), Some(Severity::High));
        assert_eq!(severity_for(".env.production"), Some(Severity::High));
        assert_eq!(severity_for(".ENV.LOCAL"), Some(Severity::High));

        assert_eq!(severity_for(".env.example"), None);
        assert_eq!(severity_for(".env.sample"), None);
        assert_eq!(severity_for(".env.template"), None);
        // Case-insensitively too.
        assert_eq!(severity_for(".ENV.EXAMPLE"), None);
    }

    #[test]
    fn high_suffixes_match_case_insensitively() {
        for suffix in [".tfstate", ".tfstate.backup", ".ppk", ".kdbx"] {
            let key = format!("state/terraform{suffix}");
            assert_eq!(severity_for(&key), Some(Severity::High), "{key}");
            let upper = format!("state/terraform{}", suffix.to_ascii_uppercase());
            assert_eq!(severity_for(&upper), Some(Severity::High), "{upper}");
        }
    }

    #[test]
    fn credentials_requires_a_preceding_dot_aws_segment() {
        assert_eq!(severity_for(".aws/credentials"), Some(Severity::High));
        assert_eq!(severity_for("home/.aws/credentials"), Some(Severity::High));
        // Case-insensitive on both the basename and the segment.
        assert_eq!(severity_for(".AWS/Credentials"), Some(Severity::High));

        // No preceding segment at all.
        assert_eq!(severity_for("credentials"), None);
        // Preceding segment present, but not .aws.
        assert_eq!(severity_for("backup/credentials"), None);
    }

    #[test]
    fn medium_suffixes_match_case_insensitively() {
        for suffix in [".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"] {
            let key = format!("certs/server{suffix}");
            assert_eq!(severity_for(&key), Some(Severity::Medium), "{key}");
            let upper = format!("certs/server{}", suffix.to_ascii_uppercase());
            assert_eq!(severity_for(&upper), Some(Severity::Medium), "{upper}");
        }
    }

    #[test]
    fn a_git_or_ssh_segment_anywhere_is_medium() {
        assert_eq!(severity_for(".git/config"), Some(Severity::Medium));
        assert_eq!(severity_for("project/.git/HEAD"), Some(Severity::Medium));
        assert_eq!(severity_for(".ssh/config"), Some(Severity::Medium));
        assert_eq!(
            severity_for("home/.SSH/known_hosts"),
            Some(Severity::Medium)
        );
    }

    #[test]
    fn high_takes_priority_over_medium() {
        // id_rsa would also sit in a .ssh segment, which alone is Medium;
        // the exact-basename High match must win.
        assert_eq!(severity_for(".ssh/id_rsa"), Some(Severity::High));
    }

    #[test]
    fn an_unremarkable_key_is_not_flagged() {
        assert_eq!(severity_for("reports/2024/summary.csv"), None);
        assert_eq!(severity_for("images/logo.png"), None);
    }

    #[test]
    fn folder_marker_like_keys_do_not_panic_or_mismatch() {
        assert_eq!(severity_for(""), None);
        assert_eq!(severity_for("/"), None);
        assert_eq!(severity_for("a/"), None);
    }

    #[test]
    fn multibyte_keys_never_panic_and_are_judged_correctly() {
        // "€bar" is 6 bytes (3-byte € + 3 ASCII bytes); a naive byte-offset
        // slice for a 4-byte suffix like ".key" would land at byte index 2,
        // inside the € sequence, and panic if done with raw indexing.
        assert_eq!(severity_for("€bar"), None);

        // A multibyte path segment elsewhere must not interfere with
        // basename extraction or matching.
        assert_eq!(severity_for("data/€/id_rsa"), Some(Severity::High));
        assert_eq!(severity_for("日本語/server.pem"), Some(Severity::Medium));

        // A multibyte basename that genuinely ends in a matched suffix.
        assert_eq!(severity_for("日本語.pem"), Some(Severity::Medium));
    }

    /// The `sensitive-key` row of README.md's rules table, split into its
    /// High part and its Medium part.
    fn readme_row() -> (&'static str, &'static str) {
        let readme = include_str!("../../README.md");
        let row = readme
            .lines()
            .find(|line| line.starts_with("| `sensitive-key` |"))
            .unwrap_or("");
        row.split_once("Medium:").unwrap_or((row, ""))
    }

    /// Drift guard: every pattern the rule matches, read from the same
    /// constants it uses, is documented in README.md under its severity.
    #[test]
    fn every_pattern_is_documented_in_the_readme_under_its_severity() {
        let (high, medium) = readme_row();
        assert!(high.contains("High:"), "README.md has no sensitive-key row");

        let (directory, name) = super::HIGH_IN_DIRECTORY;
        let mut expected_high: Vec<String> = super::HIGH_EXACT_BASENAMES
            .iter()
            .chain(super::ENV_TEMPLATE_EXCEPTIONS)
            .chain(super::HIGH_SUFFIXES)
            .map(|pattern| format!("`{pattern}`"))
            .collect();
        expected_high.push(format!("`{}*`", super::HIGH_ENV_PREFIX));
        expected_high.push(format!("`{directory}/{name}`"));
        for pattern in &expected_high {
            assert!(
                high.contains(pattern.as_str()),
                "README.md's sensitive-key High list lacks {pattern}"
            );
        }

        let expected_medium = super::MEDIUM_SUFFIXES
            .iter()
            .chain(super::MEDIUM_SEGMENTS)
            .map(|pattern| format!("`{pattern}`"));
        for pattern in expected_medium {
            assert!(
                medium.contains(pattern.as_str()),
                "README.md's sensitive-key Medium list lacks {pattern}"
            );
        }
    }
}
