//! Drops findings an operator has explicitly accepted, before they reach
//! the summary.
//!
//! Single responsibility: decide, per [`Finding`], whether a `--config`
//! suppression entry covers it. A suppressed finding is not lost: the
//! driver hands it to [`crate::aggregate::Aggregates::observe_suppressed`],
//! which counts it per rule, and nothing else — it never reaches the
//! findings matrix, the verdict, or the `--findings` stream.
//!
//! # Entries and their state
//!
//! Each entry (see [`config`] for the file format) is, for one scan,
//! exactly one of:
//!
//! - **inactive** — it names a different `bucket`. It never applies and is
//!   never reported, expired or not: a config shared across buckets should
//!   not warn about the buckets this scan did not touch;
//! - **expired** — its `expires` date is before the scan's UTC date. It
//!   does not apply, and is reported so it can be renewed or removed. On
//!   the expiry date itself it still applies;
//! - **active** — it applies. After the scan, an active entry that
//!   suppressed nothing is reported as **unused**.
//!
//! When several active entries cover one finding, the first in file order
//! wins and gets the hit.
//!
//! # Matching cost and memory budget
//!
//! Exact keys are looked up in a hash map per rule — keyed, in effect, by
//! `(RuleId, key)`, but split by rule so a lookup borrows the finding's
//! `&str` key instead of allocating an owned `(RuleId, String)` per
//! finding. Prefixes are checked linearly, per rule, in file order. That
//! is sized for configs of up to a few thousand entries, where a linear
//! prefix scan per *finding* (not per object) is cheap.
//!
//! **Memory is bounded by the config, never by the bucket:** at most
//! [`MAX_ENTRIES`] entries, each with a key or prefix of at most 1 KiB, a
//! reason of at most 1 KiB, and a bucket name of at most 63 bytes, plus
//! one hit counter each. Exact keys are held twice (entry and index), so a
//! pathological maximal config is about 3.3 KB per entry, ~33 MB (31.3 MiB)
//! in all; a realistic one is kilobytes. Scanning ten objects or ten billion leaves this
//! unchanged.

pub mod config;
mod date;

use std::collections::HashMap;

pub use config::{Config, Entry, MAX_ENTRIES, Pattern};
pub use date::Date;

use crate::model::{Finding, RuleId};

/// How many rules exist; sizes the per-rule indexes.
const NUM_RULES: usize = RuleId::ALL.len();

/// An entry's state for one scan; see this module's doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Active,
    Expired,
    Inactive,
}

/// What a scan's suppressions amounted to, for the report: the entries
/// that expired and the active entries that suppressed nothing, each in
/// file order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Entries whose `expires` date was before the scan date.
    pub expired: Vec<Entry>,
    /// Active entries that matched no finding.
    pub unused: Vec<Entry>,
}

/// Matches findings against one config's entries for one scan, counting
/// a hit on the winning entry each time a finding is suppressed.
#[derive(Debug)]
pub struct Suppressor {
    entries: Vec<Entry>,
    states: Vec<State>,
    hits: Vec<u64>,
    /// Per rule: exact key -> index of the first active entry for it.
    exact: [HashMap<String, usize>; NUM_RULES],
    /// Per rule: indexes of active prefix entries, in file order.
    prefixes: [Vec<usize>; NUM_RULES],
}

impl Suppressor {
    /// Prepares `config` for a scan of `bucket` that started on
    /// `scan_date` (UTC), deciding each entry's state up front.
    #[must_use]
    pub fn new(config: Config, bucket: &str, scan_date: Date) -> Self {
        let entries = config.into_entries();
        let mut exact: [HashMap<String, usize>; NUM_RULES] = Default::default();
        let mut prefixes: [Vec<usize>; NUM_RULES] = Default::default();

        let states: Vec<State> = entries
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                if entry.bucket.as_deref().is_some_and(|b| b != bucket) {
                    return State::Inactive;
                }
                if entry.expires.is_some_and(|expires| expires < scan_date) {
                    return State::Expired;
                }
                let rule = entry.rule.index();
                match &entry.pattern {
                    Pattern::Key(key) => {
                        if let Some(map) = exact.get_mut(rule) {
                            // `or_insert`: a later duplicate never displaces
                            // the first entry, which wins.
                            map.entry(key.clone()).or_insert(index);
                        }
                    }
                    Pattern::Prefix(_) => {
                        if let Some(list) = prefixes.get_mut(rule) {
                            list.push(index);
                        }
                    }
                }
                State::Active
            })
            .collect();

        let hits = vec![0; entries.len()];
        Self {
            entries,
            states,
            hits,
            exact,
            prefixes,
        }
    }

    /// Whether an active entry covers `finding`; if so, records a hit on
    /// the first such entry in file order.
    pub fn suppresses(&mut self, finding: &Finding<'_>) -> bool {
        let rule = finding.rule.index();
        let key = finding.object.key.as_str();

        let exact = self.exact.get(rule).and_then(|map| map.get(key)).copied();
        let prefix = self.prefixes.get(rule).and_then(|list| {
            list.iter().copied().find(|&index| {
                self.entries
                    .get(index)
                    .is_some_and(|entry| entry.pattern.matches(key))
            })
        });

        let winner = match (exact, prefix) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let Some(index) = winner else {
            return false;
        };
        if let Some(hits) = self.hits.get_mut(index) {
            *hits = hits.saturating_add(1);
        }
        true
    }

    /// Ends the scan: the expired entries, and the active entries with no
    /// hits.
    #[must_use]
    pub fn finish(self) -> Outcome {
        let mut outcome = Outcome::default();
        for ((entry, state), hits) in self.entries.into_iter().zip(self.states).zip(self.hits) {
            match state {
                State::Expired => outcome.expired.push(entry),
                State::Active if hits == 0 => outcome.unused.push(entry),
                State::Active | State::Inactive => {}
            }
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::{Config, Date, Outcome, Suppressor};
    use crate::error::LakeScanError;
    use crate::model::{Finding, ObjectMeta, RuleId, Severity, StorageClass};

    fn object(key: &str) -> ObjectMeta {
        ObjectMeta {
            key: key.to_owned(),
            size: 10,
            last_modified: SystemTime::UNIX_EPOCH,
            etag: "etag".to_owned(),
            storage_class: StorageClass::Standard,
        }
    }

    fn finding(rule: RuleId, object: &ObjectMeta) -> Finding<'_> {
        Finding {
            rule,
            severity: Severity::High,
            object,
        }
    }

    fn date(text: &str) -> Result<Date, LakeScanError> {
        Date::parse(text).ok_or_else(|| LakeScanError::Usage(format!("bad test date {text}")))
    }

    /// A suppressor for `entries` (TOML `[[suppress]]` bodies, joined in
    /// order) scanning `bucket` on `scan_date`.
    fn suppressor(
        entries: &[&str],
        bucket: &str,
        scan_date: &str,
    ) -> Result<Suppressor, LakeScanError> {
        let mut text = "version = 1\n".to_owned();
        for entry in entries {
            text.push_str("[[suppress]]\n");
            text.push_str(entry);
            text.push('\n');
        }
        let config = Config::parse(&text, "test.toml")?;
        Ok(Suppressor::new(config, bucket, date(scan_date)?))
    }

    fn suppressed(s: &mut Suppressor, rule: RuleId, key: &str) -> bool {
        let object = object(key);
        s.suppresses(&finding(rule, &object))
    }

    const TODAY: &str = "2026-10-13";

    #[test]
    fn an_exact_key_matches_only_that_key_and_rule() -> Result<(), LakeScanError> {
        let mut s = suppressor(
            &["rule = \"sensitive-key\"\nkey = \"docs/id_rsa\"\nreason = \"r\""],
            "b",
            TODAY,
        )?;
        assert!(suppressed(&mut s, RuleId::SensitiveKey, "docs/id_rsa"));
        assert!(!suppressed(&mut s, RuleId::SensitiveKey, "docs/id_rsa.pub"));
        assert!(!suppressed(&mut s, RuleId::SensitiveKey, "docs/"));
        assert!(!suppressed(&mut s, RuleId::ZeroByteObject, "docs/id_rsa"));
        Ok(())
    }

    #[test]
    fn a_prefix_matches_every_key_under_it() -> Result<(), LakeScanError> {
        let mut s = suppressor(
            &["rule = \"sensitive-key\"\nprefix = \"fixtures/\"\nreason = \"r\""],
            "b",
            TODAY,
        )?;
        assert!(suppressed(&mut s, RuleId::SensitiveKey, "fixtures/id_rsa"));
        assert!(suppressed(
            &mut s,
            RuleId::SensitiveKey,
            "fixtures/a/b/.env"
        ));
        assert!(!suppressed(&mut s, RuleId::SensitiveKey, "fixtures"));
        assert!(!suppressed(
            &mut s,
            RuleId::SensitiveKey,
            "other/fixtures/id_rsa"
        ));
        Ok(())
    }

    #[test]
    fn an_empty_prefix_suppresses_the_whole_rule() -> Result<(), LakeScanError> {
        let mut s = suppressor(
            &["rule = \"zero-byte-object\"\nprefix = \"\"\nreason = \"r\""],
            "b",
            TODAY,
        )?;
        for key in ["a", "deep/nested/key", "", "\u{1b}[31m"] {
            assert!(suppressed(&mut s, RuleId::ZeroByteObject, key), "{key:?}");
        }
        assert!(!suppressed(&mut s, RuleId::SensitiveKey, "a"));
        Ok(())
    }

    #[test]
    fn the_first_matching_entry_in_file_order_wins() -> Result<(), LakeScanError> {
        // Prefix first, then an exact key, then a duplicate exact key: the
        // prefix wins every finding it covers.
        let mut s = suppressor(
            &[
                "rule = \"sensitive-key\"\nprefix = \"docs/\"\nreason = \"first\"",
                "rule = \"sensitive-key\"\nkey = \"docs/id_rsa\"\nreason = \"second\"",
                "rule = \"sensitive-key\"\nkey = \"docs/id_rsa\"\nreason = \"third\"",
                "rule = \"sensitive-key\"\nkey = \"other/id_rsa\"\nreason = \"fourth\"",
                "rule = \"sensitive-key\"\nkey = \"other/id_rsa\"\nreason = \"fifth\"",
            ],
            "b",
            TODAY,
        )?;
        assert!(suppressed(&mut s, RuleId::SensitiveKey, "docs/id_rsa"));
        assert!(suppressed(&mut s, RuleId::SensitiveKey, "other/id_rsa"));
        assert_eq!(s.hits, [1, 0, 0, 1, 0]);

        let outcome = s.finish();
        let unused: Vec<&str> = outcome.unused.iter().map(|e| e.reason.as_str()).collect();
        assert_eq!(unused, ["second", "third", "fifth"]);
        Ok(())
    }

    #[test]
    fn an_exact_key_earlier_in_the_file_beats_a_later_prefix() -> Result<(), LakeScanError> {
        let mut s = suppressor(
            &[
                "rule = \"sensitive-key\"\nkey = \"docs/id_rsa\"\nreason = \"exact\"",
                "rule = \"sensitive-key\"\nprefix = \"docs/\"\nreason = \"prefix\"",
            ],
            "b",
            TODAY,
        )?;
        assert!(suppressed(&mut s, RuleId::SensitiveKey, "docs/id_rsa"));
        assert!(suppressed(&mut s, RuleId::SensitiveKey, "docs/.env"));
        assert_eq!(s.hits, [1, 1]);
        Ok(())
    }

    #[test]
    fn an_entry_for_another_bucket_never_applies_and_is_never_reported() -> Result<(), LakeScanError>
    {
        let mut s = suppressor(
            &[
                "rule = \"sensitive-key\"\nkey = \"id_rsa\"\nreason = \"other\"\nbucket = \"other\"",
                "rule = \"sensitive-key\"\nkey = \"gone\"\nreason = \"old\"\nbucket = \"other\"\n\
                 expires = 2000-01-01",
                "rule = \"sensitive-key\"\nkey = \".env\"\nreason = \"mine\"\nbucket = \"mine\"",
            ],
            "mine",
            TODAY,
        )?;
        assert!(!suppressed(&mut s, RuleId::SensitiveKey, "id_rsa"));
        assert!(suppressed(&mut s, RuleId::SensitiveKey, ".env"));
        assert_eq!(s.finish(), Outcome::default());
        Ok(())
    }

    #[test]
    fn an_entry_applies_on_its_expiry_date_and_expires_the_day_after() -> Result<(), LakeScanError>
    {
        let entry =
            "rule = \"sensitive-key\"\nkey = \"id_rsa\"\nreason = \"r\"\nexpires = 2026-10-13";

        let mut on_the_day = suppressor(&[entry], "b", "2026-10-13")?;
        assert!(suppressed(&mut on_the_day, RuleId::SensitiveKey, "id_rsa"));
        assert_eq!(on_the_day.finish(), Outcome::default());

        let mut day_after = suppressor(&[entry], "b", "2026-10-14")?;
        assert!(!suppressed(&mut day_after, RuleId::SensitiveKey, "id_rsa"));
        let outcome = day_after.finish();
        assert_eq!(outcome.expired.len(), 1);
        assert!(
            outcome.unused.is_empty(),
            "an expired entry is not also unused"
        );
        Ok(())
    }

    #[test]
    fn hits_count_every_suppressed_finding_and_unused_entries_are_reported()
    -> Result<(), LakeScanError> {
        let mut s = suppressor(
            &[
                "rule = \"zero-byte-object\"\nprefix = \"tmp/\"\nreason = \"scratch\"",
                "rule = \"sensitive-key\"\nkey = \"never-seen\"\nreason = \"stale\"",
            ],
            "b",
            TODAY,
        )?;
        for key in ["tmp/a", "tmp/b", "tmp/c"] {
            assert!(suppressed(&mut s, RuleId::ZeroByteObject, key));
        }
        assert!(!suppressed(&mut s, RuleId::ZeroByteObject, "keep/a"));
        assert_eq!(s.hits, [3, 0]);

        let outcome = s.finish();
        assert_eq!(outcome.expired.len(), 0);
        let unused: Vec<&str> = outcome.unused.iter().map(|e| e.reason.as_str()).collect();
        assert_eq!(unused, ["stale"]);
        Ok(())
    }

    #[test]
    fn no_config_suppresses_nothing() {
        let mut s = Suppressor::new(Config::default(), "b", Date::utc_of(SystemTime::UNIX_EPOCH));
        assert!(!suppressed(&mut s, RuleId::SensitiveKey, "id_rsa"));
        assert_eq!(s.finish(), Outcome::default());
    }
}
