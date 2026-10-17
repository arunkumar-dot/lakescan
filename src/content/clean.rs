//! Cleaning: what is dropped from a column's sample before any share is
//! computed.
//!
//! The rules are generic, not tuned to any test data: trim whitespace;
//! drop empty strings, values made of one repeated character
//! (`0000000000`, `----`, `xxxx`), and a fixed list of placeholders
//! compared case-insensitively. Nulls never reach this module: the column
//! reader skips them.
//!
//! Three more kinds of sentinel, seen in real public datasets
//! (`docs/experiments/real-data.md`), are dropped too: emails at the
//! reserved test domains ([`TEST_EMAIL_DOMAINS`], and any name under
//! `.test`), which are test accounts, not people; masked values, with a run
//! of [`MASK_RUN`] or more of one masking symbol (`****1234`,
//! `XXXX-XXXX-XXXX-0004`, `j----@mail`); and the sentinel dates
//! `1900-01-01` and `1970-01-01` (with an all-zero time, if any). Emails
//! under the reserved `.example` top-level domain are kept: the committed
//! fixtures use them, so that no fixture value can be a real address. Separately, [`drop_dominant`] removes a value that
//! makes up more than half of a column's cleaned sample (a default value
//! such as a fixed test address), unless it is the only distinct value.

use std::collections::HashMap;

/// Placeholders that stand for "no value", compared case-insensitively
/// after trimming.
const PLACEHOLDERS: [&str; 15] = [
    "n/a",
    "na",
    "null",
    "none",
    "nil",
    "unknown",
    "undefined",
    "unk",
    "tbd",
    "test",
    "sample",
    "dummy",
    "-",
    "?",
    ".",
];

/// Email domains reserved for documentation and testing (RFC 2606),
/// including their subdomains. Names under `.test` (RFC 6761) are
/// dropped too.
const TEST_EMAIL_DOMAINS: [&str; 3] = ["example.com", "example.org", "example.net"];

/// Symbols that mask a value when repeated.
const MASK_SYMBOLS: [char; 6] = ['*', 'x', 'X', '#', '\u{2022}', '-'];

/// The shortest run of one masking symbol that marks a masked value.
const MASK_RUN: usize = 4;

/// Dates that stand for "no date".
const SENTINEL_DATES: [&str; 2] = ["1900-01-01", "1970-01-01"];

/// The longest value kept in a sample, in bytes. No detected type can be
/// longer (an email address is at most 254 bytes), so a longer value is
/// kept only as a cut-down copy that can never match, which bounds a
/// sample's memory without changing any share.
pub(super) const MAX_VALUE_BYTES: usize = 257;

/// The cleaned form of `raw`, or `None` if cleaning drops it.
pub(super) fn clean(raw: &str) -> Option<&str> {
    let value = raw.trim();
    let mut chars = value.chars();
    let first = chars.next()?;
    if chars.all(|c| c == first) {
        return None;
    }
    if PLACEHOLDERS.iter().any(|p| value.eq_ignore_ascii_case(p))
        || test_email(value)
        || masked(value)
        || sentinel_date(value)
    {
        return None;
    }
    Some(crate::model::truncate_str(value, MAX_VALUE_BYTES))
}

/// Whether `value` is an email at a reserved test domain: one of
/// [`TEST_EMAIL_DOMAINS`] or a subdomain of one, or a name under `.test`.
fn test_email(value: &str) -> bool {
    let Some((_, domain)) = value.rsplit_once('@') else {
        return false;
    };
    let domain = domain.to_ascii_lowercase();
    let under = |parent: &str| {
        domain == parent
            || domain
                .strip_suffix(parent)
                .is_some_and(|rest| rest.ends_with('.'))
    };
    let tld = domain.rsplit_once('.').map(|(_, tld)| tld);
    TEST_EMAIL_DOMAINS.iter().any(|reserved| under(reserved)) || tld == Some("test")
}

/// Whether `value` has a run of [`MASK_RUN`] or more of one masking
/// symbol.
fn masked(value: &str) -> bool {
    let mut run = 0;
    let mut last = None;
    for c in value.chars() {
        if MASK_SYMBOLS.contains(&c) && last == Some(c) {
            run += 1;
        } else {
            run = 1;
        }
        last = Some(c);
        if run >= MASK_RUN && MASK_SYMBOLS.contains(&c) {
            return true;
        }
    }
    false
}

/// Whether `value` is a sentinel date, alone or with an all-zero time
/// (`1970-01-01T00:00:00Z`).
fn sentinel_date(value: &str) -> bool {
    SENTINEL_DATES.iter().any(|date| {
        value.strip_prefix(date).is_some_and(|time| {
            time.chars()
                .all(|c| matches!(c, 'T' | 't' | ' ' | '0' | ':' | '.' | 'Z' | 'z' | '+'))
        })
    })
}

/// Removes every copy of a value that makes up more than half of
/// `values`, unless it is the only distinct value.
pub(super) fn drop_dominant(values: &mut Vec<String>) {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for value in values.iter() {
        *counts.entry(value.as_str()).or_default() += 1;
    }
    if counts.len() < 2 {
        return;
    }
    let dominant = counts
        .iter()
        .find(|&(_, &count)| count * 2 > values.len())
        .map(|(value, _)| (*value).to_owned());
    if let Some(dominant) = dominant {
        values.retain(|value| *value != dominant);
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_VALUE_BYTES, clean, drop_dominant};

    #[test]
    fn whitespace_is_trimmed() {
        assert_eq!(clean("  a@b.co \t"), Some("a@b.co"));
    }

    #[test]
    fn empty_and_blank_values_are_dropped() {
        for raw in ["", " ", "\t \n"] {
            assert_eq!(clean(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn placeholders_are_dropped_in_any_case() {
        for raw in [
            "N/A",
            "na",
            "NULL",
            "None",
            "nil",
            "Unknown",
            "UNDEFINED",
            "unk",
            "TBD",
            "test",
            "Sample",
            "dummy",
            "-",
            "?",
            ".",
            " n/a ",
        ] {
            assert_eq!(clean(raw), None, "{raw:?}");
        }
        assert_eq!(clean("testing"), Some("testing"));
        assert_eq!(clean("test@test.com"), Some("test@test.com"));
    }

    /// The experiment's FHIR practitioners all have emails at
    /// `example.com`: test accounts, not people.
    #[test]
    fn emails_at_reserved_test_domains_are_dropped() {
        for raw in [
            "first.last123@example.com",
            "a@EXAMPLE.ORG",
            "a@example.net",
            "billing@mail.example.com",
            "user@acme.test",
            "user@MAIL.TEST",
        ] {
            assert_eq!(clean(raw), None, "{raw:?}");
        }
        for raw in [
            "a@mail.example",
            "a@example.co",
            "a@notexample.com",
            "a@example.com.au",
            "a@test.com",
            "a@contest",
            "example.com",
        ] {
            assert_eq!(clean(raw), Some(raw), "{raw:?}");
        }
    }

    /// The experiment's Nemotron documents mask with runs of `*` and `X`.
    #[test]
    fn masked_values_are_dropped() {
        for raw in [
            "****1234",
            "**** **** **** 1234",
            "XXXX-XXXX-XXXX-0004",
            "xxxx@mail.example",
            "j----@mail.example",
            "###-##-####",
            "\u{2022}\u{2022}\u{2022}\u{2022} 4242",
        ] {
            assert_eq!(clean(raw), None, "{raw:?}");
        }
        for raw in [
            "***1234",
            "x1234",
            "Maxine",
            "a-b-c-d",
            "XXX-12",
            "4111 1111 1111 1111",
            "1-201-555-0100",
        ] {
            assert_eq!(clean(raw), Some(raw), "{raw:?}");
        }
    }

    /// The experiment's Synthea dates hold `1900-01-01`-style sentinels.
    #[test]
    fn sentinel_dates_are_dropped() {
        for raw in [
            "1900-01-01",
            "1970-01-01",
            "1970-01-01T00:00:00Z",
            "1900-01-01 00:00:00.000",
            "1970-01-01 00:00",
        ] {
            assert_eq!(clean(raw), None, "{raw:?}");
        }
        for raw in [
            "1970-01-02",
            "1900-01-01T10:00:00Z",
            "1971-01-01",
            "19700101",
            "1970-01-01x",
        ] {
            assert_eq!(clean(raw), Some(raw), "{raw:?}");
        }
    }

    #[test]
    fn one_repeated_character_is_dropped() {
        for raw in ["0000000000", "----", "xxxx", "a", "9"] {
            assert_eq!(clean(raw), None, "{raw:?}");
        }
        assert_eq!(clean("0000000001"), Some("0000000001"));
    }

    #[test]
    fn long_values_are_cut_to_the_sample_limit() {
        let long = "ab".repeat(400);
        assert_eq!(clean(&long).map(str::len), Some(MAX_VALUE_BYTES));
    }

    #[test]
    fn a_dominant_value_is_dropped_unless_it_is_the_only_one() {
        let mut values: Vec<String> = ["d", "d", "d", "a", "b"].map(str::to_owned).to_vec();
        drop_dominant(&mut values);
        assert_eq!(values, ["a", "b"]);

        let mut only: Vec<String> = ["d", "d"].map(str::to_owned).to_vec();
        drop_dominant(&mut only);
        assert_eq!(only.len(), 2);

        // Exactly half is not more than half.
        let mut half: Vec<String> = ["d", "d", "a", "b"].map(str::to_owned).to_vec();
        drop_dominant(&mut half);
        assert_eq!(half.len(), 4);
    }
}
