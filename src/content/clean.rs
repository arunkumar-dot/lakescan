//! Cleaning: what is dropped from a column's sample before any share is
//! computed.
//!
//! The rules are generic, not tuned to any test data: trim whitespace;
//! drop empty strings, values made of one repeated character
//! (`0000000000`, `----`, `xxxx`), and a fixed list of placeholders
//! compared case-insensitively. Nulls never reach this module: the column
//! reader skips them. Separately, [`drop_dominant`] removes a value that
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
    if PLACEHOLDERS.iter().any(|p| value.eq_ignore_ascii_case(p)) {
        return None;
    }
    Some(crate::model::truncate_str(value, MAX_VALUE_BYTES))
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
