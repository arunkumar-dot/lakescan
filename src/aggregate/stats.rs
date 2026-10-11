//! Small pieces shared by several summaries: the count-and-bytes cell used
//! by the inventory, the findings matrix, and both histograms, and the
//! char-boundary-safe truncation helper used anywhere a summary keeps a
//! bounded copy of an unbounded string (a key, an unrecognized storage
//! class name).

/// A count of objects (or findings) and their total size in bytes.
///
/// The building block for every fixed-size grid in `aggregate`: no heap, so
/// merging and observing are both infallible saturating additions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CountBytes {
    /// How many objects or findings landed in this cell.
    pub count: u64,
    /// The sum of `object.size` for everything in this cell.
    pub bytes: u64,
}

impl CountBytes {
    /// Records one more object/finding of `size` bytes into this cell.
    pub fn observe(&mut self, size: u64) {
        self.count = self.count.saturating_add(1);
        self.bytes = self.bytes.saturating_add(size);
    }

    /// Folds `other`'s totals into this cell. Order-independent: this is
    /// just saturating addition, which is commutative and associative.
    pub fn merge(&mut self, other: Self) {
        self.count = self.count.saturating_add(other.count);
        self.bytes = self.bytes.saturating_add(other.bytes);
    }
}

/// Copies `s` into an owned `String`, truncated to at most `max_bytes`
/// bytes at a `char` boundary (a multibyte character is never split), and
/// reports whether truncation actually happened.
///
/// Never indexes or slices with a raw range: the boundary search walks
/// downward from `max_bytes` using `str::is_char_boundary`, and the final
/// slice is taken with `str::get`, so a boundary that doesn't line up with
/// `max_bytes` is handled, not a panic risk.
pub(super) fn truncate_at_char_boundary(s: &str, max_bytes: usize) -> (String, bool) {
    if s.len() <= max_bytes {
        return (s.to_owned(), false);
    }

    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }

    (s.get(..end).unwrap_or_default().to_owned(), true)
}

#[cfg(test)]
mod tests {
    use super::{CountBytes, truncate_at_char_boundary};

    #[test]
    fn count_bytes_observe_and_merge_are_saturating() {
        let mut a = CountBytes::default();
        a.observe(10);
        a.observe(20);
        assert_eq!(
            a,
            CountBytes {
                count: 2,
                bytes: 30
            }
        );

        let mut b = CountBytes::default();
        b.observe(u64::MAX);
        a.merge(b);
        assert_eq!(a.count, 3);
        assert_eq!(a.bytes, u64::MAX); // saturated, not wrapped.
    }

    #[test]
    fn truncate_leaves_short_strings_untouched() {
        assert_eq!(
            truncate_at_char_boundary("hello", 10),
            ("hello".to_owned(), false)
        );
        assert_eq!(
            truncate_at_char_boundary("hello", 5),
            ("hello".to_owned(), false)
        );
    }

    #[test]
    fn truncate_cuts_long_ascii_strings_exactly_at_the_limit() {
        assert_eq!(
            truncate_at_char_boundary("hello world", 5),
            ("hello".to_owned(), true)
        );
    }

    #[test]
    fn truncate_never_splits_a_multibyte_character() {
        // "é" is 2 bytes (U+00E9); a cut at byte 1 would land mid-character.
        let (truncated, was_truncated) = truncate_at_char_boundary("éé", 1);
        assert!(was_truncated);
        assert!(truncated.len() <= 1);
        // The result must still be valid UTF-8 text (trivially true since
        // it's a `String`), and in this case it is empty: byte 1 is not a
        // boundary, so the search backs off to byte 0.
        assert_eq!(truncated, "");
    }

    #[test]
    fn truncate_at_exactly_the_limit_is_not_truncated() {
        assert_eq!(
            truncate_at_char_boundary("abcde", 5),
            ("abcde".to_owned(), false)
        );
    }
}
