//! [`SizeHistogram`]: a log2 distribution of object sizes.

use super::stats::CountBytes;

/// 65 buckets: bucket 0 for size 0, and bucket `i` (`1..=64`) for sizes in
/// `[2^(i-1), 2^i)`. 65 buckets exactly cover every possible `u64`, since
/// bucket 64 is `[2^63, 2^64)` and `u64::MAX < 2^64`.
const BUCKETS: usize = 65;

/// Which bucket `size` falls into.
fn bucket_of(size: u64) -> usize {
    if size == 0 {
        return 0;
    }
    // `ilog2` never exceeds 63 for a nonzero `u64`, so `+ 1` never
    // overflows and always lands in `1..=64`.
    usize::try_from(size.ilog2()).unwrap_or(0) + 1
}

/// The `[lower, upper)` size range bucket `index` covers. `upper` is `None`
/// for the last bucket (`[2^63, u64::MAX]`, since `2^64` does not fit in a
/// `u64`). Out-of-range indices get the empty `(0, Some(0))` range.
///
/// The reporter renders these bounds; it never recomputes them, so this is
/// the one place the bucket layout is spelled out as actual values rather
/// than just a comparison (`bucket_of`).
#[must_use]
pub(super) fn bucket_bounds(index: usize) -> (u64, Option<u64>) {
    const LAST_BUCKET: usize = BUCKETS - 1;
    match index {
        0 => (0, Some(1)),
        LAST_BUCKET => (1_u64 << 63, None),
        1..LAST_BUCKET => (1_u64 << (index - 1), Some(1_u64 << index)),
        _ => (0, Some(0)),
    }
}

/// A fixed, 65-bucket log2 histogram of object sizes.
///
/// No heap: every bucket lives inline, so [`SizeHistogram::MAX_BYTES`] is
/// just `size_of::<Self>()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SizeHistogram {
    buckets: [CountBytes; BUCKETS],
}

impl Default for SizeHistogram {
    fn default() -> Self {
        Self {
            buckets: [CountBytes::default(); BUCKETS],
        }
    }
}

impl SizeHistogram {
    /// This histogram's total size: fixed, with no heap component.
    pub(super) const MAX_BYTES: usize = size_of::<Self>();

    /// Records one object of `size` bytes into its bucket.
    pub(super) fn observe(&mut self, size: u64) {
        if let Some(bucket) = self.buckets.get_mut(bucket_of(size)) {
            bucket.observe(size);
        }
    }

    /// The count and bytes in bucket `index` (`0..=64`), or the zero cell
    /// if `index` is out of range.
    #[must_use]
    pub(super) fn bucket(&self, index: usize) -> CountBytes {
        self.buckets.get(index).copied().unwrap_or_default()
    }

    /// The number of buckets ([`BUCKETS`]).
    #[must_use]
    pub(super) fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Folds `other`'s buckets into `self`.
    pub(super) fn merge(&mut self, other: &Self) {
        for (bucket, other_bucket) in self.buckets.iter_mut().zip(other.buckets.iter()) {
            bucket.merge(*other_bucket);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SizeHistogram, bucket_bounds, bucket_of};

    #[test]
    fn zero_falls_in_bucket_zero() {
        assert_eq!(bucket_of(0), 0);
    }

    #[test]
    fn one_falls_in_bucket_one() {
        // Bucket 1 covers [2^0, 2^1) = [1, 2).
        assert_eq!(bucket_of(1), 1);
    }

    #[test]
    fn exact_powers_of_two_start_a_new_bucket() {
        // 2^k is the start of bucket k+1: [2^k, 2^(k+1)).
        for k in 0..63 {
            let power = 1_u64 << k;
            assert_eq!(bucket_of(power), k + 1, "2^{k}");
            assert_eq!(bucket_of(power - 1), k, "2^{k} - 1");
        }
    }

    #[test]
    fn u64_max_falls_in_the_last_bucket() {
        assert_eq!(bucket_of(u64::MAX), 64);
    }

    #[test]
    fn observe_and_bucket_round_trip() {
        let mut hist = SizeHistogram::default();
        hist.observe(0);
        hist.observe(1);
        hist.observe(3);
        hist.observe(1024);

        assert_eq!(hist.bucket(0).count, 1); // size 0
        assert_eq!(hist.bucket(1).count, 1); // size 1: [1,2)
        assert_eq!(hist.bucket(2).count, 1); // size 3: [2,4)
        assert_eq!(hist.bucket(11).count, 1); // size 1024: [1024,2048)
        assert_eq!(hist.bucket(11).bytes, 1024);
    }

    #[test]
    fn merge_sums_every_bucket() {
        let mut a = SizeHistogram::default();
        a.observe(5);
        let mut b = SizeHistogram::default();
        b.observe(5);
        b.observe(0);

        a.merge(&b);
        assert_eq!(a.bucket(bucket_of(5)).count, 2);
        assert_eq!(a.bucket(0).count, 1);
    }

    #[test]
    fn bucket_bounds_cover_every_bucket_contiguously() {
        assert_eq!(bucket_bounds(0), (0, Some(1)));
        assert_eq!(bucket_bounds(1), (1, Some(2)));
        assert_eq!(bucket_bounds(64), (1_u64 << 63, None));

        for index in 0..63 {
            let (_, upper) = bucket_bounds(index);
            let (next_lower, _) = bucket_bounds(index + 1);
            assert_eq!(upper, Some(next_lower), "bucket {index} -> {}", index + 1);
        }
    }

    #[test]
    fn bucket_bounds_out_of_range_is_the_empty_range() {
        assert_eq!(bucket_bounds(100), (0, Some(0)));
    }
}
