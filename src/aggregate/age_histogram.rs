//! [`AgeHistogram`]: a distribution of object age, measured from the scan's
//! `now` instant.

use std::time::{Duration, SystemTime};

use super::stats::CountBytes;

/// 8 buckets: `< 1 day`, `1-7 days`, `7-30`, `30-90`, `90-180`, `180-365`,
/// `1-2 years`, `>= 2 years`. Years are treated as 365 days, matching how
/// `rules::stale_standard` already treats "90 days" as a flat duration
/// with no calendar arithmetic.
const BUCKETS: usize = 8;

/// The upper edge of each bucket except the last (which has none): bucket
/// `i` covers `[edges[i-1], edges[i])`, bucket 0 covers `[0, edges[0])`,
/// and the last bucket covers everything from `edges[6]` up.
const EDGES: [Duration; BUCKETS - 1] = [
    Duration::from_hours(24),       // 1 day
    Duration::from_hours(24 * 7),   // 7 days
    Duration::from_hours(24 * 30),  // 30 days
    Duration::from_hours(24 * 90),  // 90 days
    Duration::from_hours(24 * 180), // 180 days
    Duration::from_hours(24 * 365), // 365 days
    Duration::from_hours(24 * 730), // 2 years
];

/// Which bucket an object of age `age` falls into.
fn bucket_of(age: Duration) -> usize {
    EDGES
        .iter()
        .position(|&edge| age < edge)
        .unwrap_or(EDGES.len())
}

/// Age measured from `now`, treating a `last_modified` after `now` (clock
/// skew, or a scripted test) as age zero rather than erroring.
fn age_of(last_modified: SystemTime, now: SystemTime) -> Duration {
    now.duration_since(last_modified).unwrap_or_default()
}

/// The `[lower, upper)` age range bucket `index` covers. `upper` is `None`
/// for the last bucket, which has no finite top. Out-of-range indices get
/// the empty `(Duration::ZERO, Some(Duration::ZERO))` range.
///
/// The reporter renders these bounds; it never recomputes them, so this is
/// the one place the bucket layout is spelled out as actual values rather
/// than just a comparison (`bucket_of`).
#[must_use]
pub(super) fn bucket_bounds(index: usize) -> (Duration, Option<Duration>) {
    if index == 0 {
        return (Duration::ZERO, EDGES.first().copied());
    }
    if index == BUCKETS - 1 {
        return (EDGES.last().copied().unwrap_or(Duration::ZERO), None);
    }
    match (
        index.checked_sub(1).and_then(|i| EDGES.get(i)),
        EDGES.get(index),
    ) {
        (Some(&lower), Some(&upper)) => (lower, Some(upper)),
        _ => (Duration::ZERO, Some(Duration::ZERO)),
    }
}

/// A fixed, 8-bucket histogram of object age.
///
/// No heap: every bucket lives inline, so [`AgeHistogram::MAX_BYTES`] is
/// just `size_of::<Self>()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AgeHistogram {
    buckets: [CountBytes; BUCKETS],
}

impl Default for AgeHistogram {
    fn default() -> Self {
        Self {
            buckets: [CountBytes::default(); BUCKETS],
        }
    }
}

impl AgeHistogram {
    /// This histogram's total size: fixed, with no heap component.
    pub(super) const MAX_BYTES: usize = size_of::<Self>();

    /// Records one object, aging it from `now`.
    pub(super) fn observe(&mut self, last_modified: SystemTime, now: SystemTime, size: u64) {
        let bucket_index = bucket_of(age_of(last_modified, now));
        if let Some(bucket) = self.buckets.get_mut(bucket_index) {
            bucket.observe(size);
        }
    }

    /// The count and bytes in bucket `index` (`0..8`), or the zero cell if
    /// `index` is out of range.
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
    use std::time::Duration;

    use super::{AgeHistogram, bucket_bounds, bucket_of};

    #[test]
    fn boundaries_are_inclusive_on_the_lower_edge() {
        let one_day = Duration::from_hours(24);
        let one_second = Duration::from_secs(1);
        assert_eq!(
            bucket_of(one_day.checked_sub(one_second).unwrap_or_default()),
            0
        );
        assert_eq!(bucket_of(one_day), 1);

        let two_years = Duration::from_hours(24 * 730);
        assert_eq!(
            bucket_of(two_years.checked_sub(one_second).unwrap_or_default()),
            6
        );
        assert_eq!(bucket_of(two_years), 7);
    }

    #[test]
    fn zero_age_is_bucket_zero() {
        assert_eq!(bucket_of(Duration::ZERO), 0);
    }

    #[test]
    fn every_named_range_lands_where_expected() {
        let day = Duration::from_hours(24);
        assert_eq!(bucket_of(day * 3), 1); // 1-7 days
        assert_eq!(bucket_of(day * 15), 2); // 7-30
        assert_eq!(bucket_of(day * 60), 3); // 30-90
        assert_eq!(bucket_of(day * 120), 4); // 90-180
        assert_eq!(bucket_of(day * 300), 5); // 180-365
        assert_eq!(bucket_of(day * 500), 6); // 1-2 years
        assert_eq!(bucket_of(day * 1000), 7); // >= 2 years
    }

    #[test]
    fn a_last_modified_after_now_is_age_zero() {
        let now = std::time::SystemTime::UNIX_EPOCH + Duration::from_hours(24 * 1000);
        let mut hist = AgeHistogram::default();
        hist.observe(now + Duration::from_hours(1), now, 42);
        assert_eq!(hist.bucket(0).count, 1);
        assert_eq!(hist.bucket(0).bytes, 42);
    }

    #[test]
    fn merge_sums_every_bucket() {
        let now = std::time::SystemTime::UNIX_EPOCH + Duration::from_hours(24 * 1000);
        let mut a = AgeHistogram::default();
        a.observe(now, now, 1);
        let mut b = AgeHistogram::default();
        b.observe(now, now, 1);
        b.observe(now - Duration::from_hours(24 * 1000), now, 1);

        a.merge(&b);
        assert_eq!(a.bucket(0).count, 2);
        assert_eq!(a.bucket(7).count, 1);
    }

    #[test]
    fn bucket_bounds_cover_every_bucket_contiguously() {
        let day = Duration::from_hours(24);
        assert_eq!(bucket_bounds(0), (Duration::ZERO, Some(day)));
        assert_eq!(bucket_bounds(1), (day, Some(day * 7)));
        assert_eq!(bucket_bounds(7), (day * 730, None));

        // Every bucket's upper bound equals the next bucket's lower bound.
        for index in 0..6 {
            let (_, upper) = bucket_bounds(index);
            let (next_lower, _) = bucket_bounds(index + 1);
            assert_eq!(upper, Some(next_lower), "bucket {index} -> {}", index + 1);
        }
    }

    #[test]
    fn bucket_bounds_out_of_range_is_the_empty_range() {
        assert_eq!(bucket_bounds(100), (Duration::ZERO, Some(Duration::ZERO)));
    }
}
