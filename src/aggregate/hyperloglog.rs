//! [`Hll`]: a `HyperLogLog` cardinality estimator over `(etag, size)` pairs,
//! used as a lower-bound estimate of distinct object content.
//!
//! **Caveat documented, not hidden**: identical content uploaded as a
//! multipart upload, or encrypted with SSE-KMS, gets a *different* `ETag`
//! each time even though the bytes are the same. So `object_count -
//! estimate` is a lower bound on duplicate content, not an exact count,
//! and it is only meaningful when it is well above this estimator's own
//! ~1% relative error — a difference of a few objects proves nothing.

use std::hash::{DefaultHasher, Hash, Hasher};

/// log2 of the register count. 14 gives `2^14 = 16384` one-byte registers,
/// exactly 16 KiB, and a standard-error around `1.04 / sqrt(16384) ≈ 0.8%`.
const PRECISION: u32 = 14;

/// The number of registers, as a `u32` (not `usize`) so it can feed
/// `f64::from` directly in the estimator without an `as` cast.
const NUM_REGISTERS_U32: u32 = 1 << PRECISION;

/// The number of registers, as a `usize`, for indexing the register array.
const NUM_REGISTERS: usize = 1 << PRECISION;

/// A `HyperLogLog` sketch with `2^14` one-byte registers (16 KiB), estimating
/// the number of distinct `(etag, size)` pairs observed.
///
/// No heap: the register array is inline, so [`Hll::MAX_BYTES`] is just
/// `size_of::<Self>()`. Hashing uses [`DefaultHasher`], which — unlike
/// `RandomState`'s hasher — is not randomized per process, so the same
/// input always lands in the same register; that determinism is what
/// makes [`Hll::merge`] (element-wise max per register) equal to
/// sketching the union from scratch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Hll {
    registers: [u8; NUM_REGISTERS],
}

impl Default for Hll {
    fn default() -> Self {
        Self {
            registers: [0; NUM_REGISTERS],
        }
    }
}

impl Hll {
    /// This sketch's total size: fixed, with no heap component.
    pub(super) const MAX_BYTES: usize = size_of::<Self>();

    /// Records one `(etag, size)` pair.
    pub(super) fn observe(&mut self, etag: &str, size: u64) {
        let hash = hash_of(etag, size);
        let index = usize::try_from(hash >> (64 - PRECISION)).unwrap_or(0);
        let rank = rank_of(hash);
        if let Some(register) = self.registers.get_mut(index) {
            *register = (*register).max(rank);
        }
    }

    /// Folds `other`'s registers into `self`: element-wise max, which is
    /// exactly what sketching the union of both inputs from scratch would
    /// produce.
    pub(super) fn merge(&mut self, other: &Self) {
        for (a, b) in self.registers.iter_mut().zip(other.registers.iter()) {
            *a = (*a).max(*b);
        }
    }

    /// The estimated number of distinct `(etag, size)` pairs observed.
    ///
    /// The standard `HyperLogLog` estimator, with Flajolet et al.'s
    /// small-range linear-counting correction applied when the raw
    /// estimate is in the range where it is known to be biased. No
    /// large-range correction is applied: that only matters near `2^32`
    /// distinct values, far beyond what this estimator is sized for.
    #[must_use]
    pub(super) fn estimate(&self) -> f64 {
        let m = f64::from(NUM_REGISTERS_U32);
        let alpha_m = 0.7213 / (1.0 + 1.079 / m);

        let sum_of_inverse_powers: f64 = self
            .registers
            .iter()
            .map(|&register| 2.0_f64.powi(-i32::from(register)))
            .sum();
        let raw_estimate = alpha_m * m * m / sum_of_inverse_powers;

        if raw_estimate <= 2.5 * m {
            let zero_registers: u32 = self
                .registers
                .iter()
                .map(|&register| u32::from(register == 0))
                .sum();
            if zero_registers > 0 {
                return m * (m / f64::from(zero_registers)).ln();
            }
        }
        raw_estimate
    }
}

fn hash_of(etag: &str, size: u64) -> u64 {
    let mut hasher = DefaultHasher::new();
    etag.hash(&mut hasher);
    size.hash(&mut hasher);
    hasher.finish()
}

/// The register rank for a hash: one more than the number of leading zero
/// bits among the `64 - PRECISION` bits of `hash` *not* used to select the
/// register (see [`Hll::observe`]), capped to that many bits.
///
/// `hash << PRECISION` moves exactly those `64 - PRECISION` low bits up to
/// the top of a 64-bit word (filling the vacated low `PRECISION` bits with
/// zero), so counting *its* leading zeros counts leading zeros among the
/// right bits — except when the significant bits are all zero, in which
/// case the shifted-in zero filler would otherwise inflate the count past
/// what only `64 - PRECISION` real bits can justify; `min` guards exactly
/// that case.
fn rank_of(hash: u64) -> u8 {
    let significant_bits = 64 - PRECISION;
    let remaining = hash << PRECISION;
    let leading_zeros = remaining.leading_zeros().min(significant_bits);
    u8::try_from(leading_zeros.saturating_add(1)).unwrap_or(u8::MAX)
}

#[cfg(test)]
mod tests {
    use super::Hll;

    fn relative_error(estimate: f64, actual: f64) -> f64 {
        (estimate - actual).abs() / actual
    }

    #[test]
    fn empty_sketch_estimates_zero() {
        let hll = Hll::default();
        assert!(hll.estimate() < 1.0);
    }

    #[test]
    fn one_hundred_thousand_distinct_inputs_within_three_percent() {
        let mut hll = Hll::default();
        for i in 0..100_000_u64 {
            hll.observe(&format!("etag-{i}"), i);
        }
        let estimate = hll.estimate();
        assert!(
            relative_error(estimate, 100_000.0) <= 0.03,
            "estimate {estimate} too far from 100000"
        );
    }

    #[test]
    fn one_thousand_distinct_inputs_each_repeated_fifty_times_estimates_one_thousand() {
        let mut hll = Hll::default();
        for i in 0..1_000_u64 {
            for _ in 0..50 {
                hll.observe(&format!("etag-{i}"), i);
            }
        }
        let estimate = hll.estimate();
        assert!(
            relative_error(estimate, 1_000.0) <= 0.03,
            "estimate {estimate} too far from 1000"
        );
    }

    #[test]
    fn merging_two_sketches_matches_sketching_the_union() {
        let mut whole = Hll::default();
        let mut left = Hll::default();
        let mut right = Hll::default();

        for i in 0..5_000_u64 {
            whole.observe(&format!("etag-{i}"), i);
            if i % 2 == 0 {
                left.observe(&format!("etag-{i}"), i);
            } else {
                right.observe(&format!("etag-{i}"), i);
            }
        }

        left.merge(&right);
        assert_eq!(left, whole);
    }

    #[test]
    fn merge_is_commutative_for_overlapping_inputs() {
        let mut a = Hll::default();
        let mut b = Hll::default();
        for i in 0..1_000_u64 {
            a.observe(&format!("etag-{i}"), i);
        }
        for i in 500..1_500_u64 {
            b.observe(&format!("etag-{i}"), i);
        }

        let mut a_then_b = a.clone();
        a_then_b.merge(&b);
        let mut b_then_a = b.clone();
        b_then_a.merge(&a);

        assert_eq!(a_then_b, b_then_a);
    }
}
