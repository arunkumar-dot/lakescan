//! Folds the finding stream into bounded summaries.
//!
//! Single responsibility: answer whole-bucket questions — totals, top-k,
//! distributions, cardinalities — without ever holding the bucket in memory.
//! Findings that `suppress` set aside arrive separately, through
//! [`Aggregates::observe_suppressed`], and are only counted per rule.
//!
//! **Memory budget: 18 MB.** Bounded sketches only. Every aggregator declares
//! a `const` upper bound on its own footprint, and no aggregator may use a
//! structure whose size grows with the number of objects or findings scanned.
//! This is the only module in the pipeline permitted to retain state across
//! objects, which is exactly why its bound is explicit and checked.
//!
//! [`Aggregates::MAX_BYTES`] is a compile-time-checked sum of every summary's
//! own `MAX_BYTES`: **112,840 bytes (~110 KiB)** as of this milestone,
//! asserted below to be no more than 18 MiB. The real total is far smaller
//! than that ceiling, because every fixed capacity here (10 samples per
//! rule, 20 largest objects, 16 KiB of `Hll` registers) is sized for what a
//! report needs, not for the budget. Every summary here is mergeable and
//! order-independent: observing the same objects and findings in any order,
//! or splitting them across any number of [`Aggregates`] and folding the
//! results together with [`Aggregates::merge`], produces the identical
//! summary. That property, not raw performance, is what every type in this
//! module is designed around.

mod age_histogram;
mod hyperloglog;
mod inventory;
mod matrix;
mod sample;
mod size_histogram;
mod stats;
mod topk;

use std::time::{Duration, SystemTime};

use age_histogram::AgeHistogram;
use hyperloglog::Hll;
use inventory::Inventory;
use matrix::FindingsMatrix;
use size_histogram::SizeHistogram;
use topk::TopK;

pub use sample::Sample;
pub use stats::CountBytes;

use crate::model::{Finding, ObjectMeta, RuleId, Severity, StorageClass};

/// How many rules exist; sizes the per-rule sample array.
const NUM_RULES: usize = RuleId::ALL.len();

/// How many findings are kept as samples for each rule.
const SAMPLES_PER_RULE: usize = 10;

/// How many objects are kept in the largest-objects list.
const LARGEST_OBJECTS: usize = 20;

/// The fraction of the object count the duplicate lower bound must reach
/// before [`Aggregates::duplicates_significant`] calls it real.
const SIGNIFICANT_DUPLICATE_FRACTION: f64 = 0.02;

/// The whole-bucket summary this pipeline stage builds: one of each
/// summary described in this module's doc, folded from every object and
/// finding observed.
#[derive(Debug, Clone, PartialEq)]
pub struct Aggregates {
    now: SystemTime,
    inventory: Inventory,
    matrix: FindingsMatrix,
    samples: [TopK<Sample, SAMPLES_PER_RULE>; NUM_RULES],
    largest: TopK<Sample, LARGEST_OBJECTS>,
    /// Per rule (indexed by [`RuleId::index`]): findings a suppression
    /// entry covered, which appear nowhere else in this summary.
    suppressed: [CountBytes; NUM_RULES],
    size_histogram: SizeHistogram,
    age_histogram: AgeHistogram,
    hll: Hll,
}

impl Aggregates {
    /// The combined worst-case size of every summary this struct holds:
    /// the plain sum of each summary type's own `MAX_BYTES`. 112,840 bytes
    /// as of this milestone (see this module's doc); checked below to be
    /// within the 18 MiB module budget.
    pub const MAX_BYTES: usize = Inventory::MAX_BYTES
        + FindingsMatrix::MAX_BYTES
        + NUM_RULES * TopK::<Sample, SAMPLES_PER_RULE>::MAX_BYTES
        + TopK::<Sample, LARGEST_OBJECTS>::MAX_BYTES
        + size_of::<[CountBytes; NUM_RULES]>()
        + SizeHistogram::MAX_BYTES
        + AgeHistogram::MAX_BYTES
        + Hll::MAX_BYTES;

    /// Starts an empty summary. `now` should be the same scan-start
    /// instant passed to [`crate::rules::EvalContext`], so that this
    /// summary's age histogram and the rule engine's age-based rules agree
    /// on what "now" meant for this run.
    #[must_use]
    pub fn new(now: SystemTime) -> Self {
        Self {
            now,
            inventory: Inventory::default(),
            matrix: FindingsMatrix::default(),
            samples: std::array::from_fn(|_| TopK::default()),
            largest: TopK::default(),
            suppressed: [CountBytes::default(); NUM_RULES],
            size_histogram: SizeHistogram::default(),
            age_histogram: AgeHistogram::default(),
            hll: Hll::default(),
        }
    }

    /// Records one listed object: the inventory, both histograms, the
    /// distinct-content estimator, and a candidacy check against the
    /// largest-objects list.
    pub fn observe_object(&mut self, object: &ObjectMeta) {
        self.inventory.observe(object);
        self.size_histogram.observe(object.size);
        self.age_histogram
            .observe(object.last_modified, self.now, object.size);
        self.hll.observe(&object.etag, object.size);

        self.largest.offer(
            |worst| sample::rank_against(None, object.size, &object.key, worst),
            || Sample::for_object(object),
        );
    }

    /// Records one finding: the findings matrix, and a candidacy check
    /// against that rule's sample list.
    pub fn observe_finding(&mut self, finding: Finding<'_>) {
        self.matrix
            .observe(finding.rule, finding.severity, finding.object.size);

        if let Some(slot) = self.samples.get_mut(finding.rule.index()) {
            let severity = finding.severity;
            let object = finding.object;
            slot.offer(
                |worst| sample::rank_against(Some(severity), object.size, &object.key, worst),
                || Sample::for_finding(object, severity),
            );
        }
    }

    /// Records one suppressed finding: its rule's suppressed count and
    /// bytes, and nothing else. A suppressed finding never reaches the
    /// findings matrix (so never the verdict) or a rule's samples.
    pub fn observe_suppressed(&mut self, finding: Finding<'_>) {
        if let Some(cell) = self.suppressed.get_mut(finding.rule.index()) {
            cell.observe(finding.object.size);
        }
    }

    /// Folds `other` into `self`. Order-independent: see this module's doc.
    pub fn merge(&mut self, other: Self) {
        self.inventory.merge(other.inventory);
        self.matrix.merge(&other.matrix);
        for (slot, other_slot) in self.samples.iter_mut().zip(other.samples) {
            slot.merge(other_slot);
        }
        self.largest.merge(other.largest);
        for (cell, other_cell) in self.suppressed.iter_mut().zip(other.suppressed) {
            cell.merge(other_cell);
        }
        self.size_histogram.merge(&other.size_histogram);
        self.age_histogram.merge(&other.age_histogram);
        self.hll.merge(&other.hll);
    }

    /// The total number of objects observed.
    #[must_use]
    pub fn total_objects(&self) -> u64 {
        self.inventory.overall.count
    }

    /// The total bytes across every object observed.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.inventory.overall.bytes
    }

    /// The count and bytes for one known storage class, or `None` if
    /// `class` is [`StorageClass::Other`].
    #[must_use]
    pub fn class_stats(&self, class: &StorageClass) -> Option<CountBytes> {
        self.inventory.known_class(class)
    }

    /// The tracked unrecognized storage-class names and their stats, in
    /// lexicographically ascending order.
    pub fn other_classes(&self) -> impl Iterator<Item = (&str, CountBytes)> {
        self.inventory.other_classes()
    }

    /// The combined count and bytes of *every* unrecognized object —
    /// exact, unlike [`Aggregates::other_classes`], which only names the 8
    /// lexicographically smallest distinct unrecognized class names and
    /// would undercount this total if summed directly once a 9th distinct
    /// name has ever displaced one.
    #[must_use]
    pub fn unrecognized_totals(&self) -> CountBytes {
        self.inventory.unrecognized_totals()
    }

    /// Every storage class with at least one object, known or not: the
    /// wire name of each class in [`StorageClass::KNOWN`] that has a
    /// non-zero count, followed by the tracked unrecognized class names
    /// (already non-zero by construction — see [`Aggregates::other_classes`]).
    ///
    /// The one accessor a reporter needs for "storage class breakdown,
    /// skip the empty ones": it holds no list of classes of its own,
    /// since [`StorageClass::KNOWN`] is the single source of truth for
    /// that.
    pub fn nonzero_storage_classes(&self) -> impl Iterator<Item = (&str, CountBytes)> {
        StorageClass::KNOWN
            .iter()
            .filter_map(|class| {
                let stats = self.inventory.known_class(class)?;
                (stats.count > 0).then_some((class.as_wire(), stats))
            })
            .chain(self.other_classes())
    }

    /// The count and bytes of findings for this exact `(rule, severity)`.
    #[must_use]
    pub fn matrix_cell(&self, rule: RuleId, severity: Severity) -> CountBytes {
        self.matrix.cell(rule, severity)
    }

    /// The count and bytes of `rule`'s suppressed findings.
    #[must_use]
    pub fn suppressed(&self, rule: RuleId) -> CountBytes {
        self.suppressed
            .get(rule.index())
            .copied()
            .unwrap_or_default()
    }

    /// The highest severity seen across every finding, or `None` if no
    /// finding was ever observed.
    #[must_use]
    pub fn worst_severity(&self) -> Option<Severity> {
        self.matrix.worst_severity()
    }

    /// Up to [`SAMPLES_PER_RULE`] findings for `rule`, best-first (severity
    /// descending, then size descending, then key ascending).
    #[must_use]
    pub fn samples_for(&self, rule: RuleId) -> Vec<&Sample> {
        self.samples
            .get(rule.index())
            .map(TopK::sorted)
            .unwrap_or_default()
    }

    /// Up to [`LARGEST_OBJECTS`] objects, largest-first (size descending,
    /// then key ascending).
    #[must_use]
    pub fn largest_objects(&self) -> Vec<&Sample> {
        self.largest.sorted()
    }

    /// The count and bytes in size-histogram bucket `index`; see
    /// `aggregate::size_histogram` for the bucket layout.
    #[must_use]
    pub fn size_bucket(&self, index: usize) -> CountBytes {
        self.size_histogram.bucket(index)
    }

    /// The number of size-histogram buckets.
    #[must_use]
    pub fn size_bucket_count(&self) -> usize {
        self.size_histogram.bucket_count()
    }

    /// The `[lower, upper)` byte-size range size-histogram bucket `index`
    /// covers; `upper` is `None` for the last bucket, which has no finite
    /// top. The reporter renders these; it never recomputes them.
    #[must_use]
    pub fn size_bucket_bounds(index: usize) -> (u64, Option<u64>) {
        size_histogram::bucket_bounds(index)
    }

    /// The count and bytes in age-histogram bucket `index`; see
    /// `aggregate::age_histogram` for the bucket layout.
    #[must_use]
    pub fn age_bucket(&self, index: usize) -> CountBytes {
        self.age_histogram.bucket(index)
    }

    /// The number of age-histogram buckets.
    #[must_use]
    pub fn age_bucket_count(&self) -> usize {
        self.age_histogram.bucket_count()
    }

    /// The `[lower, upper)` age range age-histogram bucket `index` covers;
    /// `upper` is `None` for the last bucket, which has no finite top. The
    /// reporter renders these; it never recomputes them.
    #[must_use]
    pub fn age_bucket_bounds(index: usize) -> (Duration, Option<Duration>) {
        age_histogram::bucket_bounds(index)
    }

    /// The estimated number of distinct object contents observed, clamped
    /// to [`Aggregates::total_objects`]: the raw estimate can overshoot the
    /// true count slightly, but there can never be more distinct contents
    /// than objects. See `aggregate::hyperloglog` for the `ETag` caveat
    /// that makes this a lower bound on duplicates, not an exact count.
    #[must_use]
    pub fn distinct_content_estimate(&self) -> f64 {
        self.hll.estimate().min(u64_to_f64(self.total_objects()))
    }

    /// A lower bound on how many objects share content with some other
    /// object: `total_objects - distinct_content_estimate`, floored at
    /// `0.0` (the estimate can exceed the true count by a little, being an
    /// estimate). See `aggregate::hyperloglog`'s doc for why this is a
    /// *lower* bound — identical content re-uploaded with a different
    /// encryption or upload method gets a different `ETag` — and is only
    /// meaningful when well above the estimator's own ~1% error.
    #[must_use]
    pub fn duplicate_lower_bound(&self) -> f64 {
        (u64_to_f64(self.total_objects()) - self.distinct_content_estimate()).max(0.0)
    }

    /// Whether [`Aggregates::duplicate_lower_bound`] is large enough to
    /// report as real duplication rather than estimator noise: non-zero
    /// and at least [`SIGNIFICANT_DUPLICATE_FRACTION`] of the object count.
    /// The estimator's standard error is ~1%, so 2% is about two standard
    /// errors. Decided here so the reporter never has to.
    #[must_use]
    pub fn duplicates_significant(&self) -> bool {
        let bound = self.duplicate_lower_bound();
        bound > 0.0 && bound >= SIGNIFICANT_DUPLICATE_FRACTION * u64_to_f64(self.total_objects())
    }

    /// The heap this summary currently occupies, across every field that
    /// owns any: the inventory's tracked unrecognized class names, and
    /// every sample's key and (if unrecognized) storage class name. The
    /// findings matrix, both histograms, and the HLL own no heap at all,
    /// so they are not part of this sum.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        self.inventory.heap_bytes()
            + self.samples.iter().map(TopK::heap_bytes).sum::<usize>()
            + self.largest.heap_bytes()
    }
}

const _: () = assert!(Aggregates::MAX_BYTES <= 18 * 1024 * 1024);

/// Converts `value` to the nearest `f64`, exactly when `value` fits in a
/// `u32` and otherwise by reconstructing it from its high and low 32-bit
/// halves (each of which *does* fit, and so converts exactly via
/// `f64::from`).
///
/// `f64` has no `From<u64>`/`TryFrom<u64>` in `std` — a `u64` can exceed
/// the mantissa's 53 bits of precision, so neither trait's contract fits —
/// and an `as` cast is a clippy pedantic error under this crate's lints.
/// This is the honest alternative: it loses precision only where an `as`
/// cast would lose exactly the same precision, never more.
fn u64_to_f64(value: u64) -> f64 {
    if let Ok(small) = u32::try_from(value) {
        return f64::from(small);
    }
    let high = u32::try_from(value >> 32).unwrap_or(0);
    let low = u32::try_from(value & 0xFFFF_FFFF).unwrap_or(0);
    f64::from(high).mul_add(4_294_967_296.0, f64::from(low))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::Aggregates;
    use crate::model::{ObjectMeta, RuleId, Severity, StorageClass};
    use crate::rules::{self, EvalContext};

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_hours(24 * 10_000)
    }

    /// A fixed, varied set of objects: some clean, some violating one or
    /// more rules, spanning several storage classes and sizes.
    fn fixture_objects() -> Vec<ObjectMeta> {
        let now = now();
        vec![
            ObjectMeta {
                key: "reports/summary.csv".to_owned(),
                size: 2048,
                last_modified: now,
                etag: "etag-1".to_owned(),
                storage_class: StorageClass::Standard,
            },
            ObjectMeta {
                key: "id_rsa".to_owned(),
                size: 512,
                last_modified: now,
                etag: "etag-2".to_owned(),
                storage_class: StorageClass::Standard,
            },
            ObjectMeta {
                key: "archive/legacy.bin".to_owned(),
                size: 1024,
                last_modified: now,
                etag: "etag-3".to_owned(),
                storage_class: StorageClass::ReducedRedundancy,
            },
            ObjectMeta {
                key: "old/huge.bin".to_owned(),
                size: 2 * 1024 * 1024 * 1024,
                last_modified: now - Duration::from_hours(24 * 200),
                etag: "etag-4".to_owned(),
                storage_class: StorageClass::Standard,
            },
            ObjectMeta {
                key: "folder/".to_owned(),
                size: 0,
                last_modified: now,
                etag: "etag-5".to_owned(),
                storage_class: StorageClass::Standard,
            },
            ObjectMeta {
                key: "empty.bin".to_owned(),
                size: 0,
                last_modified: now,
                etag: "etag-6".to_owned(),
                storage_class: StorageClass::Standard,
            },
            ObjectMeta {
                key: "mystery.bin".to_owned(),
                size: 1024,
                last_modified: now,
                etag: "etag-7".to_owned(),
                storage_class: StorageClass::Other("NEW_CLASS".to_owned()),
            },
        ]
    }

    /// Observes every object (and every finding it raises) from `objects`
    /// into a fresh `Aggregates`.
    fn observe_all(objects: &[ObjectMeta]) -> Aggregates {
        let ctx = EvalContext { now: now() };
        let mut aggregates = Aggregates::new(now());
        for object in objects {
            aggregates.observe_object(object);
            for finding in rules::evaluate(object, &ctx) {
                aggregates.observe_finding(finding);
            }
        }
        aggregates
    }

    #[test]
    fn observing_in_either_order_or_merging_two_halves_all_agree() {
        let objects = fixture_objects();
        let mut reversed = objects.clone();
        reversed.reverse();

        let forward = observe_all(&objects);
        let backward = observe_all(&reversed);

        let (first_half, second_half) = objects.split_at(3);
        let mut merged = observe_all(first_half);
        merged.merge(observe_all(second_half));

        assert_eq!(forward, backward);
        assert_eq!(forward, merged);
    }

    #[test]
    fn totals_and_matrix_reflect_the_fixture() {
        let aggregates = observe_all(&fixture_objects());

        assert_eq!(aggregates.total_objects(), 7);
        assert_eq!(
            aggregates
                .matrix_cell(RuleId::SensitiveKey, Severity::High)
                .count,
            1
        );
        assert_eq!(
            aggregates
                .matrix_cell(RuleId::ReducedRedundancy, Severity::Medium)
                .count,
            1
        );
        assert_eq!(
            aggregates
                .matrix_cell(RuleId::StaleStandard, Severity::Medium)
                .count,
            1
        );
        assert_eq!(
            aggregates
                .matrix_cell(RuleId::ZeroByteObject, Severity::Info)
                .count,
            1,
            "folder/ marker must not count; empty.bin must"
        );
        assert_eq!(
            aggregates
                .matrix_cell(RuleId::UnknownStorageClass, Severity::Info)
                .count,
            1
        );
        assert_eq!(aggregates.worst_severity(), Some(Severity::High));
    }

    #[test]
    fn nonzero_storage_classes_lists_known_then_unrecognized_skipping_empty_ones() {
        let aggregates = observe_all(&fixture_objects());

        let classes: Vec<(&str, u64)> = aggregates
            .nonzero_storage_classes()
            .map(|(name, stats)| (name, stats.count))
            .collect();

        // Standard (5 objects) and ReducedRedundancy (1) are known classes,
        // in StorageClass::KNOWN order; NEW_CLASS is the one unrecognized
        // class, appended after. Every other known class has zero objects
        // and must not appear at all.
        assert_eq!(
            classes,
            [("STANDARD", 5), ("REDUCED_REDUNDANCY", 1), ("NEW_CLASS", 1)]
        );
    }

    #[test]
    fn adversarial_scan_stays_within_max_bytes() {
        let ctx = EvalContext { now: now() };
        let mut aggregates = Aggregates::new(now());

        for n in 0..100_000_u64 {
            let object = ObjectMeta {
                key: format!("{n:0>1500}"),
                size: n,
                last_modified: now() - Duration::from_hours(n % (24 * 1000)),
                etag: format!("etag-{n}"),
                storage_class: if n.is_multiple_of(7) {
                    StorageClass::Other(format!("CLASS-{n:0>500}"))
                } else {
                    StorageClass::Standard
                },
            };
            aggregates.observe_object(&object);
            for finding in rules::evaluate(&object, &ctx) {
                aggregates.observe_finding(finding);
            }
        }

        assert!(
            size_of::<Aggregates>() + aggregates.heap_bytes() <= Aggregates::MAX_BYTES,
            "size_of (={}) + heap_bytes (={}) exceeds MAX_BYTES (={})",
            size_of::<Aggregates>(),
            aggregates.heap_bytes(),
            Aggregates::MAX_BYTES
        );
    }

    #[test]
    fn duplicate_lower_bound_is_total_objects_minus_estimate_floored_at_zero() {
        // Every object has a distinct etag+size, so the HLL estimate should
        // land close to the true count and the lower bound close to zero.
        let mut aggregates = Aggregates::new(now());
        for n in 0..500_u64 {
            aggregates.observe_object(&ObjectMeta {
                key: format!("key-{n}"),
                size: n,
                last_modified: now(),
                etag: format!("etag-{n}"),
                storage_class: StorageClass::Standard,
            });
        }

        let bound = aggregates.duplicate_lower_bound();
        assert!(bound >= 0.0, "must never be negative: {bound}");
        assert!(
            bound < 50.0,
            "distinct content should show ~no duplicates: {bound}"
        );
    }

    #[test]
    fn duplicate_lower_bound_is_zero_when_the_estimate_exceeds_the_count() {
        // A handful of objects all sharing one etag+size: the true distinct
        // count is 1, but the HLL could in principle round up slightly;
        // either way the bound must never go negative.
        let mut aggregates = Aggregates::new(now());
        for n in 0..3_u64 {
            aggregates.observe_object(&ObjectMeta {
                key: format!("key-{n}"),
                size: 1,
                last_modified: now(),
                etag: "same-etag".to_owned(),
                storage_class: StorageClass::Standard,
            });
        }

        assert!(aggregates.duplicate_lower_bound() >= 0.0);
    }

    #[test]
    fn the_distinct_estimate_never_exceeds_the_object_count() {
        // Small counts are where the raw estimate overshoots most visibly.
        for count in 1..=40_u64 {
            let mut aggregates = Aggregates::new(now());
            for n in 0..count {
                aggregates.observe_object(&ObjectMeta {
                    key: format!("key-{n}"),
                    size: n,
                    last_modified: now(),
                    etag: format!("etag-{n}"),
                    storage_class: StorageClass::Standard,
                });
            }
            assert!(
                aggregates.distinct_content_estimate() <= super::u64_to_f64(count),
                "{count} objects estimated as {}",
                aggregates.distinct_content_estimate()
            );
        }
    }

    #[test]
    fn duplicates_are_significant_only_at_two_percent_or_more() {
        let observe = |distinct: u64, copies: u64| {
            let mut aggregates = Aggregates::new(now());
            for n in 0..distinct {
                for copy in 0..copies {
                    aggregates.observe_object(&ObjectMeta {
                        key: format!("key-{n}-{copy}"),
                        size: 100,
                        last_modified: now(),
                        etag: format!("etag-{n}"),
                        storage_class: StorageClass::Standard,
                    });
                }
            }
            aggregates
        };

        // Every object distinct: nothing to report.
        assert!(!observe(1000, 1).duplicates_significant());
        // Every object stored twice: half the objects are duplicates.
        assert!(observe(500, 2).duplicates_significant());
        // No objects at all.
        assert!(!Aggregates::new(now()).duplicates_significant());
    }

    #[test]
    fn suppressed_findings_are_counted_per_rule_and_nowhere_else() {
        let ctx = EvalContext { now: now() };
        let mut aggregates = Aggregates::new(now());
        let object = ObjectMeta {
            key: "id_rsa".to_owned(),
            size: 300,
            last_modified: now(),
            etag: "etag".to_owned(),
            storage_class: StorageClass::Standard,
        };
        aggregates.observe_object(&object);
        for finding in rules::evaluate(&object, &ctx) {
            aggregates.observe_suppressed(finding);
        }

        let suppressed = aggregates.suppressed(RuleId::SensitiveKey);
        assert_eq!((suppressed.count, suppressed.bytes), (1, 300));
        assert_eq!(aggregates.suppressed(RuleId::ZeroByteObject).count, 0);
        assert_eq!(
            aggregates
                .matrix_cell(RuleId::SensitiveKey, Severity::High)
                .count,
            0
        );
        assert_eq!(aggregates.worst_severity(), None);
        assert_eq!(aggregates.samples_for(RuleId::SensitiveKey).len(), 0);

        let mut merged = Aggregates::new(now());
        merged.merge(aggregates.clone());
        merged.merge(aggregates);
        assert_eq!(merged.suppressed(RuleId::SensitiveKey).count, 2);
    }

    /// `clippy::float_cmp` is denied crate-wide, so these compare bit
    /// patterns (`to_bits`) rather than the `f64` values with `==`
    /// directly; every case here is an exact conversion, so the bit
    /// patterns are expected to match exactly, not just approximately.
    #[test]
    fn u64_to_f64_is_exact_for_values_that_fit_in_u32_and_close_for_larger_ones() {
        assert_eq!(super::u64_to_f64(0).to_bits(), 0.0_f64.to_bits());
        assert_eq!(super::u64_to_f64(1).to_bits(), 1.0_f64.to_bits());
        assert_eq!(
            super::u64_to_f64(u64::from(u32::MAX)).to_bits(),
            f64::from(u32::MAX).to_bits()
        );

        // Beyond u32::MAX: reconstructed from high/low halves, exact at
        // this particular magnitude (a round number well within the
        // mantissa's 53 bits of precision).
        assert_eq!(
            super::u64_to_f64(1 << 40).to_bits(),
            2.0_f64.powi(40).to_bits()
        );
    }
}
