//! Folds the finding stream into bounded summaries.
//!
//! Single responsibility: answer whole-bucket questions — totals, top-k,
//! distributions, cardinalities — without ever holding the bucket in memory.
//!
//! **Memory budget: 18 MB.** Bounded sketches only. Every aggregator declares
//! a `const` upper bound on its own footprint, and no aggregator may use a
//! structure whose size grows with the number of objects or findings scanned.
//! This is the only module in the pipeline permitted to retain state across
//! objects, which is exactly why its bound is explicit and checked.
//!
//! [`Aggregates::MAX_BYTES`] is a compile-time-checked sum of every summary's
//! own `MAX_BYTES`: **112,728 bytes (~110 KiB)** as of this milestone,
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

use std::time::SystemTime;

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
    size_histogram: SizeHistogram,
    age_histogram: AgeHistogram,
    hll: Hll,
}

impl Aggregates {
    /// The combined worst-case size of every summary this struct holds:
    /// the plain sum of each summary type's own `MAX_BYTES`. 112,728 bytes
    /// as of this milestone (see this module's doc); checked below to be
    /// within the 18 MiB module budget.
    pub const MAX_BYTES: usize = Inventory::MAX_BYTES
        + FindingsMatrix::MAX_BYTES
        + NUM_RULES * TopK::<Sample, SAMPLES_PER_RULE>::MAX_BYTES
        + TopK::<Sample, LARGEST_OBJECTS>::MAX_BYTES
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

    /// Folds `other` into `self`. Order-independent: see this module's doc.
    pub fn merge(&mut self, other: Self) {
        self.inventory.merge(other.inventory);
        self.matrix.merge(&other.matrix);
        for (slot, other_slot) in self.samples.iter_mut().zip(other.samples) {
            slot.merge(other_slot);
        }
        self.largest.merge(other.largest);
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

    /// The count and bytes of findings for this exact `(rule, severity)`.
    #[must_use]
    pub fn matrix_cell(&self, rule: RuleId, severity: Severity) -> CountBytes {
        self.matrix.cell(rule, severity)
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

    /// The estimated number of distinct object contents observed. See
    /// `aggregate::hyperloglog` for the `ETag` caveat that makes this a lower
    /// bound on duplicates, not an exact count.
    #[must_use]
    pub fn distinct_content_estimate(&self) -> f64 {
        self.hll.estimate()
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
}
