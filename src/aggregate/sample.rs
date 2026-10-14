//! [`Sample`]: the one record shape held by every bounded top-K in this
//! module (the per-rule finding samples and the largest-objects list).

use std::cmp::Ordering;
use std::time::SystemTime;

use super::stats::truncate_at_char_boundary;
use super::topk::Bounded;
use crate::model::{
    ColumnDetail, Detail, MAX_COLUMN_BYTES, NotScannedReason, ObjectMeta, Severity, StorageClass,
};

/// A key longer than this is truncated when copied into a [`Sample`]. S3
/// keys can be up to 1024 bytes, so this is the real worst case, not an
/// arbitrary round number.
const MAX_KEY_BYTES: usize = 1024;

/// An unrecognized storage-class wire value longer than this is truncated
/// when copied into a [`Sample`]. Unlike keys, these are AWS-assigned
/// identifiers with no adversarial length in practice, but a `Sample` must
/// still declare a hard bound to keep [`Sample::MAX_BYTES`] honest.
const MAX_CLASS_NAME_BYTES: usize = 64;

/// One retained object or finding, owned rather than borrowed so it can
/// outlive the scanner page it was read from.
///
/// Shared by both bounded top-K lists in this crate: the per-rule finding
/// samples set `severity`; the largest-objects list leaves it `None`. Every
/// field is a bounded copy — no field can grow this struct's heap use past
/// [`Sample::MAX_BYTES`], which is asserted in `aggregate`'s memory-bound
/// tests under adversarial input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    /// The object's key, truncated to [`MAX_KEY_BYTES`] bytes at a `char`
    /// boundary if it was longer.
    pub key: String,
    /// Whether `key` is a truncated copy of the real key.
    pub key_truncated: bool,
    /// The object's size in bytes.
    pub size: u64,
    /// When the object was last modified.
    pub last_modified: SystemTime,
    /// The object's storage class. If this is [`StorageClass::Other`], the
    /// wire name is truncated to [`MAX_CLASS_NAME_BYTES`] bytes.
    pub storage_class: StorageClass,
    /// The finding's severity, for a per-rule sample; `None` for an entry
    /// in the largest-objects list, which has no associated finding.
    pub severity: Option<Severity>,
    /// What the finding said beyond its object: a PII finding's column
    /// (at most [`MAX_COLUMN_BYTES`]), confidence and counts, or why a
    /// file was not scanned.
    pub detail: SampleDetail,
}

/// An owned copy of a finding's [`Detail`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SampleDetail {
    /// A listing finding, or a largest-objects entry.
    None,
    /// A PII finding's column, confidence and counts.
    Column(ColumnDetail),
    /// Why a file could not be content-scanned.
    NotScanned(NotScannedReason),
}

impl SampleDetail {
    fn of(detail: Detail<'_>) -> Self {
        match detail {
            Detail::None => Self::None,
            Detail::Column(column) => Self::Column(column.clone()),
            Detail::NotScanned(reason) => Self::NotScanned(reason),
        }
    }

    /// The column path, or `""` when there is none: the last tie-breaker
    /// when ranking samples.
    fn column(&self) -> &str {
        match self {
            Self::Column(column) => &column.column,
            Self::None | Self::NotScanned(_) => "",
        }
    }
}

impl Sample {
    /// Builds a `Sample` for a finding on `object`.
    pub(super) fn for_finding(object: &ObjectMeta, severity: Severity, detail: Detail<'_>) -> Self {
        Self::build(object, Some(severity), SampleDetail::of(detail))
    }

    /// Builds a `Sample` for the largest-objects list (no finding).
    pub(super) fn for_object(object: &ObjectMeta) -> Self {
        Self::build(object, None, SampleDetail::None)
    }

    fn build(object: &ObjectMeta, severity: Option<Severity>, detail: SampleDetail) -> Self {
        let (key, key_truncated) = truncate_at_char_boundary(&object.key, MAX_KEY_BYTES);
        Self {
            key,
            key_truncated,
            size: object.size,
            last_modified: object.last_modified,
            storage_class: compact_storage_class(&object.storage_class),
            severity,
            detail,
        }
    }

    /// The total heap this one sample currently occupies: its key's
    /// allocation, its storage class's, if it owns one, and its column
    /// path's, if it has one.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        let column = match &self.detail {
            SampleDetail::Column(detail) => detail.column.capacity(),
            SampleDetail::None | SampleDetail::NotScanned(_) => 0,
        };
        self.key.capacity() + storage_class_heap_bytes(&self.storage_class) + column
    }
}

/// Copies `class`, truncating an [`StorageClass::Other`] wire name to
/// [`MAX_CLASS_NAME_BYTES`]. Known variants carry no heap payload, so
/// cloning them is free.
fn compact_storage_class(class: &StorageClass) -> StorageClass {
    match class {
        StorageClass::Other(name) => {
            StorageClass::Other(truncate_at_char_boundary(name, MAX_CLASS_NAME_BYTES).0)
        }
        known => known.clone(),
    }
}

fn storage_class_heap_bytes(class: &StorageClass) -> usize {
    match class {
        StorageClass::Other(name) => name.capacity(),
        _ => 0,
    }
}

impl Bounded for Sample {
    const MAX_BYTES: usize =
        size_of::<Self>() + MAX_KEY_BYTES + MAX_CLASS_NAME_BYTES + MAX_COLUMN_BYTES;
}

/// Orders samples best-first: higher severity first, then larger size,
/// then lexicographically *smaller* key, then smaller column path — the
/// key and column comparisons are reversed so that, among ties, the
/// deterministically "first" one is what a bounded top-K keeps, regardless
/// of observation order. The column breaks ties between several PII
/// findings on one file.
impl Ord for Sample {
    fn cmp(&self, other: &Self) -> Ordering {
        self.severity
            .cmp(&other.severity)
            .then_with(|| self.size.cmp(&other.size))
            .then_with(|| other.key.cmp(&self.key))
            .then_with(|| other.detail.column().cmp(self.detail.column()))
    }
}

impl PartialOrd for Sample {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Ranks a *candidate* finding or object against an already-kept [`Sample`]
/// (`worst`), without building a `Sample` for the candidate. Mirrors
/// [`Sample`]'s own [`Ord`] impl exactly; see the module-level comparison
/// tests that check the two never disagree.
pub(super) fn rank_against(
    candidate_severity: Option<Severity>,
    candidate_size: u64,
    candidate_key: &str,
    candidate_column: &str,
    worst: &Sample,
) -> Ordering {
    candidate_severity
        .cmp(&worst.severity)
        .then_with(|| candidate_size.cmp(&worst.size))
        .then_with(|| worst.key.as_str().cmp(candidate_key))
        .then_with(|| worst.detail.column().cmp(candidate_column))
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::{Sample, SampleDetail, rank_against};
    use crate::aggregate::topk::Bounded;
    use crate::model::{
        ColumnDetail, Confidence, Detail, Evidence, ObjectMeta, Severity, StorageClass,
    };

    fn finding_sample(object: &ObjectMeta, severity: Severity) -> Sample {
        Sample::for_finding(object, severity, Detail::None)
    }

    fn object(key: &str, size: u64, storage_class: StorageClass) -> ObjectMeta {
        ObjectMeta {
            key: key.to_owned(),
            size,
            last_modified: SystemTime::UNIX_EPOCH,
            etag: "etag".to_owned(),
            storage_class,
        }
    }

    #[test]
    fn long_keys_are_truncated_at_a_char_boundary_with_the_flag_set() {
        // 1025 non-ASCII, 2-byte characters: truncation must land on a
        // 2-byte boundary, never splitting the last character.
        let long_key: String = "é".repeat(600);
        let obj = object(&long_key, 10, StorageClass::Standard);
        let sample = Sample::for_object(&obj);

        assert!(sample.key_truncated);
        assert!(sample.key.len() <= super::MAX_KEY_BYTES);
        assert!(
            sample.key.len().is_multiple_of(2),
            "must not split a 2-byte char"
        );
    }

    #[test]
    fn short_keys_are_not_truncated() {
        let obj = object("short.txt", 10, StorageClass::Standard);
        let sample = Sample::for_object(&obj);
        assert!(!sample.key_truncated);
        assert_eq!(sample.key, "short.txt");
    }

    #[test]
    fn an_other_storage_class_name_is_truncated_in_the_sample() {
        let long_name = "X".repeat(200);
        let obj = object("k", 10, StorageClass::Other(long_name));
        let sample = Sample::for_object(&obj);
        let expected_name = "X".repeat(super::MAX_CLASS_NAME_BYTES);
        assert_eq!(sample.storage_class, StorageClass::Other(expected_name));
    }

    #[test]
    fn ordering_is_severity_then_size_then_key_ascending() {
        let high_small = finding_sample(&object("b", 10, StorageClass::Standard), Severity::High);
        let high_large = finding_sample(&object("b", 20, StorageClass::Standard), Severity::High);
        let medium_large =
            finding_sample(&object("b", 1000, StorageClass::Standard), Severity::Medium);
        let high_small_a = finding_sample(&object("a", 10, StorageClass::Standard), Severity::High);

        assert!(high_large > high_small, "same severity, larger size wins");
        assert!(high_small > medium_large, "severity beats size");
        assert!(
            high_small_a > high_small,
            "same severity+size, smaller key wins"
        );
    }

    #[test]
    fn rank_against_agrees_with_sample_ord() {
        let worst = finding_sample(&object("m", 100, StorageClass::Standard), Severity::Medium);

        for (severity, size, key) in [
            (Severity::High, 50_u64, "z"),
            (Severity::Medium, 200_u64, "z"),
            (Severity::Medium, 100_u64, "a"),
            (Severity::Medium, 100_u64, "z"),
            (Severity::Low, 100_u64, "a"),
        ] {
            let candidate = finding_sample(&object(key, size, StorageClass::Standard), severity);
            assert_eq!(
                rank_against(Some(severity), size, key, "", &worst),
                candidate.cmp(&worst),
                "mismatch for severity={severity:?} size={size} key={key}"
            );
        }
    }

    #[test]
    fn adversarial_sample_stays_within_max_bytes() {
        // Worst case on every bounded field at once: a key far longer than
        // the truncation limit, and an `Other` storage class name far
        // longer than its own truncation limit.
        let huge_key = "k".repeat(10_000);
        let huge_class_name = "c".repeat(10_000);
        let obj = object(&huge_key, u64::MAX, StorageClass::Other(huge_class_name));

        let detail = ColumnDetail::new(
            &"c".repeat(10_000),
            Confidence::Confirmed,
            Evidence::ColumnName,
        );
        let sample = Sample::for_finding(&obj, Severity::Critical, Detail::Column(&detail));
        assert!(matches!(&sample.detail, SampleDetail::Column(d) if d.column.len() <= 256));

        assert!(
            size_of::<Sample>() + sample.heap_bytes() <= Sample::MAX_BYTES,
            "size_of (={}) + heap_bytes (={}) exceeds MAX_BYTES (={})",
            size_of::<Sample>(),
            sample.heap_bytes(),
            Sample::MAX_BYTES
        );
    }
}
