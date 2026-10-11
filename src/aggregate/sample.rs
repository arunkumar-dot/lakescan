//! [`Sample`]: the one record shape held by every bounded top-K in this
//! module (the per-rule finding samples and the largest-objects list).

use std::cmp::Ordering;
use std::time::SystemTime;

use super::stats::truncate_at_char_boundary;
use super::topk::Bounded;
use crate::model::{ObjectMeta, Severity, StorageClass};

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
}

impl Sample {
    /// Builds a `Sample` for a finding on `object`.
    pub(super) fn for_finding(object: &ObjectMeta, severity: Severity) -> Self {
        Self::build(object, Some(severity))
    }

    /// Builds a `Sample` for the largest-objects list (no finding).
    pub(super) fn for_object(object: &ObjectMeta) -> Self {
        Self::build(object, None)
    }

    fn build(object: &ObjectMeta, severity: Option<Severity>) -> Self {
        let (key, key_truncated) = truncate_at_char_boundary(&object.key, MAX_KEY_BYTES);
        Self {
            key,
            key_truncated,
            size: object.size,
            last_modified: object.last_modified,
            storage_class: compact_storage_class(&object.storage_class),
            severity,
        }
    }

    /// The total heap this one sample currently occupies: its key's
    /// allocation, plus its storage class's, if it owns one.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        self.key.capacity() + storage_class_heap_bytes(&self.storage_class)
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
    const MAX_BYTES: usize = size_of::<Self>() + MAX_KEY_BYTES + MAX_CLASS_NAME_BYTES;
}

/// Orders samples best-first: higher severity first, then larger size,
/// then lexicographically *smaller* key — the key comparison is reversed
/// so that, among ties, the deterministically "first" key is the one a
/// bounded top-K keeps, regardless of observation order.
impl Ord for Sample {
    fn cmp(&self, other: &Self) -> Ordering {
        self.severity
            .cmp(&other.severity)
            .then_with(|| self.size.cmp(&other.size))
            .then_with(|| other.key.cmp(&self.key))
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
    worst: &Sample,
) -> Ordering {
    candidate_severity
        .cmp(&worst.severity)
        .then_with(|| candidate_size.cmp(&worst.size))
        .then_with(|| worst.key.as_str().cmp(candidate_key))
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::{Sample, rank_against};
    use crate::aggregate::topk::Bounded;
    use crate::model::{ObjectMeta, Severity, StorageClass};

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
        let high_small =
            Sample::for_finding(&object("b", 10, StorageClass::Standard), Severity::High);
        let high_large =
            Sample::for_finding(&object("b", 20, StorageClass::Standard), Severity::High);
        let medium_large =
            Sample::for_finding(&object("b", 1000, StorageClass::Standard), Severity::Medium);
        let high_small_a =
            Sample::for_finding(&object("a", 10, StorageClass::Standard), Severity::High);

        assert!(high_large > high_small, "same severity, larger size wins");
        assert!(high_small > medium_large, "severity beats size");
        assert!(
            high_small_a > high_small,
            "same severity+size, smaller key wins"
        );
    }

    #[test]
    fn rank_against_agrees_with_sample_ord() {
        let worst =
            Sample::for_finding(&object("m", 100, StorageClass::Standard), Severity::Medium);

        for (severity, size, key) in [
            (Severity::High, 50_u64, "z"),
            (Severity::Medium, 200_u64, "z"),
            (Severity::Medium, 100_u64, "a"),
            (Severity::Medium, 100_u64, "z"),
            (Severity::Low, 100_u64, "a"),
        ] {
            let candidate =
                Sample::for_finding(&object(key, size, StorageClass::Standard), severity);
            assert_eq!(
                rank_against(Some(severity), size, key, &worst),
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

        let sample = Sample::for_finding(&obj, Severity::Critical);

        assert!(
            size_of::<Sample>() + sample.heap_bytes() <= Sample::MAX_BYTES,
            "size_of (={}) + heap_bytes (={}) exceeds MAX_BYTES (={})",
            size_of::<Sample>(),
            sample.heap_bytes(),
            Sample::MAX_BYTES
        );
    }
}
