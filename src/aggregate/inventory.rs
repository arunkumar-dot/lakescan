//! [`Inventory`]: object count and bytes, overall and per storage class.

use std::cmp::Ordering;

use super::stats::{CountBytes, truncate_at_char_boundary};
use crate::model::{ObjectMeta, StorageClass};

/// The number of storage classes [`StorageClass::known_index`] assigns a
/// slot to. Sized from [`StorageClass::KNOWN`] — the single source of
/// truth for "every known class" — not restated as its own number.
const KNOWN_CLASSES: usize = StorageClass::KNOWN.len();

/// At most this many distinct unrecognized storage-class names are tracked
/// individually: the lexicographically smallest, independent of the order
/// objects were observed in or how the stream was split before merging.
const MAX_OTHER_CLASSES: usize = 8;

/// An unrecognized class name longer than this is truncated when tracked.
const MAX_CLASS_NAME_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct OtherClassSlot {
    name: String,
    stats: CountBytes,
}

/// Up to [`MAX_OTHER_CLASSES`] distinct unrecognized storage-class names,
/// always kept sorted by name so that two instances holding the same set of
/// names compare equal regardless of the order they were built in.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct OtherClasses {
    slots: [Option<OtherClassSlot>; MAX_OTHER_CLASSES],
}

impl OtherClasses {
    fn observe(&mut self, name: &str, size: u64) {
        let (name, _truncated) = truncate_at_char_boundary(name, MAX_CLASS_NAME_BYTES);
        let mut stats = CountBytes::default();
        stats.observe(size);
        self.merge_one(name, stats);
    }

    /// Merges one `(name, stats)` pair in, whether from a single
    /// observation or from another `OtherClasses` being merged in.
    fn merge_one(&mut self, name: String, stats: CountBytes) {
        for slot in self.slots.iter_mut().flatten() {
            if slot.name == name {
                slot.stats.merge(stats);
                self.resort();
                return;
            }
        }

        if let Some(empty) = self.slots.iter_mut().find(|slot| slot.is_none()) {
            *empty = Some(OtherClassSlot { name, stats });
            self.resort();
            return;
        }

        // Full, and `name` is not already tracked: keep it only if it is
        // smaller than the currently-largest-tracked name, which it then
        // displaces. Losing an evicted name's accumulated stats is correct
        // here: `Inventory::overall` already counted every object
        // regardless, and nothing can be a top-8-smallest name both before
        // and after being evicted for a smaller one.
        let largest = self
            .slots
            .iter_mut()
            .flatten()
            .max_by(|a, b| a.name.cmp(&b.name));
        if let Some(largest) = largest
            && name < largest.name
        {
            *largest = OtherClassSlot { name, stats };
            self.resort();
        }
    }

    fn merge(&mut self, other: Self) {
        for slot in other.slots.into_iter().flatten() {
            self.merge_one(slot.name, slot.stats);
        }
    }

    /// Restores the "occupied slots sorted by name, empty slots last"
    /// invariant after a mutation.
    fn resort(&mut self) {
        self.slots.sort_by(|a, b| match (a, b) {
            (Some(x), Some(y)) => x.name.cmp(&y.name),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        });
    }

    fn heap_bytes(&self) -> usize {
        self.slots
            .iter()
            .flatten()
            .map(|slot| slot.name.capacity())
            .sum()
    }
}

/// Object count and total bytes, overall and broken down by storage class.
///
/// One fixed slot per class [`StorageClass::known_index`] recognizes, plus
/// up to [`MAX_OTHER_CLASSES`] distinct unrecognized class names tracked by
/// name (see [`OtherClasses`]). No per-object allocation: the only heap
/// this type ever owns is the (bounded, truncated) unrecognized class
/// names.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct Inventory {
    /// Count and bytes across every object, regardless of storage class.
    pub overall: CountBytes,
    known: [CountBytes; KNOWN_CLASSES],
    other: OtherClasses,
}

impl Inventory {
    /// This inventory's worst-case total size: its fixed fields, plus up to
    /// [`MAX_OTHER_CLASSES`] truncated class names.
    pub(super) const MAX_BYTES: usize =
        size_of::<Self>() + MAX_OTHER_CLASSES * MAX_CLASS_NAME_BYTES;

    /// Records one object into the overall total and its storage class's
    /// slot.
    pub(super) fn observe(&mut self, object: &ObjectMeta) {
        self.overall.observe(object.size);
        match object.storage_class.known_index() {
            Some(index) => {
                if let Some(slot) = self.known.get_mut(index) {
                    slot.observe(object.size);
                }
            }
            None => {
                if let StorageClass::Other(name) = &object.storage_class {
                    self.other.observe(name, object.size);
                }
            }
        }
    }

    /// Folds `other`'s totals into `self`.
    pub(super) fn merge(&mut self, other: Self) {
        self.overall.merge(other.overall);
        for (slot, other_slot) in self.known.iter_mut().zip(other.known) {
            slot.merge(other_slot);
        }
        self.other.merge(other.other);
    }

    /// The count and bytes for one known storage class, or `None` if
    /// `class` is [`StorageClass::Other`] (use [`Inventory::other_classes`]
    /// instead).
    #[must_use]
    pub(super) fn known_class(&self, class: &StorageClass) -> Option<CountBytes> {
        class
            .known_index()
            .and_then(|index| self.known.get(index).copied())
    }

    /// The tracked unrecognized storage-class names and their stats, in
    /// lexicographically ascending order (best-first in the sense that the
    /// smallest-named entries are the ones this inventory guarantees it
    /// kept).
    pub(super) fn other_classes(&self) -> impl Iterator<Item = (&str, CountBytes)> {
        self.other
            .slots
            .iter()
            .flatten()
            .map(|slot| (slot.name.as_str(), slot.stats))
    }

    /// The combined count and bytes of *every* unrecognized object,
    /// regardless of how many distinct unrecognized class names there
    /// are: computed as `overall` minus the sum of every known class's
    /// slot, not by summing [`Inventory::other_classes`] (which only
    /// tracks the 8 lexicographically smallest names and would undercount
    /// once a 9th distinct name has ever displaced one).
    #[must_use]
    pub(super) fn unrecognized_totals(&self) -> CountBytes {
        let mut known = CountBytes::default();
        for slot in self.known {
            known.merge(slot);
        }
        CountBytes {
            count: self.overall.count.saturating_sub(known.count),
            bytes: self.overall.bytes.saturating_sub(known.bytes),
        }
    }

    /// The heap this inventory currently occupies: just the unrecognized
    /// class names, if any.
    #[must_use]
    pub(super) fn heap_bytes(&self) -> usize {
        self.other.heap_bytes()
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::{Inventory, MAX_CLASS_NAME_BYTES, MAX_OTHER_CLASSES};
    use crate::aggregate::stats::CountBytes;
    use crate::model::{ObjectMeta, StorageClass};

    fn object(size: u64, storage_class: StorageClass) -> ObjectMeta {
        ObjectMeta {
            key: "k".to_owned(),
            size,
            last_modified: SystemTime::UNIX_EPOCH,
            etag: "etag".to_owned(),
            storage_class,
        }
    }

    #[test]
    fn overall_and_known_class_totals_accumulate() {
        let mut inv = Inventory::default();
        inv.observe(&object(10, StorageClass::Standard));
        inv.observe(&object(20, StorageClass::Standard));
        inv.observe(&object(5, StorageClass::Glacier));

        assert_eq!(inv.overall.count, 3);
        assert_eq!(inv.overall.bytes, 35);
        assert_eq!(
            inv.known_class(&StorageClass::Standard),
            Some(CountBytes {
                count: 2,
                bytes: 30
            })
        );
        assert_eq!(
            inv.known_class(&StorageClass::Glacier),
            Some(CountBytes { count: 1, bytes: 5 })
        );
        assert_eq!(
            inv.known_class(&StorageClass::OnezoneIa),
            Some(CountBytes::default())
        );
    }

    #[test]
    fn known_class_returns_none_for_other() {
        assert_eq!(
            Inventory::default().known_class(&StorageClass::Other("X".to_owned())),
            None
        );
    }

    #[test]
    fn repeated_other_class_names_accumulate_in_one_slot() {
        let mut inv = Inventory::default();
        inv.observe(&object(10, StorageClass::Other("NEW_TIER".to_owned())));
        inv.observe(&object(20, StorageClass::Other("NEW_TIER".to_owned())));

        let classes: Vec<_> = inv.other_classes().collect();
        assert_eq!(
            classes,
            vec![(
                "NEW_TIER",
                CountBytes {
                    count: 2,
                    bytes: 30
                }
            )]
        );
    }

    #[test]
    fn keeps_only_the_lexicographically_smallest_other_class_names() {
        let mut inv = Inventory::default();
        // 10 distinct names, more than MAX_OTHER_CLASSES; "j0".."j9" sort
        // in exactly numeric order as strings since they share a prefix
        // and a single trailing digit.
        for n in 0..10 {
            inv.observe(&object(1, StorageClass::Other(format!("j{n}"))));
        }

        let names: Vec<&str> = inv.other_classes().map(|(name, _)| name).collect();
        assert_eq!(names.len(), MAX_OTHER_CLASSES);
        assert_eq!(names, ["j0", "j1", "j2", "j3", "j4", "j5", "j6", "j7"]);
    }

    #[test]
    fn other_class_selection_is_order_independent() {
        let names = ["m", "a", "z", "b", "y", "c", "x", "d", "w", "e"];

        let mut forward = Inventory::default();
        for name in names {
            forward.observe(&object(1, StorageClass::Other(name.to_owned())));
        }

        let mut backward = Inventory::default();
        for name in names.iter().rev() {
            backward.observe(&object(1, StorageClass::Other((*name).to_owned())));
        }

        let forward_names: Vec<&str> = forward.other_classes().map(|(name, _)| name).collect();
        let backward_names: Vec<&str> = backward.other_classes().map(|(name, _)| name).collect();
        assert_eq!(forward_names, backward_names);
    }

    #[test]
    fn long_other_class_names_are_truncated_at_a_char_boundary() {
        let mut inv = Inventory::default();
        let long_name = "x".repeat(200);
        inv.observe(&object(1, StorageClass::Other(long_name)));

        let (name, _) = inv
            .other_classes()
            .next()
            .unwrap_or(("", CountBytes::default()));
        assert!(name.len() <= MAX_CLASS_NAME_BYTES);
    }

    #[test]
    fn merging_two_inventories_matches_observing_everything_in_one() {
        let objects = [
            object(10, StorageClass::Standard),
            object(20, StorageClass::Glacier),
            object(30, StorageClass::Other("A".to_owned())),
            object(40, StorageClass::Other("B".to_owned())),
            object(50, StorageClass::StandardIa),
        ];

        let mut whole = Inventory::default();
        for object in &objects {
            whole.observe(object);
        }

        let (first, second) = objects.split_at(2);
        let mut a = Inventory::default();
        for object in first {
            a.observe(object);
        }
        let mut b = Inventory::default();
        for object in second {
            b.observe(object);
        }
        a.merge(b);

        assert_eq!(whole, a);
    }

    #[test]
    fn adversarial_many_long_other_class_names_stays_within_max_bytes() {
        let mut inv = Inventory::default();
        // Far more than MAX_OTHER_CLASSES distinct names, each far longer
        // than MAX_CLASS_NAME_BYTES.
        for n in 0..1000 {
            let name = format!("{n:0>10000}"); // 10000-byte distinct names
            inv.observe(&object(1, StorageClass::Other(name)));
        }

        assert!(
            size_of::<Inventory>() + inv.heap_bytes() <= Inventory::MAX_BYTES,
            "size_of (={}) + heap_bytes (={}) exceeds MAX_BYTES (={})",
            size_of::<Inventory>(),
            inv.heap_bytes(),
            Inventory::MAX_BYTES
        );
    }

    #[test]
    fn unrecognized_totals_is_zero_when_there_are_none() {
        let mut inv = Inventory::default();
        inv.observe(&object(10, StorageClass::Standard));
        assert_eq!(inv.unrecognized_totals(), CountBytes::default());
    }

    #[test]
    fn unrecognized_totals_sums_a_single_class() {
        let mut inv = Inventory::default();
        inv.observe(&object(10, StorageClass::Standard));
        inv.observe(&object(30, StorageClass::Other("A".to_owned())));
        inv.observe(&object(40, StorageClass::Other("A".to_owned())));

        assert_eq!(
            inv.unrecognized_totals(),
            CountBytes {
                count: 2,
                bytes: 70
            }
        );
    }

    #[test]
    fn unrecognized_totals_stays_exact_past_the_eight_tracked_names() {
        // Nine distinct unrecognized names, one past MAX_OTHER_CLASSES: the
        // ninth (lexicographically largest) is evicted from the per-name
        // tracker, but the *total* must still count every one of them.
        let mut inv = Inventory::default();
        for n in 0..9 {
            inv.observe(&object(1, StorageClass::Other(format!("class-{n}"))));
        }

        assert_eq!(inv.other_classes().count(), MAX_OTHER_CLASSES);
        assert_eq!(inv.unrecognized_totals(), CountBytes { count: 9, bytes: 9 });
    }
}
