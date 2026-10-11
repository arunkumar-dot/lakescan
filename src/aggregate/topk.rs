//! [`TopK`]: the one bounded top-K structure shared by every "best N"
//! summary in `aggregate` (the per-rule finding samples, and the
//! largest-objects list).

use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;

/// A type whose worst-case total size (its own `size_of` plus every byte of
/// heap it could ever own) is known at compile time.
///
/// Lets [`TopK::MAX_BYTES`] be computed generically, from `K` and `T`
/// alone, instead of every top-K instantiation restating the arithmetic.
pub(super) trait Bounded {
    /// `size_of::<Self>()` plus this value's maximum possible heap use.
    const MAX_BYTES: usize;
}

/// The best `K` items seen so far, by `T`'s own [`Ord`], kept in a
/// min-on-top binary heap so the current *worst* kept item — the one a new
/// candidate must beat — is always a cheap `O(1)` peek away.
///
/// Never holds more than `K` entries, even transiently: [`TopK::offer`]
/// compares a candidate against the current worst entry *before* building
/// anything, and only builds (and therefore only allocates) when the
/// candidate has actually earned a slot.
#[derive(Debug, Clone)]
pub(super) struct TopK<T, const K: usize> {
    /// `Reverse` so this max-heap's peek gives the *smallest* `T`, i.e.
    /// the worst of the kept entries.
    heap: BinaryHeap<Reverse<T>>,
}

impl<T, const K: usize> Default for TopK<T, K> {
    fn default() -> Self {
        // Reserved exactly once, up front, to `K`: since no path in this
        // type ever holds more than `K` elements, the heap's backing `Vec`
        // never needs to grow past this, and so never overshoots it the
        // way repeated doubling from an empty `BinaryHeap::new()` could.
        // `TopK::MAX_BYTES` depends on that: it bounds the backing array
        // at exactly `K * size_of::<T>()`, not on an unspecified amount of
        // allocator headroom.
        Self {
            heap: BinaryHeap::with_capacity(K),
        }
    }
}

impl<T: Ord, const K: usize> TopK<T, K> {
    /// Offers a candidate without building it unless it will be kept.
    ///
    /// `compare_to_worst` ranks the *candidate* against an already-kept
    /// entry (`Ordering::Greater` means the candidate outranks it) using
    /// only cheap, already-borrowed data — no allocation. `build` is called
    /// at most once, and only when the candidate has earned a slot: either
    /// there is room, or it outranks the current worst kept entry.
    pub(super) fn offer(
        &mut self,
        compare_to_worst: impl FnOnce(&T) -> Ordering,
        build: impl FnOnce() -> T,
    ) {
        if K == 0 {
            return;
        }

        if self.heap.len() < K {
            self.heap.push(Reverse(build()));
            return;
        }

        let should_replace = match self.heap.peek() {
            Some(Reverse(worst)) => compare_to_worst(worst) == Ordering::Greater,
            None => false,
        };
        if should_replace {
            self.heap.pop();
            self.heap.push(Reverse(build()));
        }
    }

    /// Offers an already-built value. Used for merging two sketches, where
    /// the value exists either way and there is nothing to gain by delaying
    /// its construction.
    fn offer_built(&mut self, item: T) {
        if K == 0 {
            return;
        }

        if self.heap.len() < K {
            self.heap.push(Reverse(item));
            return;
        }

        let should_replace = self.heap.peek().is_some_and(|Reverse(worst)| item > *worst);
        if should_replace {
            self.heap.pop();
            self.heap.push(Reverse(item));
        }
    }

    /// Folds `other`'s entries into `self`. Order-independent: the result
    /// depends only on the union of entries ever offered to either side,
    /// never on how that union was split or in what order it arrived — the
    /// standard exchange-argument property of bounded top-K selection.
    pub(super) fn merge(&mut self, other: Self) {
        for Reverse(item) in other.heap {
            self.offer_built(item);
        }
    }

    /// The kept entries, best-first (descending by `T`'s own [`Ord`]).
    #[must_use]
    pub(super) fn sorted(&self) -> Vec<&T> {
        let mut items: Vec<&T> = self.heap.iter().map(|Reverse(item)| item).collect();
        items.sort_by(|a, b| b.cmp(a));
        items
    }
}

impl<T: Ord, const K: usize> PartialEq for TopK<T, K> {
    /// `BinaryHeap` has no `PartialEq` of its own — its internal layout for
    /// an equivalent set of entries is not canonical — so equality here is
    /// defined on sorted contents instead.
    fn eq(&self, other: &Self) -> bool {
        self.sorted() == other.sorted()
    }
}

impl<T: Bounded, const K: usize> TopK<T, K> {
    /// This top-K's worst-case total size: its own (tiny, heap-less)
    /// bookkeeping, plus `K` entries each at their own worst case — the
    /// backing storage for up to `K` live [`T`] values, each potentially
    /// at [`Bounded::MAX_BYTES`].
    pub(super) const MAX_BYTES: usize = size_of::<Self>() + K * T::MAX_BYTES;
}

impl<const K: usize> TopK<crate::aggregate::sample::Sample, K> {
    /// The heap this top-K currently occupies: the backing array for its
    /// kept entries, plus each entry's own heap use (its key, and its
    /// storage class's, if any).
    #[must_use]
    pub(super) fn heap_bytes(&self) -> usize {
        let backing_array = self.heap.capacity() * size_of::<crate::aggregate::sample::Sample>();
        let per_entry: usize = self
            .heap
            .iter()
            .map(|Reverse(sample)| sample.heap_bytes())
            .sum();
        backing_array + per_entry
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use super::TopK;

    #[test]
    fn keeps_only_the_k_largest_values() {
        let mut top: TopK<u32, 3> = TopK::default();
        for value in [5_u32, 1, 9, 3, 7, 2, 8] {
            top.offer(|worst| value.cmp(worst), || value);
        }
        assert_eq!(top.sorted(), vec![&9, &8, &7]);
    }

    #[test]
    fn offer_never_exceeds_k_even_transiently() {
        let mut top: TopK<u32, 2> = TopK::default();
        for value in 0_u32..100 {
            top.offer(|worst| value.cmp(worst), || value);
            assert!(top.sorted().len() <= 2);
        }
    }

    #[test]
    fn a_losing_candidate_never_calls_build() {
        let mut top: TopK<u32, 1> = TopK::default();
        top.offer(|worst| 10_u32.cmp(worst), || 10);

        let mut build_called = false;
        top.offer(
            |worst| 1_u32.cmp(worst),
            || {
                build_called = true;
                1
            },
        );
        assert!(!build_called, "a losing candidate must not be built");
        assert_eq!(top.sorted(), vec![&10]);
    }

    #[test]
    fn zero_capacity_top_k_never_keeps_anything() {
        let mut top: TopK<u32, 0> = TopK::default();
        top.offer(|_| Ordering::Less, || 1);
        assert_eq!(top.sorted(), Vec::<&u32>::new());
    }

    #[test]
    fn merging_two_top_ks_is_order_independent() {
        let values = [5_u32, 1, 9, 3, 7, 2, 8, 6, 4];

        let mut whole: TopK<u32, 3> = TopK::default();
        for &value in &values {
            whole.offer(|worst| value.cmp(worst), || value);
        }

        let (first_half, second_half) = values.split_at(4);

        let mut left: TopK<u32, 3> = TopK::default();
        for &value in first_half {
            left.offer(|worst| value.cmp(worst), || value);
        }
        let mut right: TopK<u32, 3> = TopK::default();
        for &value in second_half {
            right.offer(|worst| value.cmp(worst), || value);
        }
        left.merge(right);

        assert_eq!(whole, left);
    }

    #[test]
    fn equality_does_not_depend_on_internal_heap_order() {
        let mut a: TopK<u32, 3> = TopK::default();
        for value in [1_u32, 2, 3] {
            a.offer(|worst| value.cmp(worst), || value);
        }
        let mut b: TopK<u32, 3> = TopK::default();
        for value in [3_u32, 2, 1] {
            b.offer(|worst| value.cmp(worst), || value);
        }
        assert_eq!(a, b);
    }

    #[test]
    fn adversarial_samples_keep_top_k_within_max_bytes() {
        use std::time::SystemTime;

        use crate::aggregate::sample::{Sample, rank_against};
        use crate::model::{ObjectMeta, Severity, StorageClass};

        const K: usize = 10;
        let mut top: TopK<Sample, K> = TopK::default();

        for n in 0..(K * 5) {
            // Every candidate is worst-case on every bounded field: a huge
            // key, a huge `Other` storage class name, and `Critical`
            // severity (so no candidate is rejected on severity alone).
            let object = ObjectMeta {
                key: format!("{n:0>2000}"),
                size: u64::MAX,
                last_modified: SystemTime::UNIX_EPOCH,
                etag: "etag".to_owned(),
                storage_class: StorageClass::Other("c".repeat(2000)),
            };
            top.offer(
                |worst| rank_against(Some(Severity::Critical), object.size, &object.key, worst),
                || Sample::for_finding(&object, Severity::Critical),
            );
        }

        assert!(
            size_of::<TopK<Sample, K>>() + top.heap_bytes() <= TopK::<Sample, K>::MAX_BYTES,
            "size_of (={}) + heap_bytes (={}) exceeds MAX_BYTES (={})",
            size_of::<TopK<Sample, K>>(),
            top.heap_bytes(),
            TopK::<Sample, K>::MAX_BYTES
        );
    }
}
