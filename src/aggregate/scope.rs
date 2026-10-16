//! [`OutOfScope`]: with `--pii`, the listed objects content scanning did
//! not read, and why: their extension (by extension), a sniff that found
//! no Parquet magic, or nothing to read (zero bytes, a folder marker).
//!
//! **Bounded and order-independent.** Extensions on
//! [`crate::content::NOT_PARQUET`], and "no extension", are counted
//! exactly in a fixed array. Any other extension (only seen with
//! `--pii-sniff none`, or on hidden files) is attacker-controlled: it is cut
//! to [`MAX_EXTENSION_BYTES`] and only the [`MAX_OTHER_EXTENSIONS`]
//! lexicographically smallest are kept by name, like unrecognized storage
//! classes; the total over all of them stays exact. The kept set is the
//! same in any order and after any merge, because a name once dropped is
//! larger than every name kept.

use crate::content::NOT_PARQUET;
use crate::model::truncate_str;

/// Extensions longer than this are cut (at a `char` boundary).
pub const MAX_EXTENSION_BYTES: usize = 16;

/// The most extensions off [`NOT_PARQUET`] kept by name.
const MAX_OTHER_EXTENSIONS: usize = 32;

/// The most extensions a report lists; the rest are summed.
pub const LISTED_EXTENSIONS: usize = 32;

/// One extension's count, for a report. `extension` is `""` for keys with
/// none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionCount<'a> {
    /// Lowercase, without the dot; at most [`MAX_EXTENSION_BYTES`].
    pub extension: &'a str,
    /// Objects with it.
    pub count: u64,
}

/// What `--pii` left unread; see this module's doc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutOfScope {
    /// Per [`NOT_PARQUET`] entry, by index.
    known: [u64; NOT_PARQUET.len()],
    /// Keys with no extension.
    no_extension: u64,
    /// The smallest other extensions, sorted by name, with their counts.
    other: Vec<(String, u64)>,
    /// Every object with an extension off the list, kept by name or not.
    other_total: u64,
    /// Sniffed, and not Parquet.
    sniffed_not_parquet: u64,
    /// Zero-byte objects and folder markers.
    empty: u64,
}

impl Default for OutOfScope {
    fn default() -> Self {
        Self {
            known: [0; NOT_PARQUET.len()],
            no_extension: 0,
            other: Vec::new(),
            other_total: 0,
            sniffed_not_parquet: 0,
            empty: 0,
        }
    }
}

impl OutOfScope {
    /// This summary's worst-case size: itself, and every kept extension
    /// name at full length, with the list's growth slack.
    pub(super) const MAX_BYTES: usize = size_of::<Self>()
        + 2 * MAX_OTHER_EXTENSIONS * (size_of::<(String, u64)>() + MAX_EXTENSION_BYTES);

    /// Records one object not read because of `extension` (`""`: none).
    pub(super) fn observe_extension(&mut self, extension: &str) {
        self.add_extension(extension, 1);
    }

    fn add_extension(&mut self, extension: &str, count: u64) {
        let add = |total: &mut u64| *total = total.saturating_add(count);
        if extension.is_empty() {
            return add(&mut self.no_extension);
        }
        if let Some(slot) = NOT_PARQUET
            .iter()
            .position(|known| *known == extension)
            .and_then(|index| self.known.get_mut(index))
        {
            return add(slot);
        }
        add(&mut self.other_total);
        let name = truncate_str(extension, MAX_EXTENSION_BYTES);
        match self
            .other
            .binary_search_by(|(held, _)| held.as_str().cmp(name))
        {
            Ok(index) => {
                if let Some((_, held)) = self.other.get_mut(index) {
                    add(held);
                }
            }
            Err(at) if at < MAX_OTHER_EXTENSIONS => {
                self.other.insert(at, (name.to_owned(), count));
                self.other.truncate(MAX_OTHER_EXTENSIONS);
            }
            Err(_) => {}
        }
    }

    /// Records one sniffed object that is not Parquet.
    pub(super) fn observe_sniffed_not_parquet(&mut self) {
        self.sniffed_not_parquet = self.sniffed_not_parquet.saturating_add(1);
    }

    /// Records one zero-byte object or folder marker.
    pub(super) fn observe_empty(&mut self) {
        self.empty = self.empty.saturating_add(1);
    }

    /// Folds `other` in. Order-independent: see this module's doc.
    pub(super) fn merge(&mut self, other: &Self) {
        let add = |total: &mut u64, n: u64| *total = total.saturating_add(n);
        for (mine, theirs) in self.known.iter_mut().zip(other.known) {
            add(mine, theirs);
        }
        add(&mut self.no_extension, other.no_extension);
        add(&mut self.sniffed_not_parquet, other.sniffed_not_parquet);
        add(&mut self.empty, other.empty);
        // Names kept by `other` re-enter through the same rule; its total
        // already counts the ones it dropped.
        let kept: u64 = other.other.iter().map(|(_, count)| count).sum();
        for (name, count) in &other.other {
            self.add_extension(name, *count);
        }
        self.other_total = self
            .other_total
            .saturating_add(other.other_total.saturating_sub(kept));
    }

    /// Every object counted here.
    #[must_use]
    pub fn objects(&self) -> u64 {
        self.extension_total()
            .saturating_add(self.sniffed_not_parquet)
            .saturating_add(self.empty)
    }

    fn extension_total(&self) -> u64 {
        self.known
            .iter()
            .fold(self.no_extension, |total, &n| total.saturating_add(n))
            .saturating_add(self.other_total)
    }

    /// Up to [`LISTED_EXTENSIONS`] extensions, most objects first (then by
    /// name), and the objects in every extension not listed.
    #[must_use]
    pub fn by_extension(&self) -> (Vec<ExtensionCount<'_>>, u64) {
        let mut all: Vec<ExtensionCount<'_>> = NOT_PARQUET
            .iter()
            .zip(self.known)
            .map(|(&extension, count)| ExtensionCount { extension, count })
            .chain(std::iter::once(ExtensionCount {
                extension: "",
                count: self.no_extension,
            }))
            .chain(self.other.iter().map(|(name, count)| ExtensionCount {
                extension: name,
                count: *count,
            }))
            .filter(|entry| entry.count > 0)
            .collect();
        all.sort_by(|a, b| b.count.cmp(&a.count).then(a.extension.cmp(b.extension)));
        all.truncate(LISTED_EXTENSIONS);
        let listed = all
            .iter()
            .fold(0_u64, |total, entry| total.saturating_add(entry.count));
        (all, self.extension_total().saturating_sub(listed))
    }

    /// Objects sniffed and found not to be Parquet.
    #[must_use]
    pub fn sniffed_not_parquet(&self) -> u64 {
        self.sniffed_not_parquet
    }

    /// Zero-byte objects and folder markers.
    #[must_use]
    pub fn empty(&self) -> u64 {
        self.empty
    }

    /// The heap held: the kept extension names and their list.
    #[must_use]
    pub(super) fn heap_bytes(&self) -> usize {
        self.other.capacity() * size_of::<(String, u64)>()
            + self
                .other
                .iter()
                .map(|(name, _)| name.capacity())
                .sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::{ExtensionCount, LISTED_EXTENSIONS, MAX_EXTENSION_BYTES, OutOfScope};

    fn observed(extensions: &[&str]) -> OutOfScope {
        let mut scope = OutOfScope::default();
        for extension in extensions {
            scope.observe_extension(extension);
        }
        scope
    }

    #[test]
    fn extensions_are_listed_most_common_first() {
        let mut scope = observed(&["csv", "json", "json", "", "png", "json", "csv"]);
        scope.observe_empty();
        scope.observe_sniffed_not_parquet();
        let (listed, rest) = scope.by_extension();
        assert_eq!(
            listed,
            [
                ExtensionCount {
                    extension: "json",
                    count: 3
                },
                ExtensionCount {
                    extension: "csv",
                    count: 2
                },
                ExtensionCount {
                    extension: "",
                    count: 1
                },
                ExtensionCount {
                    extension: "png",
                    count: 1
                },
            ]
        );
        assert_eq!(rest, 0);
        assert_eq!(scope.objects(), 9);
    }

    #[test]
    fn hostile_extensions_are_cut_bounded_and_still_counted_exactly() {
        let mut scope = OutOfScope::default();
        for n in 0..10_000 {
            scope.observe_extension(&format!("{n:05}{}", "x".repeat(100)));
        }
        let (listed, rest) = scope.by_extension();
        assert_eq!(listed.len(), LISTED_EXTENSIONS);
        assert!(
            listed
                .iter()
                .all(|entry| entry.extension.len() <= MAX_EXTENSION_BYTES)
        );
        assert_eq!(rest, 10_000 - 32);
        assert_eq!(scope.objects(), 10_000);
        assert!(scope.heap_bytes() <= OutOfScope::MAX_BYTES);
    }

    #[test]
    fn any_order_and_any_merge_give_the_same_counts() {
        let extensions: Vec<String> = (0..200)
            .map(|n| match n % 4 {
                0 => "json".to_owned(),
                1 => String::new(),
                _ => format!("odd{}", n % 50),
            })
            .collect();
        let refs: Vec<&str> = extensions.iter().map(String::as_str).collect();
        let forward = observed(&refs);
        let mut reversed = refs.clone();
        reversed.reverse();
        assert_eq!(observed(&reversed), forward);
        for split in [0, 1, 37, 100, 199, 200] {
            let (a, b) = refs.split_at(split);
            let mut left = observed(a);
            left.merge(&observed(b));
            let mut right = observed(b);
            right.merge(&observed(a));
            assert_eq!(left.by_extension(), forward.by_extension(), "{split}");
            assert_eq!(right.by_extension(), forward.by_extension(), "{split}");
            assert_eq!(left.objects(), 200);
        }
    }
}
