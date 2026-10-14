//! [`ContentSummary`]: what content scanning did across the whole run —
//! files by outcome, columns by what happened to them, bytes and
//! requests. Fixed-size counters only, so merging is plain saturating
//! addition.

use crate::content::{FileOutcome, FileScan};
use crate::model::NotScannedReason;

const NUM_REASONS: usize = NotScannedReason::ALL.len();

/// Content-scanning totals for one run. Present in [`super::Aggregates`]
/// only when `--pii` was given.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ContentSummary {
    /// Objects whose key names a Parquet file.
    pub files_eligible: u64,
    /// Files read whole, in one request.
    pub scanned_whole: u64,
    /// Files read partially (footer and sampled pages).
    pub scanned_partially: u64,
    /// Files not scanned, per reason, indexed by
    /// [`NotScannedReason::index`].
    not_scanned: [u64; NUM_REASONS],
    /// Candidate columns sampled and classified.
    pub columns_examined: u64,
    /// Repeated (list or map) columns skipped.
    pub skipped_repeated: u64,
    /// Columns of an unsupported type skipped.
    pub skipped_unsupported_type: u64,
    /// Columns skipped because a page exceeded the page cap.
    pub skipped_page_too_large: u64,
    /// Columns skipped because their pages could not be decoded.
    pub skipped_unreadable: u64,
    /// Bytes read from S3 for content scanning.
    pub bytes_read: u64,
    /// `GetObject` requests made for content scanning.
    pub get_requests: u64,
}

impl ContentSummary {
    /// This summary's total size as `Aggregates` holds it (optional):
    /// fixed, with no heap component.
    pub(super) const MAX_BYTES: usize = size_of::<Option<Self>>();

    /// Records one scanned (or unscannable) file.
    pub(super) fn observe(&mut self, scan: &FileScan) {
        let add = |total: &mut u64, n: u64| *total = total.saturating_add(n);
        add(&mut self.files_eligible, 1);
        match scan.outcome {
            FileOutcome::ScannedWhole => add(&mut self.scanned_whole, 1),
            FileOutcome::ScannedPartially => add(&mut self.scanned_partially, 1),
            FileOutcome::NotScanned(reason) => {
                if let Some(count) = self.not_scanned.get_mut(reason.index()) {
                    add(count, 1);
                }
            }
        }
        let stats = scan.stats;
        add(&mut self.columns_examined, stats.columns_examined);
        add(&mut self.skipped_repeated, stats.skipped_repeated);
        add(
            &mut self.skipped_unsupported_type,
            stats.skipped_unsupported_type,
        );
        add(
            &mut self.skipped_page_too_large,
            stats.skipped_page_too_large,
        );
        add(&mut self.skipped_unreadable, stats.skipped_unreadable);
        add(&mut self.bytes_read, stats.bytes_read);
        add(&mut self.get_requests, stats.get_requests);
    }

    /// Folds `other` in. Order-independent.
    pub(super) fn merge(&mut self, other: &Self) {
        let add = |total: &mut u64, n: u64| *total = total.saturating_add(n);
        add(&mut self.files_eligible, other.files_eligible);
        add(&mut self.scanned_whole, other.scanned_whole);
        add(&mut self.scanned_partially, other.scanned_partially);
        for (count, other) in self.not_scanned.iter_mut().zip(other.not_scanned) {
            add(count, other);
        }
        add(&mut self.columns_examined, other.columns_examined);
        add(&mut self.skipped_repeated, other.skipped_repeated);
        add(
            &mut self.skipped_unsupported_type,
            other.skipped_unsupported_type,
        );
        add(
            &mut self.skipped_page_too_large,
            other.skipped_page_too_large,
        );
        add(&mut self.skipped_unreadable, other.skipped_unreadable);
        add(&mut self.bytes_read, other.bytes_read);
        add(&mut self.get_requests, other.get_requests);
    }

    /// Files not scanned for `reason`.
    #[must_use]
    pub fn not_scanned(&self, reason: NotScannedReason) -> u64 {
        self.not_scanned.get(reason.index()).copied().unwrap_or(0)
    }

    /// Files not scanned, for any reason.
    #[must_use]
    pub fn not_scanned_total(&self) -> u64 {
        self.not_scanned
            .iter()
            .fold(0, |total, &n| total.saturating_add(n))
    }

    /// Files scanned, whole or partially.
    #[must_use]
    pub fn files_scanned(&self) -> u64 {
        self.scanned_whole.saturating_add(self.scanned_partially)
    }

    /// Columns skipped, for any reason.
    #[must_use]
    pub fn columns_skipped(&self) -> u64 {
        [
            self.skipped_repeated,
            self.skipped_unsupported_type,
            self.skipped_page_too_large,
            self.skipped_unreadable,
        ]
        .iter()
        .fold(0, |total, &n| total.saturating_add(n))
    }
}

#[cfg(test)]
mod tests {
    use super::ContentSummary;
    use crate::content::{FileOutcome, FileScan, FileStats};
    use crate::model::NotScannedReason;

    fn scan(outcome: FileOutcome, bytes: u64) -> FileScan {
        FileScan {
            outcome,
            columns: Vec::new(),
            stats: FileStats {
                columns_examined: 3,
                skipped_repeated: 1,
                bytes_read: bytes,
                get_requests: 2,
                ..FileStats::default()
            },
        }
    }

    #[test]
    fn observing_counts_files_by_outcome_and_sums_the_rest() {
        let mut summary = ContentSummary::default();
        summary.observe(&scan(FileOutcome::ScannedWhole, 100));
        summary.observe(&scan(FileOutcome::ScannedPartially, 10));
        summary.observe(&scan(
            FileOutcome::NotScanned(NotScannedReason::AccessDenied),
            0,
        ));
        assert_eq!(summary.files_eligible, 3);
        assert_eq!(summary.files_scanned(), 2);
        assert_eq!(summary.not_scanned(NotScannedReason::AccessDenied), 1);
        assert_eq!(summary.not_scanned_total(), 1);
        assert_eq!(summary.columns_examined, 9);
        assert_eq!(summary.columns_skipped(), 3);
        assert_eq!(summary.bytes_read, 110);
        assert_eq!(summary.get_requests, 6);
    }

    #[test]
    fn merging_is_order_independent() {
        let scans = [
            scan(FileOutcome::ScannedWhole, 5),
            scan(FileOutcome::NotScanned(NotScannedReason::Encrypted), 7),
            scan(FileOutcome::ScannedPartially, 11),
        ];
        let mut all = ContentSummary::default();
        for s in &scans {
            all.observe(s);
        }
        let [first, second, third] = scans;
        let mut left = ContentSummary::default();
        left.observe(&third);
        let mut right = ContentSummary::default();
        right.observe(&first);
        right.observe(&second);
        right.merge(&left);
        assert_eq!(all, right);
    }
}
