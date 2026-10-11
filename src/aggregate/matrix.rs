//! [`FindingsMatrix`]: count and bytes per `RuleId` × `Severity`, plus the
//! worst severity seen, derived from the matrix itself rather than tracked
//! separately.

use super::stats::CountBytes;
use crate::model::{RuleId, Severity};

const NUM_RULES: usize = RuleId::ALL.len();
const NUM_SEVERITIES: usize = Severity::ALL.len();

/// A fixed `RuleId` × `Severity` grid of [`CountBytes`] cells.
///
/// No heap: every cell lives inline in the grid, so observing and merging
/// are both plain saturating addition, and [`FindingsMatrix::MAX_BYTES`] is
/// just `size_of::<Self>()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FindingsMatrix {
    cells: [[CountBytes; NUM_SEVERITIES]; NUM_RULES],
}

impl Default for FindingsMatrix {
    fn default() -> Self {
        Self {
            cells: [[CountBytes::default(); NUM_SEVERITIES]; NUM_RULES],
        }
    }
}

impl FindingsMatrix {
    /// This grid's total size: fixed, with no heap component.
    pub(super) const MAX_BYTES: usize = size_of::<Self>();

    /// Records one finding of `rule` and `severity`, for an object of
    /// `size` bytes.
    pub(super) fn observe(&mut self, rule: RuleId, severity: Severity, size: u64) {
        if let Some(row) = self.cells.get_mut(rule.index())
            && let Some(cell) = row.get_mut(severity.index())
        {
            cell.observe(size);
        }
    }

    /// The count and bytes recorded for this exact `(rule, severity)` pair.
    #[must_use]
    pub(super) fn cell(&self, rule: RuleId, severity: Severity) -> CountBytes {
        self.cells
            .get(rule.index())
            .and_then(|row| row.get(severity.index()))
            .copied()
            .unwrap_or_default()
    }

    /// Folds `other`'s grid into `self`, cell by cell.
    pub(super) fn merge(&mut self, other: &Self) {
        for (row, other_row) in self.cells.iter_mut().zip(other.cells.iter()) {
            for (cell, other_cell) in row.iter_mut().zip(other_row.iter()) {
                cell.merge(*other_cell);
            }
        }
    }

    /// The highest severity with a nonzero count anywhere in the grid, or
    /// `None` if nothing has been observed yet.
    ///
    /// Derived on demand rather than tracked as a separate field: the
    /// matrix already has everything needed to answer this, and deriving
    /// it keeps `merge` trivially correct (plain per-cell addition) without
    /// a second piece of state that could drift out of sync.
    #[must_use]
    pub(super) fn worst_severity(&self) -> Option<Severity> {
        Severity::ALL.into_iter().rev().find(|&severity| {
            RuleId::ALL
                .into_iter()
                .any(|rule| self.cell(rule, severity).count > 0)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::FindingsMatrix;
    use crate::model::{RuleId, Severity};

    #[test]
    fn observe_accumulates_count_and_bytes_per_cell() {
        let mut matrix = FindingsMatrix::default();
        matrix.observe(RuleId::SensitiveKey, Severity::High, 100);
        matrix.observe(RuleId::SensitiveKey, Severity::High, 50);
        matrix.observe(RuleId::SensitiveKey, Severity::Medium, 10);

        let cell = matrix.cell(RuleId::SensitiveKey, Severity::High);
        assert_eq!(cell.count, 2);
        assert_eq!(cell.bytes, 150);

        let other_cell = matrix.cell(RuleId::SensitiveKey, Severity::Medium);
        assert_eq!(other_cell.count, 1);

        let untouched = matrix.cell(RuleId::ReducedRedundancy, Severity::High);
        assert_eq!(untouched.count, 0);
    }

    #[test]
    fn merge_sums_every_cell() {
        let mut a = FindingsMatrix::default();
        a.observe(RuleId::StaleStandard, Severity::Low, 5);

        let mut b = FindingsMatrix::default();
        b.observe(RuleId::StaleStandard, Severity::Low, 7);
        b.observe(RuleId::ZeroByteObject, Severity::Info, 0);

        a.merge(&b);

        assert_eq!(a.cell(RuleId::StaleStandard, Severity::Low).count, 2);
        assert_eq!(a.cell(RuleId::StaleStandard, Severity::Low).bytes, 12);
        assert_eq!(a.cell(RuleId::ZeroByteObject, Severity::Info).count, 1);
    }

    #[test]
    fn worst_severity_is_none_when_empty() {
        assert_eq!(FindingsMatrix::default().worst_severity(), None);
    }

    #[test]
    fn worst_severity_is_the_highest_nonzero_cell() {
        let mut matrix = FindingsMatrix::default();
        matrix.observe(RuleId::ZeroByteObject, Severity::Info, 0);
        matrix.observe(RuleId::ReducedRedundancy, Severity::Medium, 1);
        matrix.observe(RuleId::SensitiveKey, Severity::High, 1);

        assert_eq!(matrix.worst_severity(), Some(Severity::High));
    }
}
