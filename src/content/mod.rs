//! Structured-PII scanning of Parquet files (M7, opt-in with `--pii`).
//!
//! Single responsibility: given one listed object that looks like a
//! Parquet file, read as little of it as possible and say which columns
//! hold personal data, how sure the scan is, and how many values that is
//! based on. Never which values: no sampled value leaves this module, in
//! a finding, an error, or anywhere else.
//!
//! The pieces, in the order a file goes through them:
//!
//! - `read`: the read plan (whole file at or below `--pii-whole-file-max`,
//!   else a tail read for the footer plus the first pages of each
//!   candidate column), escalation to more row groups, and decoding with
//!   the `parquet` crate's own page and column readers;
//! - `clean`: trimming and dropping empty, placeholder, repeated-character
//!   and dominant values;
//! - `detect`: one validator per value-detectable [`PiiType`];
//! - `names`: column-name hints;
//! - `classify`: the confidence rules, at most one verdict per column.
//!
//! [`ObjectReader`] is the read seam: [`S3ObjectReader`] in production,
//! in-memory readers in tests.
//!
//! **Memory budget.** One file at a time, and every buffer is dropped
//! before the next file. The largest thing held is either the whole file
//! (at most the whole-file maximum, 8 MiB by default and 64 MiB at most)
//! or, for a partial read, the footer (at most [`FOOTER_CAP`], 16 MiB) and
//! one column window (a dictionary page and a first data page, each at
//! most [`PAGE_CAP`], 8 MiB): [`memory_bound`] is the larger of the two.
//! On top of that: the 64 KiB tail read; page headers (at most 1 MiB
//! each); one decompressed page, at most 8 MiB, because every header is
//! checked against the page cap before `parquet` allocates for it; a
//! dictionary's value slots, at most 1,048,576 of them (~32 MiB); and each
//! column's sample, at most 3 row groups × 2,000 values × 257 bytes
//! (~1.5 MB). None of it depends on what a file merely declares, and
//! nothing here grows with the bucket.

mod classify;
mod clean;
mod detect;
mod fetch;
mod header;
mod names;
mod read;

pub use fetch::{FetchError, ObjectReader, S3ObjectReader};
pub use read::{FOOTER_CAP, MAX_ROW_GROUPS, MAX_VALUES_PER_ROW_GROUP, PAGE_CAP, TAIL_BYTES};

use crate::model::{
    ColumnDetail, Detail, Finding, NotScannedReason, ObjectMeta, PiiType, RuleId, Severity,
};

/// The default `--pii-whole-file-max`: objects at or below this size are
/// read whole, in one request.
pub const DEFAULT_WHOLE_FILE_MAX: u64 = 8 * 1024 * 1024;

/// The largest `--pii-whole-file-max` accepted.
pub const MAX_WHOLE_FILE_MAX: u64 = 64 * 1024 * 1024;

/// The content stage's memory bound for a given whole-file maximum: the
/// larger of the whole file, or the footer cap plus two page caps. See
/// this module's doc for what comes on top.
#[must_use]
pub const fn memory_bound(whole_file_max: u64) -> u64 {
    let partial = FOOTER_CAP + 2 * PAGE_CAP;
    if whole_file_max > partial {
        whole_file_max
    } else {
        partial
    }
}

/// Whether `key` names a Parquet file: it ends in `.parquet` or `.parq`,
/// in any case.
#[must_use]
pub fn is_eligible(key: &str) -> bool {
    [".parquet", ".parq"].iter().any(|suffix| {
        key.len() >= suffix.len()
            && key
                .get(key.len() - suffix.len()..)
                .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
    })
}

/// How a file's scan ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOutcome {
    /// Read whole, in one request.
    ScannedWhole,
    /// Read partially: footer and sampled pages.
    ScannedPartially,
    /// Not scanned, for this reason.
    NotScanned(NotScannedReason),
}

/// One file's counts, folded into the run's content summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileStats {
    /// Candidate columns sampled and classified.
    pub columns_examined: u64,
    /// Repeated (list or map) columns, never read.
    pub skipped_repeated: u64,
    /// Columns of a type detection does not cover (booleans, floats,
    /// decimals, times).
    pub skipped_unsupported_type: u64,
    /// Columns whose dictionary or first data page exceeded [`PAGE_CAP`].
    pub skipped_page_too_large: u64,
    /// Columns whose pages could not be decoded.
    pub skipped_unreadable: u64,
    /// Bytes returned by every read of this file.
    pub bytes_read: u64,
    /// `GetObject` requests made for this file.
    pub get_requests: u64,
}

/// One column's PII verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnFinding {
    /// What the column holds.
    pub pii: PiiType,
    /// The column, confidence and counts.
    pub detail: ColumnDetail,
}

/// Everything scanning one file produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileScan {
    /// How the scan ended.
    pub outcome: FileOutcome,
    /// One verdict per column found to hold PII.
    pub columns: Vec<ColumnFinding>,
    /// Counts for the content summary.
    pub stats: FileStats,
}

impl FileScan {
    /// The findings this scan raises against `object`: one per PII
    /// column, or one `content-not-scanned` (Info) if the file was not
    /// scanned.
    pub fn findings<'a>(&'a self, object: &'a ObjectMeta) -> impl Iterator<Item = Finding<'a>> {
        let not_scanned = match self.outcome {
            FileOutcome::NotScanned(reason) => Some(Finding {
                rule: RuleId::ContentNotScanned,
                severity: Severity::Info,
                object,
                detail: Detail::NotScanned(reason),
            }),
            FileOutcome::ScannedWhole | FileOutcome::ScannedPartially => None,
        };
        self.columns
            .iter()
            .map(move |column| Finding {
                rule: column.pii.rule(),
                severity: column.detail.confidence.severity(),
                object,
                detail: Detail::Column(&column.detail),
            })
            .chain(not_scanned)
    }
}

/// Scans one eligible object through `reader`. Never fails: a file that
/// cannot be read or parsed is a [`FileOutcome::NotScanned`].
pub async fn scan_file<R: ObjectReader>(
    reader: &mut R,
    object: &ObjectMeta,
    whole_file_max: u64,
) -> FileScan {
    let mut stats = FileStats::default();
    let result = {
        let mut session = read::session(reader, &object.key, object.size, &mut stats);
        match session.open(whole_file_max).await {
            Ok((metadata, opened)) => {
                let whole = matches!(opened, read::Opened::Whole(_));
                session
                    .scan(&metadata, &opened)
                    .await
                    .map(|columns| (whole, columns))
            }
            Err(reason) => Err(reason),
        }
    };
    match result {
        Ok((whole, columns)) => FileScan {
            outcome: if whole {
                FileOutcome::ScannedWhole
            } else {
                FileOutcome::ScannedPartially
            },
            columns,
            stats,
        },
        Err(reason) => FileScan {
            outcome: FileOutcome::NotScanned(reason),
            columns: Vec::new(),
            stats,
        },
    }
}

#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod tests;
