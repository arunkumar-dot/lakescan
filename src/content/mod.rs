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
//! [`SimStore`] (in memory, with a simulated latency model) in tests and
//! the benchmark.
//!
//! **Speed.** The driver scans up to `--concurrency` files at once; within
//! a partially read file, each round's page reads are coalesced (see
//! `read::coalesce`, `--coalesce-gap`) and up to four are in flight at
//! once. Decoding runs on tokio's blocking pool, inside `catch_unwind`.
//!
//! **Memory budget.** Every fetch and decode holds permits from one
//! [`MemoryBudget`] (`--memory-budget`) for the bytes it fetches or the
//! sizes it declares, released when the buffers are dropped; see `budget`
//! for how that stays deadlock-free. [`file_need`] is the most one file can
//! hold under the caps: a whole read (the file, its metadata, one decode
//! of two pages at [`PAGE_CAP`] plus a dictionary's slots, and one
//! column's samples), or a partial one (metadata up to [`FOOTER_CAP`], plus
//! the larger of opening and sampling: prefetched ranges, one decode, and
//! a batch of columns' samples). 108,474,240 bytes (~103 MiB) at the default whole-file
//! maximum. A budget below it is a usage error. Outside the budget, each
//! in-flight file holds only its key, counts and findings (a few
//! kilobytes) and up to 12,288 page locations (~0.8 MiB at most); its
//! metadata and its per-column scan records (at most [`MAX_COLUMNS`]
//! columns, or the file is `too-many-columns`) are under permits. None of
//! it depends on what a
//! file merely declares, and nothing here grows with the bucket.

mod budget;
mod classify;
mod clean;
mod detect;
mod fetch;
mod header;
mod names;
mod read;
mod sim;

pub use budget::{BudgetTooSmall, FileBudget, MemoryBudget, Permit};
pub use fetch::{FetchError, ObjectReader, S3ObjectReader};
pub use read::{
    COALESCE_MAX, DEFAULT_COALESCE_GAP, FOOTER_CAP, MAX_COLUMNS, MAX_ROW_GROUPS,
    MAX_VALUES_PER_ROW_GROUP, PAGE_CAP, TAIL_BYTES, file_need,
};
pub use sim::{Latency, SimStore};

use crate::model::{
    ColumnDetail, Detail, Finding, NotScannedReason, ObjectMeta, PiiType, RuleId, Severity,
};

/// The default `--pii-whole-file-max`: objects at or below this size are
/// read whole, in one request.
pub const DEFAULT_WHOLE_FILE_MAX: u64 = 8 * 1024 * 1024;

/// The largest `--pii-whole-file-max` accepted.
pub const MAX_WHOLE_FILE_MAX: u64 = 64 * 1024 * 1024;

/// The default `--memory-budget`: 256 MiB.
pub const DEFAULT_MEMORY_BUDGET: u64 = 256 * 1024 * 1024;

/// The default `--concurrency`.
pub const DEFAULT_CONCURRENCY: usize = 16;

/// The largest `--concurrency` accepted.
pub const MAX_CONCURRENCY: usize = 256;

/// How one file is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanOptions {
    /// Files at or below this size are read whole.
    pub whole_file_max: u64,
    /// Page reads this close together are read as one (0: never).
    pub coalesce_gap: u64,
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
    /// Columns compressed with a codec `LakeScan` cannot decode safely
    /// (LZO).
    pub skipped_unsupported_codec: u64,
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

/// Scans one eligible object through `reader`, holding buffers only under
/// permits from `budget`. Never fails: a file that cannot be read or
/// parsed is a [`FileOutcome::NotScanned`].
pub async fn scan_file<R: ObjectReader>(
    reader: R,
    object: &ObjectMeta,
    options: ScanOptions,
    budget: FileBudget,
) -> FileScan {
    let mut session = read::session(
        reader,
        &object.key,
        object.size,
        budget,
        options.coalesce_gap,
    );
    let result = match session.open(options.whole_file_max).await {
        Ok((metadata, _metadata_permit, opened)) => {
            let whole = matches!(opened, read::Opened::Whole(_));
            session
                .scan(&metadata, &opened)
                .await
                .map(|scanned| (whole, scanned))
        }
        Err(reason) => Err(reason),
    };
    let stats = session.stats;
    match result {
        Ok((whole, scanned)) => FileScan {
            // Findings from column names alone (dates of birth) stand even
            // when no value could be read.
            outcome: if scanned.nothing_examined {
                FileOutcome::NotScanned(NotScannedReason::NoColumnExamined)
            } else if whole {
                FileOutcome::ScannedWhole
            } else {
                FileOutcome::ScannedPartially
            },
            columns: scanned.findings,
            stats,
        },
        Err(reason) => FileScan {
            outcome: FileOutcome::NotScanned(reason),
            columns: Vec::new(),
            stats,
        },
    }
}

/// Test-only decode fault injection (see `read::fault`).
#[cfg(test)]
pub(crate) use read::fault as read_fault;

#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod tests;
