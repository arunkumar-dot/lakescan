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
//! of two pages at [`PAGE_CAP`] plus a dictionary's slots and a repeated
//! page's levels and value slots (at most [`MAX_REPEATED_VALUES`]), and one
//! column's samples), or a partial one (metadata up to [`FOOTER_CAP`], plus
//! the larger of opening and sampling: prefetched ranges, one decode, and
//! a batch of columns' samples). 113,192,832 bytes (~108 MiB) at the default whole-file
//! maximum. A budget below it is a usage error. Outside the budget, each
//! in-flight file holds only its key, counts, findings and up to
//! [`MAX_NOT_EXAMINED_EXAMPLES`](crate::model::MAX_NOT_EXAMINED_EXAMPLES)
//! not-examined column paths (a few kilobytes) and up to 12,288 page
//! locations (~0.8 MiB at most); its
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

pub use budget::{
    BUDGET_WAIT, BudgetError, FileBudget, MAX_MEMORY_BUDGET, MemoryBudget, Permit, Refused,
};
pub use fetch::{FetchError, ObjectReader, S3ObjectReader};
pub use read::{
    COALESCE_MAX, DEFAULT_COALESCE_GAP, FOOTER_CAP, MAX_COLUMNS, MAX_REPEATED_VALUES,
    MAX_ROW_GROUPS, MAX_VALUES_PER_ROW_GROUP, PAGE_CAP, TAIL_BYTES, file_need,
};
pub use sim::{Latency, SimStore};

use crate::model::{
    ColumnDetail, Detail, Finding, NotExamined, NotExaminedReason, NotScannedReason, ObjectMeta,
    PiiType, RuleId, Severity,
};

/// The default `--pii-whole-file-max`: objects at or below this size are
/// read whole, in one request.
pub const DEFAULT_WHOLE_FILE_MAX: u64 = 8 * 1024 * 1024;

/// The largest `--pii-whole-file-max` accepted.
pub const MAX_WHOLE_FILE_MAX: u64 = 64 * 1024 * 1024;

/// The default `--memory-budget`: 512 MiB.
pub const DEFAULT_MEMORY_BUDGET: u64 = 512 * 1024 * 1024;

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

/// Which objects without a Parquet extension are sniffed (`--pii-sniff`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sniff {
    /// Objects with no extension, or one not on [`NOT_PARQUET`]: one
    /// ranged GET of their last 8 bytes each.
    Unknown,
    /// None: only `.parquet` and `.parq` keys are scanned.
    None,
}

impl Sniff {
    /// `"unknown"` or `"none"`, as the flag spells it.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::None => "none",
        }
    }
}

/// Extensions (lowercase, without the dot) of formats that are never
/// Parquet, so objects carrying them are never sniffed: text and data
/// formats, archives and compression, other columnar and row formats,
/// documents, media, code and configuration, keys and certificates, and
/// the checksum and state files data tools leave behind.
pub const NOT_PARQUET: [&str; 96] = [
    "json",
    "jsonl",
    "ndjson",
    "geojson",
    "csv",
    "tsv",
    "psv",
    "txt",
    "text",
    "log",
    "out",
    "err",
    "md",
    "rst",
    "xml",
    "html",
    "htm",
    "xhtml",
    "css",
    "js",
    "mjs",
    "map",
    "yaml",
    "yml",
    "toml",
    "ini",
    "cfg",
    "conf",
    "properties",
    "env",
    "sql",
    "sh",
    "bash",
    "py",
    "ipynb",
    "rb",
    "java",
    "class",
    "jar",
    "war",
    "go",
    "rs",
    "gz",
    "gzip",
    "bz2",
    "xz",
    "zst",
    "lz4",
    "zip",
    "tar",
    "tgz",
    "7z",
    "rar",
    "avro",
    "orc",
    "arrow",
    "feather",
    "crc",
    "tfstate",
    "pem",
    "key",
    "crt",
    "cer",
    "der",
    "p12",
    "pfx",
    "pub",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "bmp",
    "tif",
    "tiff",
    "webp",
    "svg",
    "ico",
    "heic",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "odt",
    "ods",
    "rtf",
    "mp3",
    "mp4",
    "m4a",
    "mov",
    "avi",
    "wav",
    "flac",
    "webm",
];

/// The extension of `key`'s last path segment, lowercase and without the
/// dot: what follows its last `.`, or `""` if it has none (or ends in
/// one). Not cut to any length; [`crate::aggregate`] bounds what it keeps.
#[must_use]
pub fn extension_of(key: &str) -> String {
    let name = key.rsplit('/').next().unwrap_or(key);
    name.rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default()
}

/// What `--pii` does with one listed object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// A `.parquet` or `.parq` key: content-scanned.
    Parquet,
    /// Maybe Parquet: sniffed first, and scanned if it is.
    Sniff,
    /// Not content-scanned because of its extension (`""` for none).
    Extension(String),
    /// A zero-byte object or a folder marker: nothing to read.
    Empty,
}

/// What `--pii` with `sniff` does with `object`. Zero-byte objects and
/// folder markers are never sniffed, and neither are files whose name
/// starts with `_` or `.` (Hadoop's hidden-file convention: `_SUCCESS`,
/// `_metadata`, `.crc` files), which Spark, Hive and Trino skip too.
#[must_use]
pub fn scope_of(object: &ObjectMeta, sniff: Sniff) -> Scope {
    if is_eligible(&object.key) {
        return Scope::Parquet;
    }
    if object.size == 0 || object.key.ends_with('/') {
        return Scope::Empty;
    }
    let extension = extension_of(&object.key);
    let name = object.key.rsplit('/').next().unwrap_or(&object.key);
    let hidden = name.starts_with(['_', '.']);
    if sniff == Sniff::None || hidden || NOT_PARQUET.contains(&extension.as_str()) {
        Scope::Extension(extension)
    } else {
        Scope::Sniff
    }
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
    /// Sniffed (no Parquet extension) and found not to be Parquet: out of
    /// scope, never a `content-not-scanned` finding.
    SniffedNotParquet,
}

/// One file's counts, folded into the run's content summary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileStats {
    /// Candidate columns sampled and classified.
    pub columns_examined: u64,
    /// Repeated (list or map) columns, never read. Always 0 since M12,
    /// which reads repeated string and integer columns; kept so the
    /// summary's fields stay the same.
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
    /// `GetObject` requests made for this file, including a sniff.
    pub get_requests: u64,
    /// 1 if the object was sniffed for the Parquet magic, else 0.
    pub sniffed: u64,
    /// Columns that could hold personal data but were not examined, per
    /// reason, indexed by [`NotExaminedReason::index`]: string and integer
    /// columns skipped for any reason, and columns of an unsupported type
    /// whose name hints personal data. A subset of the skipped counts.
    pub not_examined: [u64; NotExaminedReason::ALL.len()],
}

impl FileStats {
    /// Columns not examined, for any reason.
    #[must_use]
    pub fn not_examined_total(&self) -> u64 {
        self.not_examined
            .iter()
            .fold(0, |total, &n| total.saturating_add(n))
    }
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
    /// Columns that could hold personal data but were not examined: the
    /// smallest [`crate::model::MAX_NOT_EXAMINED_EXAMPLES`], by path then
    /// reason. [`FileStats::not_examined`] counts them all.
    pub not_examined: Vec<NotExamined>,
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
            FileOutcome::ScannedWhole
            | FileOutcome::ScannedPartially
            | FileOutcome::SniffedNotParquet => None,
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
            not_examined: scanned.not_examined,
            stats,
        },
        // A file not scanned has no columns of its own to report.
        Err(reason) => FileScan {
            outcome: FileOutcome::NotScanned(reason),
            columns: Vec::new(),
            not_examined: Vec::new(),
            stats: FileStats {
                not_examined: [0; NotExaminedReason::ALL.len()],
                ..stats
            },
        },
    }
}

/// Sniffs `object`, which has no Parquet extension: one ranged GET of its
/// last 8 bytes, under permits, counted in the file's stats. Parquet (the
/// `PAR1` magic, or `PARE` for an encrypted footer) is then scanned like
/// any `.parquet` file, so a sniffed Parquet file that cannot be read is
/// `content-not-scanned` and fails closed. Anything else is
/// [`FileOutcome::SniffedNotParquet`]. An object under 12 bytes cannot be
/// Parquet and is not fetched. A sniff that fails (refused, or still
/// failing after retries) leaves the type unknown, so it fails closed too.
pub async fn sniff_and_scan<R: ObjectReader>(
    reader: R,
    object: &ObjectMeta,
    options: ScanOptions,
    mut budget: FileBudget,
) -> FileScan {
    let not = |outcome, stats| FileScan {
        outcome,
        columns: Vec::new(),
        not_examined: Vec::new(),
        stats,
    };
    let mut stats = FileStats {
        sniffed: 1,
        ..FileStats::default()
    };
    if object.size < 12 {
        return not(FileOutcome::SniffedNotParquet, stats);
    }
    let magic = {
        let permit = match budget.acquire(8).await {
            Ok(permit) => permit,
            Err(Refused::TimedOut) => {
                return not(
                    FileOutcome::NotScanned(NotScannedReason::BudgetTimeout),
                    stats,
                );
            }
            Err(Refused::OverNeed) => {
                return not(FileOutcome::NotScanned(NotScannedReason::Unreadable), stats);
            }
        };
        let read = reader
            .read_range(&object.key, object.size - 8, object.size)
            .await;
        stats.get_requests = 1;
        let magic = match read {
            Ok(bytes) => {
                let bytes = bytes.into_bytes();
                stats.bytes_read = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                bytes.get(4..8).map(<[u8]>::to_vec)
            }
            Err(FetchError::AccessDenied) => {
                return not(
                    FileOutcome::NotScanned(NotScannedReason::AccessDenied),
                    stats,
                );
            }
            Err(FetchError::Failed) => {
                return not(
                    FileOutcome::NotScanned(NotScannedReason::FetchFailed),
                    stats,
                );
            }
        };
        drop(permit);
        magic
    };
    if !matches!(magic.as_deref(), Some(b"PAR1" | b"PARE")) {
        return not(FileOutcome::SniffedNotParquet, stats);
    }
    let mut scan = scan_file(reader, object, options, budget).await;
    scan.stats.get_requests = scan.stats.get_requests.saturating_add(stats.get_requests);
    scan.stats.bytes_read = scan.stats.bytes_read.saturating_add(stats.bytes_read);
    scan.stats.sniffed = stats.sniffed;
    scan
}

/// Test-only decode fault injection (see `read::fault`).
#[cfg(test)]
pub(crate) use read::fault as read_fault;

#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod tests;
