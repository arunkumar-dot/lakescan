//! Serializes results to an output sink.
//!
//! Single responsibility: render what the pipeline produced. The reporter
//! formats and writes; it does not compute, re-sort, or re-derive anything,
//! and it is the only module that touches the output destination.
//!
//! **Memory budget: 1 MB.** Output is a streaming writer behind a 64 KB
//! buffer. Records are written as they arrive, so no complete report is ever
//! materialized in memory regardless of how large the scan was.
//!
//! # Two inputs
//!
//! The reporter has two independent inputs, both produced upstream of it:
//!
//! - **Summaries**, from [`crate::aggregate::Aggregates`]: [`write_summary`]
//!   renders the whole-bucket picture — inventory, the findings matrix,
//!   samples, histograms, the distinct-content estimate — as either
//!   [`Format::Text`] or [`Format::Json`]. This is always a single,
//!   complete snapshot, written once at the end of a scan. The same
//!   snapshot is also rendered as CSV ([`write_inventory_csv`]) and as an
//!   interactive HTML dashboard ([`write_html`]), on request.
//! - An **optional per-finding stream**, from [`crate::rules::evaluate`]:
//!   [`FindingsWriter`] renders one JSON Lines record per [`Finding`] *as it
//!   arrives*, independent of the summary and independent of whether a
//!   summary is written at all. A driver that wants a live, per-finding feed
//!   (piped to `jq`, tailed, fed into another tool) uses this instead of
//!   waiting for [`Aggregates`] to finish.
//!
//! Both inputs are read-only here: the reporter never mutates an
//! [`Aggregates`] or a [`Finding`], and never recomputes a number either one
//! already carries (a bucket bound, a severity code, a byte count) — it asks
//! for the value and formats it.
//!
//! # JSON summary schema
//!
//! [`write_summary`] with [`Format::Json`] writes one JSON object.
//!
//! ## Stability: `schema_version` 1 is stable
//!
//! As of v0.1.0 (M11), `schema_version` 1 is **stable**: the schema below
//! is a public contract, and a consumer written against it keeps working
//! with every later release that still reports version 1.
//!
//! ## Compatibility policy
//!
//! `schema_version` is frozen at its current value for as long as every
//! change is **additive**: a new field, a new object in a list, a new
//! section, a new code in a map keyed by codes. Consumers must ignore
//! fields and codes they do not recognize. Removing or renaming a field,
//! changing its type, or changing what an existing field means is
//! **breaking** and bumps `schema_version`. Before v0.1.0 the schema was
//! not yet frozen; M11 made its last breaking change at version 1,
//! removing `largest_objects[].severity`, which was always `null`. The
//! `suppressed`, `suppressions`, and `distinct_content.duplicates_significant`
//! fields (M6), `content`, a suppression entry's `column`, and a
//! sample's `column`, `confidence`, `evidence`, `matched`, `sampled` and
//! `reason` (M7), `coverage` and `pii_inventory` with its `summary` and
//! per-table `status` (M8), and the `fetch-failed` reason and
//! `summary.tables_not_fully_scanned_documented` (M9), and the
//! `too-many-columns` reason (M10) were added under
//! this policy, so the version is still 1. M11.1 added, still at version
//! 1: `scan.settings`, `content.sniffed`, the `budget-timeout` reason,
//! `coverage.out_of_scope` and `coverage.sampling`,
//! `pii_inventory.truncated`, the undocumented confidence split on
//! `pii_inventory.summary`, `oldest_file` and `newest_file` on a table,
//! and `expires` on an inventory column. M12 added, still at version 1:
//! `content.columns_not_examined` and
//! `content.files_with_columns_not_examined`,
//! `coverage.columns_not_examined`, a table's `columns_not_examined`,
//! `summary.tables_with_columns_not_examined`, and the table status
//! `columns_not_examined` (a new code: a table that would have read
//! `no_pii_in_scanned_files` though columns that could hold PII were not
//! examined). Since M12 repeated columns are read, so
//! `content.columns_skipped.repeated` is always 0. M8 also made a PII rule's
//! `bytes` and `suppressed.bytes` always 0: they double-counted files
//! (once per column), and a consumer summing them was already wrong.
//!
//! ```text
//! {
//!   "schema_version": 1,
//!   "tool": { "name": string, "version": string },
//!   "scan": {
//!     "bucket": string,
//!     "prefix": string | null,
//!     "started_at": string,       // RFC 3339, UTC, seconds precision
//!     "elapsed_ms": integer,
//!     "settings": {               // the flags this run used; never a path
//!       "pii": bool,
//!       "pii_whole_file_max": integer | null, // null without --pii
//!       "pii_sniff": string | null,           // "unknown" or "none"
//!       "coalesce_gap": integer | null,
//!       "concurrency": integer | null,
//!       "memory_budget": integer | null,
//!       "fail_on": string,        // Severity::code(), or "none"
//!       "prefix": string | null,
//!       "config": { "sha256": string, "entries": integer } | null
//!                                 // the --config file's SHA-256 and how
//!                                 // many entries it has; null without one
//!     }
//!   },
//!   "verdict": { "worst_severity": string | null },  // Severity::code(), or null if no finding
//!   "inventory": {
//!     "object_count": integer,
//!     "total_bytes": integer,
//!     "by_storage_class": [        // non-zero known classes only
//!       { "storage_class": string, "count": integer, "bytes": integer }
//!     ],
//!     "unrecognized_storage_classes": [string],  // wire names, ascending;
//!                                                 // at most the 8 smallest
//!     "unrecognized_storage_class_totals": { "count": integer, "bytes": integer }
//!                                 // every unrecognized object, exactly —
//!                                 // always present, zero when there are
//!                                 // none. by_storage_class's counts plus
//!                                 // this count equal object_count (and
//!                                 // the same for bytes), even when more
//!                                 // than 8 distinct unrecognized classes
//!                                 // exist
//!   },
//!   "findings": [                  // one entry per rule with >=1 finding
//!     {                            // or >=1 suppressed finding, in
//!       "rule": string,            // RuleId::ALL order; RuleId::code()
//!       "title": string,           // RuleId::title()
//!       "counts": { "critical": integer, "high": integer, "medium": integer,
//!                   "low": integer, "info": integer },
//!                                  // every severity, always: no v1 rule
//!                                  // raises "critical" yet, but the scale
//!                                  // stays complete so adding one is not
//!                                  // a schema change
//!       "bytes":  { "critical": integer, "high": integer, "medium": integer,
//!                   "low": integer, "info": integer },
//!                                  // the finding objects' sizes; always 0
//!                                  // for PII rules (RuleId::is_pii), which
//!                                  // are about columns: not applicable
//!       "suppressed": { "count": integer, "bytes": integer }
//!                                  // findings a --config entry covered;
//!                                  // not included in counts/bytes above
//!                                  // (bytes 0 for PII rules, as above)
//!     }
//!   ],
//!   "content": {                   // null unless --pii was given
//!     "files_eligible": integer,   // .parquet/.parq keys, plus sniffed
//!                                  // objects that are Parquet
//!     "scanned_whole": integer,    // downloaded whole, in one GetObject,
//!                                  // then sampled like any other file
//!     "scanned_partially": integer,// footer + sampled pages
//!     "not_scanned": {             // one key per NotScannedReason::code(),
//!       "not-parquet": integer,    // always all nine, zero when none
//!       "unreadable": integer,
//!       "access-denied": integer,
//!       "encrypted": integer,
//!       "footer-too-large": integer,
//!       "no-column-examined": integer, // Parquet, but every column whose
//!                                  // values could be read was skipped
//!       "fetch-failed": integer,   // a GetObject still failed after the
//!                                  // SDK's retries (M9)
//!       "too-many-columns": integer, // over 16,384 leaf columns (M10)
//!       "budget-timeout": integer  // waited over 10 minutes for permits
//!     },
//!     "columns_examined": integer, // candidate columns sampled and classified
//!     "columns_skipped": {
//!       "repeated": integer,        // always 0 since M12, which reads
//!                                   // list and map columns
//!       "unsupported_type": integer,// booleans, floats, decimals, times
//!       "page_too_large": integer,  // a page over the 8 MiB cap
//!       "unreadable": integer,      // pages that could not be decoded
//!       "unsupported_codec": integer // a codec not decoded safely (LZO)
//!     },
//!     "columns_not_examined": {    // columns that could hold personal
//!       "unsupported-type": integer, // data but were not examined, in
//!       "page-too-large": integer, // scanned files, counted once per
//!       "unreadable": integer,     // file, by NotExaminedReason::code():
//!       "unsupported-codec": integer // always all four. A string or
//!                                  // integer column skipped for any
//!                                  // reason, or an unread type (float,
//!                                  // decimal, time) named like PII (M12)
//!     },
//!     "files_with_columns_not_examined": integer, // scanned files with any
//!     "bytes_read": integer,       // bytes returned by every GetObject
//!     "get_requests": integer,     // GetObject requests made, sniffs included
//!     "sniffed": integer           // extensionless or unknown-extension
//!                                  // objects given one 8-byte ranged GET
//!   },
//!   "coverage": {                  // null unless --pii was given
//!     "files_eligible": integer,   // as content.files_eligible
//!     "files_scanned": integer,    // downloaded whole or read partially
//!     "not_scanned_suppressed": integer,   // content-not-scanned finding
//!                                  // suppressed: documented
//!     "not_scanned_unsuppressed": integer, // undocumented; any of these
//!                                  // fails the run with exit code 6
//!     "percent": number | null,    // files_scanned / files_eligible * 100,
//!                                  // rounded down to one decimal; null
//!                                  // when files_eligible is 0
//!     "columns_not_examined": {    // in scanned files: PII unknown in them
//!       "total": integer,          // counted once per file
//!       "files": integer,          // scanned files with any
//!       "tables": integer,         // tables with any
//!       "by_reason": { "<not-examined reason code>": integer },
//!                                  // every NotExaminedReason::code()
//!       "examples": [              // the 64 smallest by (table, column,
//!         { "table": string, "column": string, "reason": string }
//!       ],                         // reason), each distinct
//!       "examples_truncated": bool // true if any distinct one was left out
//!     },
//!     "out_of_scope": {            // listed objects content scanning did
//!       "objects": integer,        // not read
//!       "by_extension": [          // the most common, at most 32
//!         { "extension": string, "count": integer }
//!                                  // extension is "" for none; escaped
//!                                  // and cut, because keys are hostile
//!       ],
//!       "other_extensions": integer, // objects whose extension was not
//!                                  // one of the 32 listed
//!       "sniffed_not_parquet": integer, // sniffed, and not Parquet
//!       "empty": integer           // zero-byte objects and folder markers
//!     },
//!     "sampling": {
//!       "method": string,          // how a column is sampled
//!       "exhaustive": bool         // always false: a sample is not the file
//!     }
//!   },
//!   "pii_inventory": {             // null unless --pii was given
//!     "summary": {                 // the headline, over tables held:
//!       "tables_with_pii": integer,  // tables with a PII location
//!       "pii_columns": integer,    // (table, column, rule) locations
//!       "undocumented": integer,   // of those: the action items
//!       "undocumented_confirmed": integer, // of undocumented, by the
//!       "undocumented_likely": integer,    // location's highest confidence
//!       "undocumented_possible": integer,
//!       "documented": integer,
//!       "tables_not_fully_scanned": integer, // with any file not scanned
//!       "tables_not_fully_scanned_documented": integer, // of those, every
//!                                  // unscanned file documented
//!       "tables_with_columns_not_examined": integer // with any column not
//!                                  // examined in a scanned file (M12)
//!     },
//!     "tables": [                  // sorted by table; a table is
//!       {                          // aggregate::table_of(key): the key's
//!                                  // directory minus Hive partitions and
//!                                  // one trailing "data" segment
//!         "table": string,         // "" for the bucket root; at most 1 KiB
//!         "status": string,        // "pii_found"; "no_pii_in_scanned_files"
//!                                  // (some files may not have been
//!                                  // scanned); "columns_not_examined":
//!                                  // none found in the columns examined,
//!                                  // but PII is unknown in the rest
//!                                  // (M12); "not_scanned": no file was
//!                                  // read, so PII is unknown
//!         "files_eligible": integer,
//!         "files_scanned": integer,
//!         "files_not_scanned": integer,
//!         "not_scanned": {         // reasons with any file only, keyed by
//!           "<reason code>": {     // NotScannedReason::code()
//!             "suppressed": integer,
//!             "unsuppressed": integer
//!           }
//!         },
//!         "example_key": string | null, // the smallest key in the table
//!                                  // with a PII finding; at most 1 KiB
//!         "oldest_file": string | null, // RFC 3339 of the oldest and
//!         "newest_file": string | null, // newest last_modified among the
//!                                  // table's eligible Parquet files
//!         "columns": [             // sorted by column, then rule
//!           {
//!             "column": string,    // the column path, at most 256 bytes
//!             "rule": string,      // a PII rule's code
//!             "highest_confidence": string, // over every file, suppressed
//!                                  // or not; Confidence::code()
//!             "evidence": string,  // "values" if any file's finding
//!                                  // rested on values, else "column-name"
//!             "files_confirmed": integer, // unsuppressed findings at each
//!             "files_likely": integer,    // confidence, one per file
//!             "files_possible": integer,
//!             "files_suppressed": integer,
//!             "status": string,    // "UNDOCUMENTED" if any file's finding
//!                                  // was not suppressed, else "documented"
//!             "reason": string | null, // documented only: the reason of the
//!                                  // first --config entry (file order)
//!                                  // that suppressed any of them
//!             "expires": string | null // YYYY-MM-DD when that entry expires;
//!                                  // null otherwise
//!           }
//!         ],
//!         "columns_not_examined": { // in this table's scanned files (M12)
//!           "total": integer,      // counted once per file
//!           "files": integer,      // scanned files with any
//!           "by_reason": { "<not-examined reason code>": integer },
//!           "examples": [          // this table's share of
//!             { "column": string, "reason": string } // coverage's examples
//!           ]
//!         }
//!       }
//!     ],
//!     "truncated": bool,           // true when left_out is non-zero
//!     "left_out": {                // what the caps dropped, exactly:
//!       "files": integer,          // files in tables left out
//!       "findings": integer        // findings in tables or entries left out
//!     },
//!     "caps": { "tables": integer, "entries": integer } // 4096, 16384
//!   },
//!   "suppressions": {              // --config entries worth attention,
//!     "expired": [ entry ],        // each list in file order; both empty
//!     "unused":  [ entry ]         // without --config
//!   },                             // entry: { "rule": string,
//!                                  //   "key": string  OR  "prefix": string,
//!                                  //   "reason": string,
//!                                  //   "expires": string | null,  // YYYY-MM-DD
//!                                  //   "column": string }  // only if set
//!   "samples": {                   // one key per rule with >=1 finding,
//!     "<rule code>": [             // keys unordered (plain JSON object);
//!       {                         // each list is best-first (severity
//!         "key": string,          // desc, size desc, key asc)
//!         "key_truncated": bool,  // whether key was cut to 1,024 bytes;
//!                                 // never true for S3, whose keys are at
//!                                 // most 1,024 bytes, but kept for future
//!                                 // sources with longer names
//!         "severity": string,
//!         "size": integer,
//!         "storage_class": string,
//!         "last_modified": string, // RFC 3339
//!         "column": string,        // PII rules only: the column path,
//!                                  // at most 256 bytes
//!         "confidence": string,    // PII rules only: Confidence::code()
//!         "evidence": string,      // PII rules only: "values", or
//!                                  // "column-name" when the finding rests
//!                                  // on the column's name alone (always
//!                                  // for person names and dates of birth)
//!         "matched": integer,      // evidence "values" only: cleaned
//!         "sampled": integer,      //   sampled values that matched / in all
//!         "reason": string         // content-not-scanned only:
//!                                  // NotScannedReason::code()
//!       }
//!     ]
//!   },
//!   "largest_objects": [           // up to 20, size desc, then key asc
//!     { "key": string, "key_truncated": bool, "size": integer,
//!       "storage_class": string, "last_modified": string }
//!                                  // a sample's object fields: no finding,
//!                                  // so no severity and no detail
//!   ],
//!   "size_histogram": [            // non-empty buckets only, ascending
//!     { "lower": integer, "upper": integer | null, "count": integer, "bytes": integer }
//!   ],
//!   "age_histogram": [             // non-empty buckets only, ascending
//!     { "lower_seconds": integer, "upper_seconds": integer | null,
//!       "count": integer, "bytes": integer }
//!   ],
//!   "distinct_content": {
//!     "estimate": number,           // clamped to object_count
//!     "duplicate_lower_bound": number,
//!     "duplicates_significant": bool  // Aggregates::duplicates_significant:
//!                                     // the bound is non-zero and at least
//!                                     // 2% of object_count; below that it
//!                                     // is within estimator error
//!   }
//! }
//! ```
//!
//! A sample never carries a sampled value: only the column path and
//! counts. The findings stream (`--findings`) carries the same optional
//! fields per record.
//!
//! Some values appear twice, and always agree (`report::json`'s tests
//! check each): `coverage.files_eligible` equals `content.files_eligible`;
//! `coverage.files_scanned` equals `content.scanned_whole` plus
//! `content.scanned_partially`; and each table's `files_not_scanned`
//! equals its `files_eligible` minus its `files_scanned`.
//!
//! Severities are rendered via [`crate::model::Severity::code`], storage
//! classes via [`crate::model::StorageClass::as_wire`], rules via
//! [`crate::model::RuleId::code`], every byte count as an exact integer, and
//! every timestamp as RFC 3339 (see the `rfc3339` submodule). [`Format::Text`]
//! carries the identical information in a human-readable layout; see
//! `text`'s module doc for its section order.

mod csv;
mod escape;
mod findings;
#[cfg(test)]
mod fixture;
mod html;
mod human_size;
mod json;
mod rfc3339;
mod sink;
mod style;
mod text;

use std::io::Write;
use std::time::{Duration, SystemTime};

pub(crate) use escape::escaped;
pub use findings::FindingsWriter;
use sink::Sink;
pub use style::Style;

use crate::aggregate::{Aggregates, Status};
use crate::content::{MAX_ROW_GROUPS, MAX_VALUES_PER_ROW_GROUP, Sniff};
use crate::error::{ExitCode, LakeScanError};
use crate::model::Severity;
use crate::suppress::{Fingerprint, Outcome};

/// This build's name and version, for the report's `tool` section —
/// `env!` constants from `Cargo.toml`, not configuration: there is exactly
/// one tool and one version per build.
const TOOL_NAME: &str = env!("CARGO_PKG_NAME");
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// How content is inspected, in every mode, as every format states it.
pub(crate) const SAMPLING_METHOD: &str = "sampled: the dictionary and first data page of each \
     column in up to 3 row groups, at most 2,000 values per column per row group; files read \
     whole are downloaded whole but sampled the same way";

const _: () = assert!(MAX_ROW_GROUPS == 3 && MAX_VALUES_PER_ROW_GROUP == 2000);

/// Content-scanning settings for one run: `--pii` and the flags it enables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PiiSettings {
    /// `--pii-whole-file-max`.
    pub whole_file_max: u64,
    /// `--pii-sniff`.
    pub sniff: Sniff,
    /// `--coalesce-gap`.
    pub coalesce_gap: u64,
    /// `--concurrency`.
    pub concurrency: usize,
    /// `--memory-budget`.
    pub memory_budget: u64,
}

/// What a run was asked to do, recorded in every report so a result is
/// read with the settings that produced it. Never the config file's path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScanSettings {
    /// Content scanning and its settings; `None` without `--pii`.
    pub pii: Option<PiiSettings>,
    /// `--fail-on`; `None` for `none`.
    pub fail_on: Option<Severity>,
    /// The `--config` file's fingerprint, if one was given.
    pub config: Option<Fingerprint>,
}

impl ScanSettings {
    /// The one line the text summary and the HTML report show. `prefix`
    /// is bucket-derived in effect (it names keys): the caller escapes it
    /// with the rest of the line.
    pub(crate) fn line(&self, prefix: Option<&str>) -> String {
        let mut parts = Vec::new();
        match &self.pii {
            Some(pii) => parts.push(format!(
                "pii=on whole-file-max={} sniff={} coalesce-gap={} concurrency={} memory-budget={}",
                pii.whole_file_max,
                pii.sniff.code(),
                pii.coalesce_gap,
                pii.concurrency,
                pii.memory_budget
            )),
            None => parts.push("pii=off".to_owned()),
        }
        parts.push(format!(
            "fail-on={}",
            self.fail_on.map_or("none", Severity::code)
        ));
        parts.push(format!("prefix={}", prefix.unwrap_or("(none)")));
        parts.push(match &self.config {
            Some(config) => format!(
                "config=sha256:{} ({})",
                config.sha256,
                text::counted(
                    u64::try_from(config.entries).unwrap_or(u64::MAX),
                    "entry",
                    "entries"
                )
            ),
            None => "config=(none)".to_owned(),
        });
        parts.join(" ")
    }
}

/// What a report's header describes about the scan that produced it.
///
/// The driver fills this in from what it already knows (the target, when
/// the scan started, how long it took); the reporter only prints it, never
/// computes any of these fields itself.
#[derive(Debug, Clone)]
pub struct ScanInfo {
    /// The bucket that was scanned.
    pub bucket: String,
    /// The key prefix the scan was scoped to, if any.
    pub prefix: Option<String>,
    /// When the scan started.
    pub started_at: SystemTime,
    /// How long the scan took, start to finish.
    pub elapsed: Duration,
    /// The `--config` entries that expired or went unused during this
    /// scan; empty without `--config`.
    pub suppressions: Outcome,
    /// The settings the scan ran with.
    pub settings: ScanSettings,
}

/// Which shape [`write_summary`] renders: machine-readable or human-readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Plain text, for a human reading a terminal.
    Text,
    /// One JSON object; see this module's doc for the schema.
    Json,
}

/// Renders the complete whole-bucket summary once, in `format`.
///
/// Wraps `out` in a 64 KB [`std::io::BufWriter`] and writes directly into
/// it; the report is never materialized as a `String` or `Vec` first. The
/// buffer is flushed explicitly before returning, and a flush error is
/// reported like any other write error — [`std::io::BufWriter`]'s `Drop`
/// would otherwise discard it silently.
///
/// If `out` reports [`std::io::ErrorKind::BrokenPipe`] (the reader went
/// away) at any point, writing stops there and this still returns `Ok`:
/// a closed reader is not a failure of the scan.
///
/// # Errors
/// Returns [`LakeScanError::Report`] for any write or flush error other
/// than a broken pipe.
pub fn write_summary<W: Write>(
    out: W,
    format: Format,
    info: &ScanInfo,
    aggregates: &Aggregates,
) -> Result<(), LakeScanError> {
    write_summary_styled(out, format, info, aggregates, Style::PLAIN, false)
}

/// [`write_summary`] with `style` applied to the text format's own words
/// (headings, severity words, the `UNDOCUMENTED` / `documented` labels).
/// Bucket-derived text is never styled, and [`Format::Json`] ignores
/// `style` and `compact`: a machine-readable summary has no colour and is
/// always complete. With `compact`, the text format leaves out its samples,
/// largest objects, histograms and duplicate estimate, and says so in one
/// line; findings, coverage and the PII inventory are always written.
///
/// # Errors
/// As [`write_summary`].
pub fn write_summary_styled<W: Write>(
    out: W,
    format: Format,
    info: &ScanInfo,
    aggregates: &Aggregates,
    style: Style,
    compact: bool,
) -> Result<(), LakeScanError> {
    let mut sink = Sink::new(out);
    match format {
        Format::Text => text::write(&mut sink, info, aggregates, style, compact)?,
        Format::Json => json::write(&mut sink, info, aggregates)?,
    }
    sink.flush().map_err(LakeScanError::Report)
}

/// Writes the PII inventory in `aggregates` as CSV (`--inventory`); see
/// the `csv` submodule for the format and its formula-injection
/// neutralization. Behind the same 64 KB buffer as [`write_summary`], with
/// the same broken-pipe rule.
///
/// # Errors
/// Returns [`LakeScanError::Report`] for any write or flush error other
/// than a broken pipe.
pub fn write_inventory_csv<W: Write>(
    out: W,
    info: &ScanInfo,
    aggregates: &Aggregates,
) -> Result<(), LakeScanError> {
    let mut sink = Sink::new(out);
    csv::write(&mut sink, &info.suppressions, aggregates)?;
    sink.flush().map_err(LakeScanError::Report)
}

/// Writes the HTML dashboard (`--html`) for a run ending with `code`. The
/// page is the compiled-in dashboard with this run's JSON substituted for
/// its fixture; see the `html` submodule. Behind the same 64 KB buffer as
/// [`write_summary`], with the same broken-pipe rule.
///
/// # Errors
/// Returns [`LakeScanError::Report`] for any write or flush error other
/// than a broken pipe.
pub fn write_html<W: Write>(
    out: W,
    info: &ScanInfo,
    aggregates: &Aggregates,
    code: ExitCode,
) -> Result<(), LakeScanError> {
    let mut sink = Sink::new(out);
    html::write(&mut sink, info, aggregates, code)?;
    sink.flush().map_err(LakeScanError::Report)
}

/// The strict RFC 4180 reader the CSV tests use, for tests elsewhere.
#[cfg(test)]
pub(crate) fn parse_csv(text: &str) -> Option<Vec<Vec<String>>> {
    csv::parse(text)
}

/// The expiry date of the suppression entry that documents an inventory
/// entry with `status`, if it is documented and the entry expires.
fn expiry_of(status: Status, suppressions: &Outcome) -> Option<crate::suppress::Date> {
    match status {
        Status::Undocumented => None,
        Status::Documented { entry } => suppressions.expires.get(entry).copied().flatten(),
    }
}

/// An inventory entry's status as every format spells it: `"UNDOCUMENTED"`,
/// or `"documented"` with the reason of the suppression entry that
/// documents it (from `suppressions`, by index).
fn status_of(status: Status, suppressions: &Outcome) -> (&'static str, Option<&str>) {
    match status {
        Status::Undocumented => ("UNDOCUMENTED", None),
        Status::Documented { entry } => (
            "documented",
            Some(suppressions.reasons.get(entry).map_or("", String::as_str)),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use super::{Format, write_summary};
    use crate::error::LakeScanError;
    use crate::report::fixture;

    /// A writer that always fails with `kind`, starting from the very
    /// first byte.
    struct AlwaysFails(io::ErrorKind);

    impl Write for AlwaysFails {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(self.0))
        }
    }

    #[test]
    fn a_broken_pipe_returns_ok() {
        let result = write_summary(
            AlwaysFails(io::ErrorKind::BrokenPipe),
            Format::Text,
            &fixture::scan_info(),
            &fixture::aggregates(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn a_non_broken_pipe_error_returns_report() {
        let result = write_summary(
            AlwaysFails(io::ErrorKind::PermissionDenied),
            Format::Json,
            &fixture::scan_info(),
            &fixture::aggregates(),
        );
        assert!(matches!(result, Err(LakeScanError::Report(_))));
    }

    /// The objects whose keys are codes rather than field names, by path
    /// (`[]` for any list element), and the placeholder the schema doc
    /// writes for them.
    const CODE_MAPS: [(&str, &str); 6] = [
        ("content.not_scanned", "\"not-parquet\": integer"),
        (
            "content.columns_not_examined",
            "\"unsupported-type\": integer",
        ),
        (
            "coverage.columns_not_examined.by_reason",
            "\"<not-examined reason code>\"",
        ),
        ("pii_inventory.tables.[].not_scanned", "\"<reason code>\""),
        (
            "pii_inventory.tables.[].columns_not_examined.by_reason",
            "\"<not-examined reason code>\"",
        ),
        ("samples", "\"<rule code>\""),
    ];

    /// Every object key anywhere in `value`, with the path of the object
    /// holding it.
    fn collect_keys(value: &serde_json::Value, path: &str, out: &mut Vec<(String, String)>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    out.push((path.to_owned(), key.clone()));
                    let child_path = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    collect_keys(child, &child_path, out);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    collect_keys(item, &format!("{path}.[]"), out);
                }
            }
            _ => {}
        }
    }

    /// Whether `value` is a non-empty object or list.
    fn filled(value: Option<&serde_json::Value>) -> bool {
        match value {
            Some(serde_json::Value::Object(map)) => !map.is_empty(),
            Some(serde_json::Value::Array(items)) => !items.is_empty(),
            _ => false,
        }
    }

    /// The text after the first `start` in `text`, up to the next `end`.
    fn section<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
        let from = text
            .find(start)
            .map_or(text, |at| text.get(at..).unwrap_or(""));
        let body = from.get(start.len()..).unwrap_or("");
        body.find(end).and_then(|at| body.get(..at)).unwrap_or(body)
    }

    /// Drift guard: every key the JSON summary can carry is documented, in
    /// README.md's "JSON output" section (as `` `key` ``) and in this
    /// module's schema block (as `"key"`). Keys of the maps keyed by codes
    /// (`CODE_MAPS`) are rule or reason codes: those must be documented
    /// anywhere in README.md, and the schema shows their placeholder.
    #[test]
    fn every_json_summary_key_is_documented() -> Result<(), Box<dyn std::error::Error>> {
        let readme_all = include_str!("../../README.md");
        let readme = section(readme_all, "\n## JSON output\n", "\n## ");
        let source = include_str!("mod.rs");
        let schema = section(source, "//! # JSON summary schema", "//! ```\n//!\n");
        assert!(
            schema.contains("\"schema_version\""),
            "schema block not found"
        );

        let mut buf = Vec::new();
        write_summary(
            &mut buf,
            Format::Json,
            &fixture::scan_info(),
            &fixture::aggregates(),
        )?;
        let value: serde_json::Value = serde_json::from_slice(&buf)?;

        // The fixture must populate every section, or keys could hide.
        for pointer in [
            "/content",
            "/coverage",
            "/pii_inventory/summary",
            "/pii_inventory/tables",
            "/suppressions/expired",
            "/suppressions/unused",
            "/findings",
            "/samples",
            "/largest_objects",
            "/size_histogram",
            "/age_histogram",
        ] {
            assert!(
                filled(value.pointer(pointer)),
                "the report fixture leaves {pointer} empty"
            );
        }
        let tables = value
            .pointer("/pii_inventory/tables")
            .and_then(serde_json::Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        for field in ["columns", "not_scanned"] {
            assert!(
                tables.iter().any(|table| filled(table.get(field))),
                "the report fixture has no table with {field}"
            );
        }

        let mut keys = Vec::new();
        collect_keys(&value, "", &mut keys);
        let mut missing = Vec::new();
        for (parent, key) in &keys {
            if let Some((_, placeholder)) = CODE_MAPS.iter().find(|(path, _)| path == parent) {
                if !readme_all.contains(&format!("`{key}`")) {
                    missing.push(format!("README.md: code `{key}` (in {parent})"));
                }
                if !schema.contains(placeholder) && !schema.contains(&format!("\"{key}\"")) {
                    missing.push(format!("schema doc: \"{key}\" (in {parent})"));
                }
                continue;
            }
            if !readme.contains(&format!("`{key}`")) {
                missing.push(format!("README.md JSON output: `{key}` (in {parent:?})"));
            }
            if !schema.contains(&format!("\"{key}\"")) {
                missing.push(format!("schema doc: \"{key}\" (in {parent:?})"));
            }
        }
        missing.sort();
        missing.dedup();
        assert!(
            missing.is_empty(),
            "undocumented JSON keys:\n{}",
            missing.join("\n")
        );
        Ok(())
    }

    #[test]
    fn both_formats_succeed_against_an_ordinary_sink() {
        let mut buf = Vec::new();
        assert!(
            write_summary(
                &mut buf,
                Format::Text,
                &fixture::scan_info(),
                &fixture::aggregates()
            )
            .is_ok()
        );

        let mut buf = Vec::new();
        assert!(
            write_summary(
                &mut buf,
                Format::Json,
                &fixture::scan_info(),
                &fixture::aggregates()
            )
            .is_ok()
        );
    }
}
