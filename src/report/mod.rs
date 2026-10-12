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
//!   complete snapshot, written once at the end of a scan.
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
//! `schema_version` is a frozen field: existing fields keep their meaning
//! and type across versions; a breaking change bumps it.
//!
//! ```text
//! {
//!   "schema_version": 1,
//!   "tool": { "name": string, "version": string },
//!   "scan": {
//!     "bucket": string,
//!     "prefix": string | null,
//!     "started_at": string,       // RFC 3339, UTC, seconds precision
//!     "elapsed_ms": integer
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
//!   "findings": [                  // one entry per rule with >=1 finding,
//!     {                            // in RuleId::ALL order
//!       "rule": string,            // RuleId::code()
//!       "title": string,           // RuleId::title()
//!       "counts": { "critical": integer, "high": integer, "medium": integer,
//!                   "low": integer, "info": integer },
//!       "bytes":  { "critical": integer, "high": integer, "medium": integer,
//!                   "low": integer, "info": integer }
//!     }
//!   ],
//!   "samples": {                   // one key per rule with >=1 finding,
//!     "<rule code>": [             // keys unordered (plain JSON object);
//!       {                         // each list is best-first (severity
//!         "key": string,          // desc, size desc, key asc)
//!         "key_truncated": bool,
//!         "severity": string,
//!         "size": integer,
//!         "storage_class": string,
//!         "last_modified": string  // RFC 3339
//!       }
//!     ]
//!   },
//!   "largest_objects": [ /* same shape as a sample, minus "severity" */ ],
//!   "size_histogram": [            // non-empty buckets only, ascending
//!     { "lower": integer, "upper": integer | null, "count": integer, "bytes": integer }
//!   ],
//!   "age_histogram": [             // non-empty buckets only, ascending
//!     { "lower_seconds": integer, "upper_seconds": integer | null,
//!       "count": integer, "bytes": integer }
//!   ],
//!   "distinct_content": { "estimate": number, "duplicate_lower_bound": number }
//! }
//! ```
//!
//! Severities are rendered via [`crate::model::Severity::code`], storage
//! classes via [`crate::model::StorageClass::as_wire`], rules via
//! [`crate::model::RuleId::code`], every byte count as an exact integer, and
//! every timestamp as RFC 3339 (see the `rfc3339` submodule). [`Format::Text`]
//! carries the identical information in a human-readable layout; see
//! `text`'s module doc for its section order.

mod escape;
mod findings;
#[cfg(test)]
mod fixture;
mod human_size;
mod json;
mod rfc3339;
mod sink;
mod text;

use std::io::Write;
use std::time::{Duration, SystemTime};

pub use findings::FindingsWriter;
use sink::Sink;

use crate::aggregate::Aggregates;
use crate::error::LakeScanError;

/// This build's name and version, for the report's `tool` section —
/// `env!` constants from `Cargo.toml`, not configuration: there is exactly
/// one tool and one version per build.
const TOOL_NAME: &str = env!("CARGO_PKG_NAME");
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

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
    let mut sink = Sink::new(out);
    match format {
        Format::Text => text::write(&mut sink, info, aggregates)?,
        Format::Json => json::write(&mut sink, info, aggregates)?,
    }
    sink.flush().map_err(LakeScanError::Report)
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
