//! The plain-text summary writer.
//!
//! Section order, always: header, verdict, inventory, findings, content,
//! suppressions, samples (per rule), largest objects, size histogram, age
//! histogram, distinct-content. A section with nothing to list says so in
//! one line, except content, which is omitted entirely unless content
//! scanning (`--pii`) was on, and suppressions, which is omitted entirely
//! unless some `--config` entry expired or went unused. A rule's findings print one
//! line per severity it actually raised, worst first, and skip the rest —
//! a rule with a single High finding is one line, not a zero-padded row
//! across every severity — followed by its suppressed count when it has
//! any. A rule whose findings were all suppressed is still listed, with
//! only that line.
//!
//! No color, no box-drawing: this is meant to be `grep`-able and safe to
//! pipe. Every object key and every Parquet column path is
//! attacker-controlled, so each is written through [`write_escaped`], which
//! renders control and bidi-override characters as `\u{XXXX}` instead of
//! letting them reach the terminal (see `escape`'s module doc).

use std::io::Write;

use super::escape::write_escaped;
use super::human_size::human_bytes;
use super::rfc3339::format_rfc3339;
use super::{ScanInfo, TOOL_NAME, TOOL_VERSION};
use crate::aggregate::{Aggregates, Sample, SampleDetail};
use crate::error::LakeScanError;
use crate::model::{Evidence, NotScannedReason, RuleId, Severity};
use crate::suppress::{Entry, Pattern};

/// `write!`/`writeln!` to `out`, mapping any I/O error to
/// [`LakeScanError::Report`] — every text-writing call in this file goes
/// through one of these two so the error handling never has to be spelled
/// out twice.
macro_rules! w {
    ($out:expr, $($arg:tt)*) => {
        write!($out, $($arg)*).map_err(LakeScanError::Report)
    };
}
macro_rules! wl {
    ($out:expr, $($arg:tt)*) => {
        writeln!($out, $($arg)*).map_err(LakeScanError::Report)
    };
}
macro_rules! wl_empty {
    ($out:expr) => {
        writeln!($out).map_err(LakeScanError::Report)
    };
}

/// `{secs}.{millis:03}s`, integer arithmetic only.
fn human_duration(elapsed: std::time::Duration) -> String {
    format!("{}.{:03}s", elapsed.as_secs(), elapsed.subsec_millis())
}

fn write_key<W: Write>(out: &mut W, sample: &Sample) -> Result<(), LakeScanError> {
    write_escaped(out, &sample.key).map_err(LakeScanError::Report)?;
    if sample.key_truncated {
        w!(out, "…")?;
    }
    Ok(())
}

fn write_header<W: Write>(out: &mut W, info: &ScanInfo) -> Result<(), LakeScanError> {
    wl!(out, "{TOOL_NAME} {TOOL_VERSION}")?;
    w!(out, "s3://{}", info.bucket)?;
    if let Some(prefix) = &info.prefix {
        w!(out, "/{prefix}")?;
    }
    wl_empty!(out)?;
    wl!(out, "started:  {}", format_rfc3339(info.started_at))?;
    wl!(out, "elapsed:  {}", human_duration(info.elapsed))?;
    wl_empty!(out)
}

fn write_verdict<W: Write>(out: &mut W, aggregates: &Aggregates) -> Result<(), LakeScanError> {
    wl!(out, "VERDICT")?;
    match aggregates.worst_severity() {
        Some(severity) => wl!(out, "  worst severity: {}", severity.code())?,
        None => wl!(out, "  no findings")?,
    }
    wl_empty!(out)
}

fn write_inventory<W: Write>(out: &mut W, aggregates: &Aggregates) -> Result<(), LakeScanError> {
    wl!(out, "INVENTORY")?;
    wl!(out, "  objects:     {}", aggregates.total_objects())?;
    wl!(
        out,
        "  total bytes: {} ({})",
        aggregates.total_bytes(),
        human_bytes(aggregates.total_bytes())
    )?;

    let classes: Vec<(&str, u64, u64)> = aggregates
        .nonzero_storage_classes()
        .map(|(name, stats)| (name, stats.count, stats.bytes))
        .collect();

    if classes.is_empty() {
        return wl_empty!(out);
    }

    wl!(out, "  by storage class:")?;
    for (name, count, bytes) in &classes {
        wl!(
            out,
            "    {name:<24} count={count:<10} bytes={bytes} ({})",
            human_bytes(*bytes)
        )?;
    }
    wl_empty!(out)
}

fn write_findings<W: Write>(out: &mut W, aggregates: &Aggregates) -> Result<(), LakeScanError> {
    wl!(out, "FINDINGS")?;

    let rows: Vec<RuleId> = RuleId::ALL
        .into_iter()
        .filter(|&rule| {
            aggregates.suppressed(rule).count > 0
                || Severity::ALL
                    .into_iter()
                    .any(|severity| aggregates.matrix_cell(rule, severity).count > 0)
        })
        .collect();

    if rows.is_empty() {
        wl!(out, "  no findings")?;
        return wl_empty!(out);
    }

    for rule in rows {
        wl!(out, "  {} - {}", rule.code(), rule.title())?;
        // Worst severity first; skip any severity this rule never raised,
        // so a rule with one High finding shows exactly one line, not four
        // zero lines plus the one that matters.
        for severity in Severity::ALL.into_iter().rev() {
            let cell = aggregates.matrix_cell(rule, severity);
            if cell.count == 0 {
                continue;
            }
            wl!(
                out,
                "    {}: {} ({})",
                severity.code(),
                cell.count,
                human_bytes(cell.bytes)
            )?;
        }
        let suppressed = aggregates.suppressed(rule);
        if suppressed.count > 0 {
            wl!(
                out,
                "    suppressed: {} ({})",
                suppressed.count,
                human_bytes(suppressed.bytes)
            )?;
        }
    }
    wl_empty!(out)
}

/// One `--config` entry: rule, key or prefix (escaped, like any key), the
/// expiry date if it has one, and the reason (escaped too: it is free text
/// from a file).
fn write_entry<W: Write>(out: &mut W, entry: &Entry) -> Result<(), LakeScanError> {
    w!(out, "    {}  ", entry.rule.code())?;
    let (label, value) = match &entry.pattern {
        Pattern::Key(key) => ("key", key),
        Pattern::Prefix(prefix) => ("prefix", prefix),
    };
    w!(out, "{label}=")?;
    if value.is_empty() {
        // Spelled out: a bare `prefix=` would read as a formatting slip.
        w!(out, "\"\" (every key)")?;
    } else {
        write_escaped(out, value).map_err(LakeScanError::Report)?;
    }
    if let Some(column) = &entry.column {
        w!(out, "  column=")?;
        write_escaped(out, column).map_err(LakeScanError::Report)?;
    }
    if let Some(expires) = entry.expires {
        w!(out, "  expires={expires}")?;
    }
    w!(out, "  reason: ")?;
    write_escaped(out, &entry.reason).map_err(LakeScanError::Report)?;
    wl_empty!(out)
}

fn write_content<W: Write>(out: &mut W, aggregates: &Aggregates) -> Result<(), LakeScanError> {
    let Some(content) = aggregates.content() else {
        return Ok(());
    };
    wl!(out, "CONTENT")?;
    wl!(out, "  parquet files:      {}", content.files_eligible)?;
    wl!(out, "    scanned whole:     {}", content.scanned_whole)?;
    wl!(out, "    scanned partially: {}", content.scanned_partially)?;
    w!(
        out,
        "    not scanned:       {}",
        content.not_scanned_total()
    )?;
    let reasons: Vec<String> = NotScannedReason::ALL
        .into_iter()
        .filter(|&reason| content.not_scanned(reason) > 0)
        .map(|reason| format!("{}={}", reason.code(), content.not_scanned(reason)))
        .collect();
    if reasons.is_empty() {
        wl_empty!(out)?;
    } else {
        wl!(out, " ({})", reasons.join(", "))?;
    }
    wl!(out, "  columns examined:   {}", content.columns_examined)?;
    wl!(
        out,
        "  columns skipped:    {} (repeated={}, unsupported-type={}, page-too-large={}, unreadable={})",
        content.columns_skipped(),
        content.skipped_repeated,
        content.skipped_unsupported_type,
        content.skipped_page_too_large,
        content.skipped_unreadable
    )?;
    wl!(
        out,
        "  bytes read:         {} ({})",
        content.bytes_read,
        human_bytes(content.bytes_read)
    )?;
    wl!(out, "  GET requests:       {}", content.get_requests)?;
    wl_empty!(out)
}

fn write_suppressions<W: Write>(out: &mut W, info: &ScanInfo) -> Result<(), LakeScanError> {
    let outcome = &info.suppressions;
    if outcome.expired.is_empty() && outcome.unused.is_empty() {
        return Ok(());
    }
    wl!(out, "SUPPRESSIONS")?;
    for (heading, entries) in [("expired", &outcome.expired), ("unused", &outcome.unused)] {
        if entries.is_empty() {
            continue;
        }
        wl!(out, "  {heading}:")?;
        for entry in entries {
            write_entry(out, entry)?;
        }
    }
    wl_empty!(out)
}

fn write_samples<W: Write>(out: &mut W, aggregates: &Aggregates) -> Result<(), LakeScanError> {
    wl!(out, "SAMPLES")?;
    let mut any = false;
    for rule in RuleId::ALL {
        let samples = aggregates.samples_for(rule);
        if samples.is_empty() {
            continue;
        }
        any = true;
        wl!(out, "  [{}]", rule.code())?;
        for sample in samples {
            w!(out, "    ")?;
            write_key(out, sample)?;
            match &sample.detail {
                SampleDetail::None => {}
                SampleDetail::Column(detail) => {
                    w!(out, "  column=")?;
                    write_escaped(out, &detail.column).map_err(LakeScanError::Report)?;
                    w!(out, " confidence={}", detail.confidence.code())?;
                    match detail.evidence {
                        Evidence::Values { matched, sampled } => {
                            w!(out, " evidence=values matched={matched}/{sampled}")?;
                        }
                        Evidence::ColumnName => w!(out, " evidence=column-name")?,
                    }
                }
                SampleDetail::NotScanned(reason) => w!(out, "  reason={}", reason.code())?,
            }
            let severity = sample.severity.map_or("?", Severity::code);
            wl!(
                out,
                "  severity={severity} size={} ({}) class={} modified={}",
                sample.size,
                human_bytes(sample.size),
                sample.storage_class.as_wire(),
                format_rfc3339(sample.last_modified)
            )?;
        }
    }
    if !any {
        wl!(out, "  no findings")?;
    }
    wl_empty!(out)
}

fn write_largest_objects<W: Write>(
    out: &mut W,
    aggregates: &Aggregates,
) -> Result<(), LakeScanError> {
    wl!(out, "LARGEST OBJECTS")?;
    let largest = aggregates.largest_objects();
    if largest.is_empty() {
        wl!(out, "  (none)")?;
        return wl_empty!(out);
    }
    for sample in largest {
        w!(out, "  ")?;
        write_key(out, sample)?;
        wl!(
            out,
            "  size={} ({}) class={} modified={}",
            sample.size,
            human_bytes(sample.size),
            sample.storage_class.as_wire(),
            format_rfc3339(sample.last_modified)
        )?;
    }
    wl_empty!(out)
}

fn write_size_histogram<W: Write>(
    out: &mut W,
    aggregates: &Aggregates,
) -> Result<(), LakeScanError> {
    wl!(out, "SIZE HISTOGRAM")?;
    let mut any = false;
    for index in 0..aggregates.size_bucket_count() {
        let cell = aggregates.size_bucket(index);
        if cell.count == 0 {
            continue;
        }
        any = true;
        let (lower, upper) = Aggregates::size_bucket_bounds(index);
        let range = match upper {
            Some(upper) => format!("[{lower}, {upper})"),
            None => format!("[{lower}, u64::MAX]"),
        };
        wl!(
            out,
            "  {range:<24} count={:<10} bytes={} ({})",
            cell.count,
            cell.bytes,
            human_bytes(cell.bytes)
        )?;
    }
    if !any {
        wl!(out, "  (no objects)")?;
    }
    wl_empty!(out)
}

fn write_age_histogram<W: Write>(
    out: &mut W,
    aggregates: &Aggregates,
) -> Result<(), LakeScanError> {
    wl!(out, "AGE HISTOGRAM")?;
    let mut any = false;
    for index in 0..aggregates.age_bucket_count() {
        let cell = aggregates.age_bucket(index);
        if cell.count == 0 {
            continue;
        }
        any = true;
        let (lower, upper) = Aggregates::age_bucket_bounds(index);
        let range = match upper {
            Some(upper) => format!(
                "[{}d, {}d)",
                lower.as_secs() / 86_400,
                upper.as_secs() / 86_400
            ),
            None => format!("[{}d, inf)", lower.as_secs() / 86_400),
        };
        wl!(
            out,
            "  {range:<24} count={:<10} bytes={} ({})",
            cell.count,
            cell.bytes,
            human_bytes(cell.bytes)
        )?;
    }
    if !any {
        wl!(out, "  (no objects)")?;
    }
    wl_empty!(out)
}

fn write_distinct_content<W: Write>(
    out: &mut W,
    aggregates: &Aggregates,
) -> Result<(), LakeScanError> {
    wl!(out, "DISTINCT CONTENT")?;
    w!(
        out,
        "  ~{:.0} distinct (etag, size) values across {} objects; ",
        aggregates.distinct_content_estimate(),
        aggregates.total_objects(),
    )?;
    if aggregates.duplicates_significant() {
        wl!(
            out,
            "at least ~{:.0} duplicates",
            aggregates.duplicate_lower_bound()
        )?;
    } else {
        wl!(
            out,
            "no duplicates detected (differences under ~2% are within estimator error)"
        )?;
    }
    wl!(
        out,
        "  (re-uploaded or re-encrypted content gets a new ETag and is not detected)"
    )
}

/// Writes the plain-text summary to `out`.
pub(super) fn write<W: Write>(
    out: &mut W,
    info: &ScanInfo,
    aggregates: &Aggregates,
) -> Result<(), LakeScanError> {
    write_header(out, info)?;
    write_verdict(out, aggregates)?;
    write_inventory(out, aggregates)?;
    write_findings(out, aggregates)?;
    write_content(out, aggregates)?;
    write_suppressions(out, info)?;
    write_samples(out, aggregates)?;
    write_largest_objects(out, aggregates)?;
    write_size_histogram(out, aggregates)?;
    write_age_histogram(out, aggregates)?;
    write_distinct_content(out, aggregates)
}

#[cfg(test)]
mod tests {
    use super::write;
    use crate::report::fixture;

    /// Golden file: the fixture, rendered as text, compared byte-for-byte
    /// to `tests/golden/summary.txt`. `include_str!` resolves relative to
    /// this file, so the comparison does not depend on the test runner's
    /// working directory. On mismatch, `assert_eq!` reports exactly where
    /// the two strings first diverge.
    #[test]
    fn an_empty_prefix_is_spelled_out() -> Result<(), Box<dyn std::error::Error>> {
        let entry = crate::suppress::Entry {
            rule: crate::model::RuleId::StaleStandard,
            pattern: crate::suppress::Pattern::Prefix(String::new()),
            reason: "r".to_owned(),
            expires: None,
            bucket: None,
            column: None,
        };
        let mut buf = Vec::new();
        super::write_entry(&mut buf, &entry)?;
        assert_eq!(
            String::from_utf8(buf)?,
            "    stale-standard  prefix=\"\" (every key)  reason: r\n"
        );
        Ok(())
    }

    #[test]
    fn matches_the_golden_file() -> Result<(), crate::error::LakeScanError> {
        let golden = include_str!("../../tests/golden/summary.txt");

        let mut buf = Vec::new();
        write(&mut buf, &fixture::scan_info(), &fixture::aggregates())?;
        let actual = String::from_utf8(buf).unwrap_or_default();

        assert_eq!(actual, golden);
        Ok(())
    }
}
