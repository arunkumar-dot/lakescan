//! The plain-text summary writer.
//!
//! Section order, always: header, verdict, inventory, findings, content,
//! coverage, PII inventory, suppressions, samples (per rule), largest
//! objects, size histogram, age histogram, distinct-content. A section with
//! nothing to list says so in one line, except content, coverage and the
//! PII inventory, which are omitted entirely unless content scanning
//! (`--pii`) was on, and suppressions, which is omitted entirely unless
//! some `--config` entry expired or went unused. A PII rule's byte totals
//! print as `-`: its findings are about columns, so bytes do not apply.
//! A rule's findings print one
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
use super::{ScanInfo, TOOL_NAME, TOOL_VERSION, status_of};
use crate::aggregate::{
    Aggregates, InventoryEntry, MAX_ENTRIES, MAX_TABLES, Sample, SampleDetail, Table, TableStatus,
};
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

    // Bytes, or `-` for a PII rule, whose findings are about columns.
    let bytes = |rule: RuleId, bytes: u64| {
        if rule.is_pii() {
            "-".to_owned()
        } else {
            human_bytes(bytes)
        }
    };
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
                bytes(rule, cell.bytes)
            )?;
        }
        let suppressed = aggregates.suppressed(rule);
        if suppressed.count > 0 {
            wl!(
                out,
                "    suppressed: {} ({})",
                suppressed.count,
                bytes(rule, suppressed.bytes)
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
        "  columns skipped:    {} (repeated={}, unsupported-type={}, page-too-large={}, unreadable={}, unsupported-codec={})",
        content.columns_skipped(),
        content.skipped_repeated,
        content.skipped_unsupported_type,
        content.skipped_page_too_large,
        content.skipped_unreadable,
        content.skipped_unsupported_codec
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

fn write_coverage<W: Write>(out: &mut W, aggregates: &Aggregates) -> Result<(), LakeScanError> {
    let Some(coverage) = aggregates.coverage() else {
        return Ok(());
    };
    wl!(out, "COVERAGE")?;
    wl!(out, "  parquet files:  {}", coverage.files_eligible)?;
    let percent = coverage
        .percent
        .map_or_else(|| "n/a".to_owned(), |percent| format!("{percent:.1}%"));
    wl!(
        out,
        "  scanned:        {} ({percent})",
        coverage.files_scanned
    )?;
    wl!(
        out,
        "  not scanned:    {} documented, {} undocumented",
        coverage.not_scanned_suppressed,
        coverage.not_scanned_unsuppressed
    )?;
    wl_empty!(out)
}

/// One table's heading: its name, file counts, and its unscanned files by
/// reason, documented or not.
fn write_table_heading<W: Write>(out: &mut W, table: &Table) -> Result<(), LakeScanError> {
    w!(out, "  ")?;
    if table.name().is_empty() {
        w!(out, "(bucket root)")?;
    } else {
        write_escaped(out, table.name()).map_err(LakeScanError::Report)?;
    }
    w!(
        out,
        "  files: {} scanned, {} not scanned",
        table.files_scanned,
        table.files_not_scanned()
    )?;
    let reasons: Vec<String> = NotScannedReason::ALL
        .into_iter()
        .flat_map(|reason| {
            [
                (table.not_scanned_unsuppressed(reason), "undocumented"),
                (table.not_scanned_suppressed(reason), "documented"),
            ]
            .into_iter()
            .filter(|&(count, _)| count > 0)
            .map(move |(count, state)| format!("{}={count} {state}", reason.code()))
        })
        .collect();
    if !reasons.is_empty() {
        w!(out, " ({})", reasons.join(", "))?;
    }
    wl_empty!(out)?;
    if let Some(key) = table.example_key() {
        w!(out, "    example: ")?;
        write_escaped(out, key).map_err(LakeScanError::Report)?;
        wl_empty!(out)?;
    }
    Ok(())
}

/// `"1 <one>"` or `"N <many>"`.
pub(super) fn counted(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// `"1 file"` or `"N files"`.
pub(super) fn files(n: u64) -> String {
    counted(n, "file", "files")
}

/// An undocumented row's file counts, non-zero ones only: `"4 files
/// confirmed"`, `"3 files confirmed, 1 likely"`, `"2 files likely, 1
/// suppressed"`.
pub(super) fn undocumented_counts(entry: &InventoryEntry) -> String {
    let parts: Vec<(u64, &str)> = [
        (entry.files_confirmed, "confirmed"),
        (entry.files_likely, "likely"),
        (entry.files_possible, "possible"),
        (entry.files_suppressed, "suppressed"),
    ]
    .into_iter()
    .filter(|&(count, _)| count > 0)
    .collect();
    parts
        .iter()
        .enumerate()
        .map(|(index, &(count, label))| {
            if index == 0 {
                format!("{} {label}", files(count))
            } else {
                format!("{count} {label}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn write_entry_row<W: Write>(
    out: &mut W,
    info: &ScanInfo,
    entry: &InventoryEntry,
) -> Result<(), LakeScanError> {
    w!(out, "    ")?;
    write_escaped(out, entry.column()).map_err(LakeScanError::Report)?;
    w!(
        out,
        "  {}  {}  evidence={}  ",
        entry.rule().code(),
        entry.highest_confidence().code(),
        entry.evidence().code()
    )?;
    match status_of(entry.status(), &info.suppressions) {
        (status, Some(reason)) => {
            // Documented: every file's finding was suppressed, so the
            // count is all of them.
            w!(out, "{}, {status}: ", files(entry.files()))?;
            write_escaped(out, reason).map_err(LakeScanError::Report)?;
            wl_empty!(out)
        }
        (status, None) => wl!(out, "{}  {status}", undocumented_counts(entry)),
    }
}

fn write_pii_inventory<W: Write>(
    out: &mut W,
    info: &ScanInfo,
    aggregates: &Aggregates,
) -> Result<(), LakeScanError> {
    let Some(inventory) = aggregates.pii_inventory() else {
        return Ok(());
    };
    wl!(out, "PII INVENTORY")?;
    let summary = inventory.summary();
    let gaps = if summary.tables_not_fully_scanned > 0 {
        format!(
            " ({} documented)",
            summary.tables_not_fully_scanned_documented
        )
    } else {
        String::new()
    };
    wl!(
        out,
        "  {} with PII, {}: {} undocumented (action needed), {} documented. {} not fully \
         scanned{gaps}.",
        counted(summary.tables_with_pii, "table", "tables"),
        counted(summary.pii_columns, "PII column", "PII columns"),
        summary.undocumented,
        summary.documented,
        counted(summary.tables_not_fully_scanned, "table", "tables"),
    )?;
    if inventory.tables().is_empty() {
        wl!(out, "  no Parquet files")?;
    }
    for table in inventory.tables() {
        write_table_heading(out, table)?;
        match table.status() {
            TableStatus::PiiFound => {
                for entry in table.entries_for_review() {
                    write_entry_row(out, info, entry)?;
                }
            }
            // Never "no PII found" about files that were not read.
            TableStatus::NoPiiInScannedFiles => {
                let scanned = table.files_scanned;
                let noun = if scanned == 1 { "file" } else { "files" };
                w!(out, "    no PII found in {scanned} scanned {noun}")?;
                if table.files_not_scanned() > 0 {
                    w!(out, "; {} not scanned", table.files_not_scanned())?;
                }
                wl_empty!(out)?;
            }
            TableStatus::NotScanned => wl!(out, "    not scanned: PII unknown")?,
        }
    }
    if inventory.truncated() {
        wl!(
            out,
            "  truncated: {} files and {} findings left out over the caps ({MAX_TABLES} tables, \
             {MAX_ENTRIES} entries); scan a narrower prefix to see them",
            inventory.left_out_files(),
            inventory.left_out_findings()
        )?;
    }
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
    write_coverage(out, aggregates)?;
    write_pii_inventory(out, info, aggregates)?;
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

    /// One observed file: `(key, outcome, suppressed, findings)`, each
    /// finding `(column, confidence, suppression)`.
    type TestFile<'a> = (
        &'a str,
        crate::content::FileOutcome,
        bool,
        &'a [(&'a str, crate::model::Confidence, Option<usize>)],
    );

    /// Renders the PII INVENTORY section for `files`, observed directly.
    fn inventory_section(files: &[TestFile<'_>]) -> Result<String, Box<dyn std::error::Error>> {
        use crate::model::{ColumnDetail, Detail, Evidence, Finding, ObjectMeta, RuleId, Severity};
        let now = fixture::now();
        let mut aggregates = crate::aggregate::Aggregates::new(now);
        aggregates.enable_content();
        for (key, outcome, suppressed, findings) in files {
            let object = ObjectMeta {
                key: (*key).to_owned(),
                size: 100,
                last_modified: now,
                etag: "e".to_owned(),
                storage_class: crate::model::StorageClass::Standard,
            };
            for (column, confidence, suppression) in *findings {
                let detail = ColumnDetail::new(
                    column,
                    *confidence,
                    Evidence::Values {
                        matched: 30,
                        sampled: 30,
                    },
                );
                let finding = Finding {
                    rule: RuleId::PiiEmail,
                    severity: Severity::High,
                    object: &object,
                    detail: Detail::Column(&detail),
                };
                match suppression {
                    Some(entry) => aggregates.observe_suppressed(finding, *entry),
                    None => aggregates.observe_finding(finding),
                }
            }
            let scan = crate::content::FileScan {
                outcome: *outcome,
                columns: Vec::new(),
                stats: crate::content::FileStats::default(),
            };
            aggregates.observe_content(&object, &scan, *suppressed);
        }
        let mut info = fixture::scan_info();
        info.suppressions.reasons = vec!["Consented, DPA-12".to_owned()];
        let mut buf = Vec::new();
        super::write_pii_inventory(&mut buf, &info, &aggregates)?;
        Ok(String::from_utf8(buf)?)
    }

    #[test]
    fn the_inventory_never_claims_more_than_was_read() -> Result<(), Box<dyn std::error::Error>> {
        use crate::content::FileOutcome::{NotScanned, ScannedWhole};
        use crate::model::Confidence::{Confirmed, Likely};
        use crate::model::NotScannedReason::Unreadable;
        let section = inventory_section(&[
            // No file read: unknown, never "no PII found".
            ("dark/a.parquet", NotScanned(Unreadable), false, &[]),
            // Some read, nothing found, some not read.
            ("half/a.parquet", ScannedWhole, false, &[]),
            ("half/b.parquet", ScannedWhole, false, &[]),
            ("half/c.parquet", NotScanned(Unreadable), true, &[]),
            // All read, nothing found.
            ("clean/a.parquet", ScannedWhole, false, &[]),
            // PII, documented and not, with mixed confidences.
            (
                "pii/a.parquet",
                ScannedWhole,
                false,
                &[
                    ("zip", Confirmed, None),
                    ("email", Confirmed, Some(0)),
                    ("phone", Likely, None),
                ],
            ),
            (
                "pii/b.parquet",
                ScannedWhole,
                false,
                &[
                    ("zip", Likely, None),
                    ("email", Confirmed, Some(0)),
                    ("phone", Likely, Some(0)),
                ],
            ),
        ])?;
        assert_eq!(
            section,
            "PII INVENTORY\n\
             \x20 1 table with PII, 3 PII columns: 2 undocumented (action needed), 1 documented. \
             2 tables not fully scanned (1 documented).\n\
             \x20 clean  files: 1 scanned, 0 not scanned\n\
             \x20   no PII found in 1 scanned file\n\
             \x20 dark  files: 0 scanned, 1 not scanned (unreadable=1 undocumented)\n\
             \x20   not scanned: PII unknown\n\
             \x20 half  files: 2 scanned, 1 not scanned (unreadable=1 documented)\n\
             \x20   no PII found in 2 scanned files; 1 not scanned\n\
             \x20 pii  files: 2 scanned, 0 not scanned\n\
             \x20   example: pii/a.parquet\n\
             \x20   phone  pii-email  likely  evidence=values  1 file likely, 1 suppressed  \
             UNDOCUMENTED\n\
             \x20   zip  pii-email  confirmed  evidence=values  1 file confirmed, 1 likely  \
             UNDOCUMENTED\n\
             \x20   email  pii-email  confirmed  evidence=values  2 files, documented: \
             Consented, DPA-12\n\
             \n"
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
