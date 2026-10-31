//! The HTML report (`--html`): the interactive dashboard in
//! [`DASHBOARD`], with this run's data substituted for the fixture.
//!
//! The page is compiled in with [`include_str!`], so the file shipped is
//! the file built. It is one self-contained document (inline CSS and
//! script, no images). Opening it makes no network request.
//!
//! **No computing.** It renders what [`Aggregates`] holds and the exit
//! code the driver decided.
//!
//! **Hostile input.** Names go out through `serde_json`, the same escaping
//! as the JSON summary, and then every `<` in that JSON is written
//! `\u003c` before it is placed in the `<script>` block. A column named
//! `</script>` cannot end the block. The page's script only ever sets
//! `textContent`.

use std::io::{self, Write};
use std::time::Duration;

use serde::Serialize;

use super::rfc3339::format_rfc3339;
use super::{ScanInfo, TOOL_NAME, TOOL_VERSION, expiry_of, status_of};
use crate::aggregate::{Aggregates, SampleDetail};
use crate::error::{ExitCode, LakeScanError};
use crate::model::{NotScannedReason, RuleId, Severity};

/// The dashboard page, fixture data and all. The line that starts with
/// `const DATA = ` is replaced at runtime.
const DASHBOARD: &str = include_str!("dashboard.html");

/// The sampling caveat the dashboard shows under coverage. Fixed wording.
const CAVEAT: &str = "Inspection is sampled: up to 3 row groups, up to 2,000 values per column \
     per row group. No finding does not mean no personal data.";

/// Writes the dashboard for one run that ended with `code`.
///
/// # Errors
/// [`LakeScanError::Report`] when the dashboard has no single
/// `const DATA = ` line to fill, when the data cannot be serialized, or
/// when `out` cannot be written. A broken pipe is not an error here: the
/// caller wraps `out` in the shared [`super::sink::Sink`].
pub(super) fn write<W: Write>(
    out: &mut W,
    info: &ScanInfo,
    aggregates: &Aggregates,
    code: ExitCode,
) -> Result<(), LakeScanError> {
    let json = serde_json::to_string(&DashboardData::new(info, aggregates, code))
        .map_err(|err| LakeScanError::Report(err.into()))?;
    let json = json.replace('<', "\\u003c");
    let page = embed_data(DASHBOARD, &json)?;
    out.write_all(page.as_bytes())
        .map_err(LakeScanError::Report)
}

/// Replaces the one `const DATA = ...;` line in `template` with `json`.
fn embed_data(template: &str, json: &str) -> Result<String, LakeScanError> {
    let mut found = None;
    for line in template.lines() {
        if line.trim_start().starts_with("const DATA = ") {
            if found.is_some() {
                return Err(report_msg(
                    "dashboard HTML has more than one `const DATA = ` line",
                ));
            }
            found = Some(line);
        }
    }
    let Some(marker) = found else {
        return Err(report_msg(
            "dashboard HTML has no `const DATA = ` line to replace with the scan data",
        ));
    };
    let Some((indent, _)) = marker.split_once("const DATA = ") else {
        return Err(report_msg(
            "dashboard HTML has no `const DATA = ` line to replace with the scan data",
        ));
    };
    let replacement = format!("{indent}const DATA = {json};");
    Ok(template.replacen(marker, &replacement, 1))
}

fn report_msg(message: &str) -> LakeScanError {
    LakeScanError::Report(io::Error::new(
        io::ErrorKind::InvalidData,
        message.to_owned(),
    ))
}

/// `tenths` as a JSON number with one decimal place (`12` → `1.2`).
fn one_decimal(tenths: u64) -> f64 {
    let tenths = u32::try_from(tenths).unwrap_or(u32::MAX);
    f64::from(tenths) / 10.0
}

/// `elapsed` in seconds, rounded down to one decimal.
fn elapsed_seconds(elapsed: Duration) -> f64 {
    let millis = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    one_decimal(millis / 100)
}

fn mib(bytes: u64) -> u64 {
    bytes / 1024 / 1024
}

/// `"none"`, or `"<N> suppression entries (sha256: <12 hex chars>)"`.
fn config_line(info: &ScanInfo) -> String {
    match &info.settings.config {
        None => "none".to_owned(),
        Some(config) => {
            let prefix = match config.sha256.char_indices().nth(12) {
                Some((index, _)) => config.sha256.get(..index).unwrap_or(&config.sha256),
                None => config.sha256.as_str(),
            };
            let entries = u64::try_from(config.entries).unwrap_or(u64::MAX);
            format!("{entries} suppression entries (sha256: {prefix})")
        }
    }
}

fn reason_label(reason: NotScannedReason) -> &'static str {
    match reason {
        NotScannedReason::NotParquet => "Not a Parquet file",
        NotScannedReason::Unreadable => "Unreadable Parquet",
        NotScannedReason::AccessDenied => "Access denied",
        NotScannedReason::Encrypted => "Encrypted Parquet",
        NotScannedReason::FooterTooLarge => "Footer too large",
        NotScannedReason::NoColumnExamined => "No column examined",
        NotScannedReason::FetchFailed => "Fetch failed",
        NotScannedReason::TooManyColumns => "Too many columns",
        NotScannedReason::BudgetTimeout => "Budget timeout",
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardData<'a> {
    tool: ToolSection,
    scan: ScanSection<'a>,
    exit: ExitSection,
    summary: SummarySection,
    columns: Vec<ColumnRow<'a>>,
    unscanned: Vec<UnscannedFile<'a>>,
    coverage: CoverageSection,
    metadata_rules: Vec<MetadataRule>,
}

#[derive(Serialize)]
struct ToolSection {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanSection<'a> {
    bucket: &'a str,
    prefix: Option<&'a str>,
    started_at: String,
    elapsed_seconds: f64,
    config: String,
    settings: SettingsSection,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SettingsSection {
    pii: bool,
    concurrency: u16,
    memory_budget_mib: u64,
    whole_file_max_mib: u64,
    coalesce_gap_mib: u64,
    fail_on: &'static str,
}

#[derive(Serialize)]
struct ExitSection {
    code: u8,
    name: &'static str,
    meaning: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SummarySection {
    undocumented: u64,
    undocumented_confirmed: u64,
    undocumented_likely: u64,
    undocumented_possible: u64,
    documented: u64,
    tables_with_pii: u64,
    tables_total: u64,
    coverage_pct: f64,
    not_scanned: u64,
    not_scanned_documented: u64,
    not_scanned_undocumented: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ColumnRow<'a> {
    table: &'a str,
    column: &'a str,
    rule: &'static str,
    confidence: &'static str,
    evidence: &'static str,
    files: u64,
    files_confirmed: u64,
    files_likely: u64,
    files_possible: u64,
    files_suppressed: u64,
    status: &'static str,
    reason: Option<&'a str>,
    expires: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnscannedFile<'a> {
    key: &'a str,
    reason_code: &'static str,
    reason: &'static str,
    status: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CoverageSection {
    eligible: u64,
    scanned_whole: u64,
    scanned_partial: u64,
    not_scanned_documented: u64,
    not_scanned_undocumented: u64,
    columns_examined: u64,
    columns_skipped: ColumnsSkipped,
    caveat: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ColumnsSkipped {
    repeated: u64,
    unsupported_type: u64,
    page_too_large: u64,
    unreadable: u64,
    unsupported_codec: u64,
}

#[derive(Serialize)]
struct MetadataRule {
    rule: &'static str,
    title: &'static str,
    count: u64,
    severity: &'static str,
}

impl<'a> DashboardData<'a> {
    fn new(info: &'a ScanInfo, aggregates: &'a Aggregates, code: ExitCode) -> Self {
        let (pii, concurrency, memory_budget_mib, whole_file_max_mib, coalesce_gap_mib) =
            match &info.settings.pii {
                Some(pii) => (
                    true,
                    u16::try_from(pii.concurrency).unwrap_or(u16::MAX),
                    mib(pii.memory_budget),
                    mib(pii.whole_file_max),
                    mib(pii.coalesce_gap),
                ),
                None => (false, 0, 0, 0, 0),
            };
        let coverage = coverage_section(aggregates);
        let summary = summary_section(
            aggregates,
            coverage.not_scanned_documented,
            coverage.not_scanned_undocumented,
            coverage_pct(aggregates),
        );
        Self {
            tool: ToolSection {
                name: TOOL_NAME,
                version: TOOL_VERSION,
            },
            scan: ScanSection {
                bucket: &info.bucket,
                prefix: info.prefix.as_deref(),
                started_at: format_rfc3339(info.started_at),
                elapsed_seconds: elapsed_seconds(info.elapsed),
                config: config_line(info),
                settings: SettingsSection {
                    pii,
                    concurrency,
                    memory_budget_mib,
                    whole_file_max_mib,
                    coalesce_gap_mib,
                    fail_on: info.settings.fail_on.map_or("none", Severity::code),
                },
            },
            exit: ExitSection {
                code: u8::try_from(code.as_i32()).unwrap_or(u8::MAX),
                name: code.name(),
                meaning: code.meaning(),
            },
            summary,
            columns: columns(info, aggregates),
            unscanned: unscanned(aggregates),
            coverage,
            metadata_rules: metadata_rules(aggregates),
        }
    }
}

fn coverage_pct(aggregates: &Aggregates) -> f64 {
    aggregates
        .coverage()
        .and_then(|coverage| coverage.percent)
        .unwrap_or(0.0)
}

fn summary_section(
    aggregates: &Aggregates,
    not_scanned_documented: u64,
    not_scanned_undocumented: u64,
    coverage_pct: f64,
) -> SummarySection {
    let inventory = aggregates
        .pii_inventory()
        .map(crate::aggregate::PiiInventory::summary);
    let tables_total = aggregates.pii_inventory().map_or(0, |inventory| {
        u64::try_from(inventory.tables().len()).unwrap_or(u64::MAX)
    });
    SummarySection {
        undocumented: inventory.map_or(0, |summary| summary.undocumented),
        undocumented_confirmed: inventory.map_or(0, |summary| summary.undocumented_confirmed),
        undocumented_likely: inventory.map_or(0, |summary| summary.undocumented_likely),
        undocumented_possible: inventory.map_or(0, |summary| summary.undocumented_possible),
        documented: inventory.map_or(0, |summary| summary.documented),
        tables_with_pii: inventory.map_or(0, |summary| summary.tables_with_pii),
        tables_total,
        coverage_pct,
        not_scanned: not_scanned_documented.saturating_add(not_scanned_undocumented),
        not_scanned_documented,
        not_scanned_undocumented,
    }
}

fn columns<'a>(info: &'a ScanInfo, aggregates: &'a Aggregates) -> Vec<ColumnRow<'a>> {
    let Some(inventory) = aggregates.pii_inventory() else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    for table in inventory.tables() {
        for entry in table.entries_for_review() {
            let (status, reason) = match status_of(entry.status(), &info.suppressions) {
                ("documented", reason) => ("documented", reason),
                _ => ("undocumented", None),
            };
            rows.push(ColumnRow {
                table: table.name(),
                column: entry.column(),
                rule: entry.rule().code(),
                confidence: entry.highest_confidence().code(),
                evidence: entry.evidence().code(),
                files: entry.files(),
                files_confirmed: entry.files_confirmed,
                files_likely: entry.files_likely,
                files_possible: entry.files_possible,
                files_suppressed: entry.files_suppressed,
                status,
                reason,
                expires: expiry_of(entry.status(), &info.suppressions).map(|date| date.to_string()),
            });
        }
    }
    rows
}

/// Undocumented files the aggregates still hold as `content-not-scanned`
/// samples. A suppressed file is not kept as a sample, so a documented
/// unscanned file is counted in `coverage` and is not listed here.
fn unscanned(aggregates: &Aggregates) -> Vec<UnscannedFile<'_>> {
    aggregates
        .samples_for(RuleId::ContentNotScanned)
        .iter()
        .filter_map(|sample| {
            let SampleDetail::NotScanned(reason) = sample.detail else {
                return None;
            };
            Some(UnscannedFile {
                key: sample.key.as_str(),
                reason_code: reason.code(),
                reason: reason_label(reason),
                status: "undocumented",
            })
        })
        .collect()
}

fn coverage_section(aggregates: &Aggregates) -> CoverageSection {
    let content = aggregates.content();
    let coverage = aggregates.coverage();
    CoverageSection {
        eligible: coverage.map_or(0, |coverage| coverage.files_eligible),
        scanned_whole: content.map_or(0, |content| content.scanned_whole),
        scanned_partial: content.map_or(0, |content| content.scanned_partially),
        not_scanned_documented: coverage.map_or(0, |coverage| coverage.not_scanned_suppressed),
        not_scanned_undocumented: coverage.map_or(0, |coverage| coverage.not_scanned_unsuppressed),
        columns_examined: content.map_or(0, |content| content.columns_examined),
        columns_skipped: ColumnsSkipped {
            repeated: content.map_or(0, |content| content.skipped_repeated),
            unsupported_type: content.map_or(0, |content| content.skipped_unsupported_type),
            page_too_large: content.map_or(0, |content| content.skipped_page_too_large),
            unreadable: content.map_or(0, |content| content.skipped_unreadable),
            unsupported_codec: content.map_or(0, |content| content.skipped_unsupported_codec),
        },
        caveat: CAVEAT,
    }
}

fn metadata_rules(aggregates: &Aggregates) -> Vec<MetadataRule> {
    RuleId::ALL
        .into_iter()
        .filter(|rule| !rule.is_content())
        .map(|rule| MetadataRule {
            rule: rule.code(),
            title: rule.title(),
            count: finding_count(aggregates, rule),
            severity: highest_severity(aggregates, rule),
        })
        .collect()
}

fn finding_count(aggregates: &Aggregates, rule: RuleId) -> u64 {
    Severity::ALL.into_iter().fold(0, |total, severity| {
        total.saturating_add(aggregates.matrix_cell(rule, severity).count)
    })
}

fn highest_severity(aggregates: &Aggregates, rule: RuleId) -> &'static str {
    Severity::ALL
        .into_iter()
        .rev()
        .find(|severity| aggregates.matrix_cell(rule, *severity).count > 0)
        .map_or("none", Severity::code)
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use super::{embed_data, write};
    use crate::aggregate::Aggregates;
    use crate::content::{ColumnFinding, FileOutcome, FileScan, FileStats};
    use crate::error::{ExitCode, LakeScanError};
    use crate::model::{
        ColumnDetail, Confidence, Detail, Evidence, Finding, NotScannedReason, ObjectMeta, PiiType,
        StorageClass,
    };
    use crate::report::fixture;
    use crate::report::write_html;

    const FIXTURE_DATA: &str = r#"{
                "tool": { "name": "lakescan", "version": "0.1.3" },
                "scan": {
                    "bucket": "example-bucket",
                    "prefix": "logs/",
                    "startedAt": "2023-11-14T22:13:20Z",
                    "elapsedSeconds": 1.2,
                    "config": "5 suppression entries (sha256: ed56731f5617)",
                    "settings": {
                        "pii": true,
                        "concurrency": 16,
                        "memoryBudgetMib": 512,
                        "wholeFileMaxMib": 8,
                        "coalesceGapMib": 1,
                        "failOn": "high"
                    }
                },
                "exit": {
                    "code": 1,
                    "name": "FindingsExceedThreshold",
                    "meaning": "The scan completed, but an unsuppressed finding reached the failing threshold."
                },
                "summary": {
                    "undocumented": 2,
                    "undocumentedConfirmed": 1,
                    "undocumentedLikely": 1,
                    "undocumentedPossible": 0,
                    "documented": 1,
                    "tablesWithPii": 1,
                    "tablesTotal": 3,
                    "coveragePct": 75.0,
                    "notScanned": 1,
                    "notScannedDocumented": 1,
                    "notScannedUndocumented": 0
                },
                "columns": [
                    {
                        "table": "warehouse/customers",
                        "column": "contact.phone",
                        "rule": "pii-phone",
                        "confidence": "likely",
                        "evidence": "values",
                        "files": 1,
                        "filesConfirmed": 0,
                        "filesLikely": 1,
                        "filesPossible": 0,
                        "filesSuppressed": 0,
                        "status": "undocumented",
                        "reason": null,
                        "expires": null
                    },
                    {
                        "table": "warehouse/customers",
                        "column": "email",
                        "rule": "pii-email",
                        "confidence": "confirmed",
                        "evidence": "values",
                        "files": 2,
                        "filesConfirmed": 2,
                        "filesLikely": 0,
                        "filesPossible": 0,
                        "filesSuppressed": 0,
                        "status": "undocumented",
                        "reason": null,
                        "expires": null
                    },
                    {
                        "table": "warehouse/customers",
                        "column": "full_name",
                        "rule": "pii-person-name",
                        "confidence": "likely",
                        "evidence": "column-name",
                        "files": 2,
                        "filesConfirmed": 0,
                        "filesLikely": 0,
                        "filesPossible": 0,
                        "filesSuppressed": 2,
                        "status": "documented",
                        "reason": "Names are needed for invoicing (DPA section 4)",
                        "expires": "2027-06-30"
                    }
                ],
                "unscanned": [],
                "coverage": {
                    "eligible": 4,
                    "scannedWhole": 2,
                    "scannedPartial": 1,
                    "notScannedDocumented": 1,
                    "notScannedUndocumented": 0,
                    "columnsExamined": 0,
                    "columnsSkipped": {
                        "repeated": 0,
                        "unsupportedType": 1,
                        "pageTooLarge": 0,
                        "unreadable": 0,
                        "unsupportedCodec": 0
                    },
                    "caveat": "Inspection is sampled: up to 3 row groups, up to 2,000 values per column per row group. No finding does not mean no personal data."
                },
                "metadataRules": [
                    { "rule": "sensitive-key", "title": "Key looks like a credential or secret file", "count": 1, "severity": "high" },
                    { "rule": "reduced-redundancy", "title": "Object uses the deprecated REDUCED_REDUNDANCY storage class", "count": 1, "severity": "medium" },
                    { "rule": "stale-standard", "title": "Large STANDARD object has gone unmodified for a long time", "count": 1, "severity": "medium" },
                    { "rule": "small-object-cold-tier", "title": "Small object sits in a cold storage tier that bills a size minimum", "count": 1, "severity": "low" },
                    { "rule": "zero-byte-object", "title": "Zero-byte object that is not a folder marker", "count": 1, "severity": "info" },
                    { "rule": "unknown-storage-class", "title": "Object reports a storage class this build of LakeScan does not recognize", "count": 1, "severity": "info" }
                ]
    }"#;

    fn page(
        info: &crate::report::ScanInfo,
        aggregates: &Aggregates,
        code: ExitCode,
    ) -> Result<String, LakeScanError> {
        let mut buf = Vec::new();
        write(&mut buf, info, aggregates, code)?;
        String::from_utf8(buf)
            .map_err(|err| LakeScanError::Report(io::Error::new(io::ErrorKind::InvalidData, err)))
    }

    fn data_json(page: &str) -> Option<&str> {
        let line = page
            .lines()
            .find(|line| line.trim_start().starts_with("const DATA = "))?;
        let (_, rest) = line.trim_start().split_once("const DATA = ")?;
        rest.strip_suffix(';')
    }

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
    fn the_dashboard_source_matches_the_file_on_disk() -> Result<(), io::Error> {
        let on_disk = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/report/dashboard.html"
        ))?;
        assert_eq!(on_disk, include_str!("dashboard.html"));
        Ok(())
    }

    #[test]
    fn a_run_that_missed_one_file_in_3000_reports_99_9_not_100() -> Result<(), LakeScanError> {
        let mut aggregates = Aggregates::new(fixture::now());
        aggregates.enable_content();
        for index in 0..3000 {
            let object = ObjectMeta {
                key: format!("lake/t/part-{index}.parquet"),
                size: 10,
                last_modified: fixture::now(),
                etag: "e".to_owned(),
                storage_class: StorageClass::Standard,
            };
            let outcome = if index == 0 {
                FileOutcome::NotScanned(NotScannedReason::Unreadable)
            } else {
                FileOutcome::ScannedWhole
            };
            let scan = FileScan {
                outcome,
                columns: Vec::new(),
                not_examined: Vec::new(),
                stats: FileStats::default(),
            };
            aggregates.observe_content(&object, &scan, false);
        }
        let page = page(
            &fixture::scan_info(),
            &aggregates,
            ExitCode::ContentNotScanned,
        )?;
        let json = data_json(&page).ok_or_else(|| {
            LakeScanError::Report(io::Error::other("no DATA line in the rendered page"))
        })?;
        let value: serde_json::Value = serde_json::from_str(json).map_err(|err| {
            LakeScanError::Report(io::Error::new(io::ErrorKind::InvalidData, err))
        })?;
        let pct = value
            .pointer("/summary/coveragePct")
            .and_then(serde_json::Value::as_f64);
        assert_eq!(pct.map(f64::to_bits), Some(99.9_f64.to_bits()), "{json}");
        let eligible = value
            .pointer("/coverage/eligible")
            .and_then(serde_json::Value::as_u64);
        assert_eq!(eligible, Some(3000));
        Ok(())
    }

    /// The dashboard's script must show the percentage Rust already rounded
    /// down. Recomputing it in JS, or painting a decimal tile through
    /// `Math.round`, would turn 99.9 into 100 for a run that missed a file.
    #[test]
    fn the_dashboard_never_recomputes_or_rounds_coverage_up() {
        let source = include_str!("dashboard.html");
        assert!(
            !source.contains("function coveragePct"),
            "coverage must come from DATA.summary.coveragePct, not a JS recompute"
        );
        assert!(
            source.contains("var pct = DATA.summary.coveragePct;"),
            "the coverage tile must read DATA.summary.coveragePct"
        );
        for forbidden in ["* 100)", "* 100;", "100 * ", "Math.round(value * 10)"] {
            assert!(
                !source.contains(forbidden),
                "the dashboard script contains {forbidden:?}: percentages must be floored"
            );
        }
        let count_up = source
            .split_once("function countUp")
            .and_then(|(_, rest)| rest.split_once("function readHash"))
            .map_or("", |(body, _)| body);
        assert!(
            count_up.contains("toFixed(decimals)"),
            "a decimal tile must be painted with toFixed(decimals)"
        );
        assert!(
            !count_up.contains("String(Math.round(value)) + suffix"),
            "countUp paints a decimal tile with Math.round"
        );
    }

    #[test]
    fn a_missing_data_line_is_a_report_error() {
        let err = embed_data("<html></html>", "{}");
        assert!(matches!(err, Err(LakeScanError::Report(_))));
    }

    #[test]
    fn a_broken_pipe_returns_ok() {
        let result = write_html(
            AlwaysFails(io::ErrorKind::BrokenPipe),
            &fixture::scan_info(),
            &fixture::aggregates(),
            ExitCode::Ok,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn a_script_closing_column_name_stays_inside_the_data_json() -> Result<(), LakeScanError> {
        let hostile = "</script><script>alert(1)</script>";
        let mut aggregates = Aggregates::new(fixture::now());
        aggregates.enable_content();
        let object = ObjectMeta {
            key: "lake/t/part-0.parquet".to_owned(),
            size: 10,
            last_modified: fixture::now(),
            etag: "e".to_owned(),
            storage_class: StorageClass::Standard,
        };
        let detail = ColumnDetail::new(hostile, Confidence::Confirmed, Evidence::ColumnName);
        let scan = FileScan {
            outcome: FileOutcome::ScannedWhole,
            columns: vec![ColumnFinding {
                pii: PiiType::Email,
                detail: detail.clone(),
            }],
            not_examined: Vec::new(),
            stats: FileStats::default(),
        };
        aggregates.observe_content(&object, &scan, false);
        aggregates.observe_finding(Finding {
            rule: PiiType::Email.rule(),
            severity: Confidence::Confirmed.severity(),
            object: &object,
            detail: Detail::Column(&detail),
        });
        let page = page(
            &fixture::scan_info(),
            &aggregates,
            ExitCode::FindingsExceedThreshold,
        )?;
        let json = data_json(&page).ok_or_else(|| {
            LakeScanError::Report(io::Error::other("no DATA line in the rendered page"))
        })?;
        assert!(!json.contains('<'), "{json}");
        assert!(json.contains("\\u003c/script>"), "{json}");
        let value: serde_json::Value = serde_json::from_str(json).map_err(|err| {
            LakeScanError::Report(io::Error::new(io::ErrorKind::InvalidData, err))
        })?;
        let column = value
            .pointer("/columns/0/column")
            .and_then(serde_json::Value::as_str);
        assert_eq!(column, Some(hostile));
        Ok(())
    }

    #[test]
    fn matches_the_golden_file_and_the_fixture_round_trips() -> Result<(), LakeScanError> {
        let golden = include_str!("../../tests/golden/dashboard.html");
        let page = page(
            &fixture::scan_info(),
            &fixture::aggregates(),
            ExitCode::FindingsExceedThreshold,
        )?;
        let json = data_json(&page).ok_or_else(|| {
            LakeScanError::Report(io::Error::other("no DATA line in the rendered page"))
        })?;
        let value: serde_json::Value = serde_json::from_str(json).map_err(|err| {
            LakeScanError::Report(io::Error::new(io::ErrorKind::InvalidData, err))
        })?;
        let expected: serde_json::Value = serde_json::from_str(FIXTURE_DATA).map_err(|err| {
            LakeScanError::Report(io::Error::new(io::ErrorKind::InvalidData, err))
        })?;
        assert_eq!(value, expected);
        assert_eq!(page, golden);
        Ok(())
    }
}
