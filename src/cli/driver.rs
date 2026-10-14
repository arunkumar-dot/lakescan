//! The scan driver: wires `scanner` → `rules` (and, with `--pii`,
//! `content`) → `suppress` → `aggregate` → `report` for one run and
//! decides the run's [`ExitCode`].
//!
//! The driver never opens a destination itself. The summary, the optional
//! findings stream, the optional progress line, the optional suppression
//! warnings, and the error stream all arrive as writers, and object
//! contents arrive through an [`ObjectReader`], which is what lets the
//! tests below run a whole scan against in-memory buffers, a scripted
//! [`PageSource`], and in-memory Parquet files.

use std::io::Write;
use std::time::{Instant, SystemTime};

use super::target::Target;
use crate::aggregate::{Aggregates, ContentSummary};
use crate::content::{self, ObjectReader};
use crate::error::{ExitCode, LakeScanError};
use crate::model::{Finding, NotScannedReason, Severity};
use crate::report::{self, FindingsWriter, Format, ScanInfo};
use crate::rules::{self, EvalContext};
use crate::scanner::{PageSource, Scanner};
use crate::suppress::{Config, Date, Entry, Outcome, Suppressor};

/// Clears the current terminal line: carriage return, then ANSI "erase
/// entire line".
const CLEAR_LINE: &str = "\r\x1b[2K";

/// Content scanning for one run: where object contents come from, and
/// which files are small enough to read whole.
pub(crate) struct Content<R> {
    /// Reads object byte ranges.
    pub(crate) reader: R,
    /// Files at or below this size are read whole.
    pub(crate) whole_file_max: u64,
}

/// Where one scan's output goes.
pub(crate) struct Outputs<O, F, P, D, E> {
    /// The summary destination, written once after the scan.
    pub(crate) summary: O,
    /// The JSON Lines findings stream, if one was requested.
    pub(crate) findings: Option<F>,
    /// The progress line's destination, or `None` for no progress output.
    /// The caller decides (terminal or not, `--quiet` or not); the driver
    /// only writes to it.
    pub(crate) progress: Option<P>,
    /// Where to warn about expired and unused suppression entries after
    /// the scan, or `None` (`--quiet`) for no warnings.
    pub(crate) warnings: Option<D>,
    /// Where to explain an [`ExitCode::ContentNotScanned`] verdict; always
    /// written, `--quiet` or not, since it explains a failing exit code.
    pub(crate) errors: E,
}

/// Runs one scan of `source` to completion and returns its verdict:
/// [`ExitCode::ContentNotScanned`] when `content` was given, at least one
/// Parquet file was eligible, and none could be scanned;
/// [`ExitCode::FindingsExceedThreshold`] when the worst finding's severity
/// is at or above `fail_on`; otherwise [`ExitCode::Ok`]. `fail_on` of
/// `None` never fails on findings.
///
/// With `content`, every eligible object (see [`content::is_eligible`]) is
/// content-scanned as it is listed, one at a time, and its findings take
/// the same path as listing findings.
///
/// "Now" is captured once, at the start, and shared by the rule engine, the
/// aggregates, and the suppressor (whose expiry check uses its UTC date),
/// so every stage agrees on it. Every finding passes through the
/// suppressor: a suppressed one is counted by
/// [`Aggregates::observe_suppressed`] and goes nowhere else — not the
/// findings matrix, not the verdict, not the findings stream.
///
/// The findings stream is finished before the summary is written, and the
/// progress line is cleared before either, whether the scan succeeded or
/// not. Suppression warnings follow the summary.
///
/// # Errors
/// Returns whatever the scanner returns for a failed listing, and
/// [`LakeScanError::Report`] if the findings stream or the summary cannot
/// be written.
pub(crate) async fn scan<S, R, O, F, P, D, E>(
    source: S,
    target: Target,
    config: Config,
    format: Format,
    fail_on: Option<Severity>,
    mut content: Option<Content<R>>,
    outputs: Outputs<O, F, P, D, E>,
) -> Result<ExitCode, LakeScanError>
where
    S: PageSource,
    R: ObjectReader,
    O: Write,
    F: Write,
    P: Write,
    D: Write,
    E: Write,
{
    let started_at = SystemTime::now();
    let clock = Instant::now();
    let ctx = EvalContext { now: started_at };
    // Boxed: `Aggregates` is ~110 KiB of fixed-size summaries, which would
    // otherwise sit inline in this function's future.
    let mut aggregates = Box::new(Aggregates::new(started_at));
    let mut suppressor = Suppressor::new(config, &target.bucket, Date::utc_of(started_at));
    if content.is_some() {
        aggregates.enable_content();
    }

    let Outputs {
        summary,
        findings,
        mut progress,
        warnings,
        mut errors,
    } = outputs;
    let mut findings = findings.map(FindingsWriter::new);

    let listed = walk(
        &mut Scanner::new(source),
        &ctx,
        content.as_mut(),
        &mut Sinks {
            aggregates: &mut aggregates,
            suppressor: &mut suppressor,
            findings: findings.as_mut(),
            finding_count: 0,
        },
        progress.as_mut(),
    )
    .await;
    if let Some(out) = progress.as_mut() {
        // Best effort: a progress line that cannot be cleared is cosmetic,
        // not a reason to fail a scan that otherwise succeeded.
        let _ = out
            .write_all(CLEAR_LINE.as_bytes())
            .and_then(|()| out.flush());
    }
    listed?;
    let elapsed = clock.elapsed();

    if let Some(findings) = findings {
        findings.finish()?;
    }

    let info = ScanInfo {
        bucket: target.bucket,
        prefix: target.prefix,
        started_at,
        elapsed,
        suppressions: suppressor.finish(),
    };
    report::write_summary(summary, format, &info, &aggregates)?;

    if let Some(mut out) = warnings {
        // Best effort, like progress: the summary already carries these.
        let _ = write_warnings(&mut out, &info.suppressions);
    }

    if let Some(content) = aggregates.content()
        && nothing_scanned(content)
    {
        // Best effort: the exit code carries the verdict regardless.
        let _ = write_not_scanned(&mut errors, content);
        return Ok(ExitCode::ContentNotScanned);
    }
    Ok(verdict(aggregates.worst_severity(), fail_on))
}

/// Whether content scanning found eligible files but scanned none of
/// them.
fn nothing_scanned(content: &ContentSummary) -> bool {
    content.files_eligible > 0 && content.files_scanned() == 0
}

/// Explains [`ExitCode::ContentNotScanned`]: the reasons, and, when most
/// files were refused, the permissions content scanning needs.
fn write_not_scanned<E: Write>(out: &mut E, content: &ContentSummary) -> std::io::Result<()> {
    let reasons: Vec<String> = NotScannedReason::ALL
        .into_iter()
        .filter(|&reason| content.not_scanned(reason) > 0)
        .map(|reason| format!("{}={}", reason.code(), content.not_scanned(reason)))
        .collect();
    writeln!(
        out,
        "lakescan: no Parquet file could be content-scanned ({} eligible: {})",
        content.files_eligible,
        reasons.join(", ")
    )?;
    let denied = content.not_scanned(NotScannedReason::AccessDenied);
    if denied.saturating_mul(2) > content.not_scanned_total() {
        writeln!(
            out,
            "lakescan: reading Parquet content requires s3:GetObject on the objects, and \
             kms:Decrypt on the key of any SSE-KMS-encrypted object"
        )?;
    }
    out.flush()
}

/// One line per expired, then per unused, suppression entry.
fn write_warnings<D: Write>(out: &mut D, outcome: &Outcome) -> std::io::Result<()> {
    let line = |out: &mut D, state: &str, entry: &Entry| {
        let expires = entry
            .expires
            .map(|date| format!(" (expires {date})"))
            .unwrap_or_default();
        let column = entry
            .column
            .as_ref()
            .map(|column| format!(", column {column:?}"))
            .unwrap_or_default();
        writeln!(
            out,
            "lakescan: warning: {state} suppression for {}, {}{column}{expires}: {:?}",
            entry.rule.code(),
            entry.pattern,
            entry.reason
        )
    };
    for entry in &outcome.expired {
        line(out, "expired", entry)?;
    }
    for entry in &outcome.unused {
        line(out, "unused", entry)?;
    }
    out.flush()
}

/// Where every finding goes: through `suppressor`, then either to
/// [`Aggregates::observe_suppressed`] or to the findings matrix and the
/// findings stream, if there is one.
struct Sinks<'a, F: Write> {
    aggregates: &'a mut Aggregates,
    suppressor: &'a mut Suppressor,
    findings: Option<&'a mut FindingsWriter<F>>,
    finding_count: u64,
}

impl<F: Write> Sinks<'_, F> {
    fn route(&mut self, finding: Finding<'_>) -> Result<(), LakeScanError> {
        if self.suppressor.suppresses(&finding) {
            self.aggregates.observe_suppressed(finding);
            return Ok(());
        }
        self.aggregates.observe_finding(finding);
        if let Some(writer) = self.findings.as_deref_mut() {
            writer.write(finding)?;
        }
        self.finding_count = self.finding_count.saturating_add(1);
        Ok(())
    }
}

/// Pulls every page from `scanner`, feeding each object into the
/// aggregates and each finding it raises (listing rules, then, for an
/// eligible Parquet object, content scanning) through `sinks`, and
/// rewrites the progress line after every page. Every content buffer is
/// dropped before the next object.
async fn walk<S, R, F, P>(
    scanner: &mut Scanner<S>,
    ctx: &EvalContext,
    mut content: Option<&mut Content<R>>,
    sinks: &mut Sinks<'_, F>,
    mut progress: Option<&mut P>,
) -> Result<(), LakeScanError>
where
    S: PageSource,
    R: ObjectReader,
    F: Write,
    P: Write,
{
    let mut object_count: u64 = 0;
    let mut file_count: u64 = 0;

    while let Some(page) = scanner.next_page().await? {
        for object in page {
            sinks.aggregates.observe_object(object);
            for finding in rules::evaluate(object, ctx) {
                sinks.route(finding)?;
            }
            if let Some(content) = content.as_deref_mut()
                && content::is_eligible(&object.key)
            {
                let scan =
                    content::scan_file(&mut content.reader, object, content.whole_file_max).await;
                sinks.aggregates.observe_content(&scan);
                for finding in scan.findings(object) {
                    sinks.route(finding)?;
                }
                file_count = file_count.saturating_add(1);
            }
        }
        object_count = object_count.saturating_add(u64::try_from(page.len()).unwrap_or(u64::MAX));

        if let Some(out) = progress.as_deref_mut() {
            let files = if content.is_some() {
                format!(", {file_count} parquet files")
            } else {
                String::new()
            };
            // Best effort, as above.
            let _ = write!(
                out,
                "{CLEAR_LINE}scanned {object_count} objects{files}, {} findings",
                sinks.finding_count
            )
            .and_then(|()| out.flush());
        }
    }

    Ok(())
}

/// The run's exit code: a failing verdict exactly when there was a finding
/// and its worst severity is at or above the threshold.
fn verdict(worst: Option<Severity>, fail_on: Option<Severity>) -> ExitCode {
    match (worst, fail_on) {
        (Some(worst), Some(threshold)) if worst >= threshold => ExitCode::FindingsExceedThreshold,
        _ => ExitCode::Ok,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::time::{Duration, SystemTime};

    use super::{CLEAR_LINE, Content, Outputs, scan, verdict};
    use crate::cli::target::Target;
    use crate::content::testing::{
        Layout, MemoryReader, Values, aadhaars, emails, mobiles, parquet_file,
    };
    use crate::error::{ExitCode, LakeScanError};
    use crate::model::{NotScannedReason, ObjectMeta, Severity, StorageClass};
    use crate::report::Format;
    use crate::scanner::PageSource;
    use crate::suppress::Config;

    /// One scripted response to a single `fetch_page` call.
    enum Step {
        Page(Vec<ObjectMeta>, Option<String>),
        Err(LakeScanError),
    }

    struct FakeSource {
        steps: VecDeque<Step>,
    }

    impl PageSource for FakeSource {
        fn fetch_page(
            &mut self,
            _continuation: Option<String>,
            out: &mut Vec<ObjectMeta>,
        ) -> impl Future<Output = Result<Option<String>, LakeScanError>> + Send {
            std::future::ready(match self.steps.pop_front() {
                Some(Step::Page(entries, next)) => {
                    out.extend(entries);
                    Ok(next)
                }
                Some(Step::Err(err)) => Err(err),
                None => Ok(None),
            })
        }
    }

    fn source(steps: Vec<Step>) -> FakeSource {
        FakeSource {
            steps: steps.into(),
        }
    }

    fn object(key: &str, size: u64, storage_class: StorageClass) -> ObjectMeta {
        ObjectMeta {
            key: key.to_owned(),
            size,
            // Recent, so no age-based rule fires regardless of when the
            // test runs.
            last_modified: SystemTime::now() - Duration::from_secs(60),
            etag: format!("etag-{key}"),
            storage_class,
        }
    }

    fn target() -> Target {
        Target {
            bucket: "test-bucket".to_owned(),
            prefix: None,
        }
    }

    /// Two pages: a clean object and an `id_rsa` (sensitive-key, High),
    /// then a zero-byte object (zero-byte-object, Info).
    fn two_pages() -> FakeSource {
        source(vec![
            Step::Page(
                vec![
                    object("reports/summary.csv", 2048, StorageClass::Standard),
                    object("id_rsa", 512, StorageClass::Standard),
                ],
                Some("tok-1".to_owned()),
            ),
            Step::Page(
                vec![object("scratch/empty.tmp", 0, StorageClass::Standard)],
                None,
            ),
        ])
    }

    #[test]
    fn verdict_fails_at_or_above_the_threshold_only() {
        assert_eq!(
            verdict(Some(Severity::High), Some(Severity::High)),
            ExitCode::FindingsExceedThreshold
        );
        assert_eq!(
            verdict(Some(Severity::Critical), Some(Severity::High)),
            ExitCode::FindingsExceedThreshold
        );
        assert_eq!(
            verdict(Some(Severity::Medium), Some(Severity::High)),
            ExitCode::Ok
        );
        assert_eq!(verdict(None, Some(Severity::Info)), ExitCode::Ok);
        assert_eq!(verdict(Some(Severity::Critical), None), ExitCode::Ok);
    }

    #[tokio::test]
    async fn a_scan_writes_the_summary_and_every_finding_and_fails_on_high()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut summary = Vec::new();
        let mut findings = Vec::new();
        let code = scan(
            two_pages(),
            target(),
            Config::default(),
            Format::Json,
            Some(Severity::High),
            None::<Content<MemoryReader>>,
            Outputs {
                summary: &mut summary,
                findings: Some(&mut findings),
                progress: None::<Vec<u8>>,
                warnings: None::<Vec<u8>>,
                errors: Vec::<u8>::new(),
            },
        )
        .await?;

        assert_eq!(code, ExitCode::FindingsExceedThreshold);

        let summary: serde_json::Value = serde_json::from_slice(&summary)?;
        let inventory = summary.get("inventory");
        assert_eq!(
            inventory.and_then(|i| i.get("object_count")),
            Some(&serde_json::json!(3))
        );
        assert_eq!(
            summary.get("scan").and_then(|s| s.get("bucket")),
            Some(&serde_json::json!("test-bucket"))
        );

        let findings = String::from_utf8(findings)?;
        let rules: Vec<String> = findings
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).map(|record| {
                    record
                        .get("rule")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                })
            })
            .collect::<Result<_, _>>()?;
        assert_eq!(rules, ["sensitive-key", "zero-byte-object"]);
        Ok(())
    }

    #[tokio::test]
    async fn a_higher_threshold_or_none_passes() -> Result<(), LakeScanError> {
        for fail_on in [Some(Severity::Critical), None] {
            let code = scan(
                two_pages(),
                target(),
                Config::default(),
                Format::Text,
                fail_on,
                None::<Content<MemoryReader>>,
                Outputs {
                    summary: Vec::new(),
                    findings: None::<Vec<u8>>,
                    progress: None::<Vec<u8>>,
                    warnings: None::<Vec<u8>>,
                    errors: Vec::<u8>::new(),
                },
            )
            .await?;
            assert_eq!(code, ExitCode::Ok, "fail_on {fail_on:?}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn progress_is_rewritten_per_page_and_cleared_at_the_end()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut progress = Vec::new();
        scan(
            two_pages(),
            target(),
            Config::default(),
            Format::Text,
            None,
            None::<Content<MemoryReader>>,
            Outputs {
                summary: Vec::new(),
                findings: None::<Vec<u8>>,
                progress: Some(&mut progress),
                warnings: None::<Vec<u8>>,
                errors: Vec::<u8>::new(),
            },
        )
        .await?;

        let progress = String::from_utf8(progress)?;
        assert_eq!(
            progress,
            format!(
                "{CLEAR_LINE}scanned 2 objects, 1 findings\
                 {CLEAR_LINE}scanned 3 objects, 2 findings\
                 {CLEAR_LINE}"
            )
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_listing_clears_progress_and_writes_no_summary() {
        let mut summary = Vec::new();
        let mut progress = Vec::new();
        let result = scan(
            source(vec![
                Step::Page(
                    vec![object("a", 1, StorageClass::Standard)],
                    Some("tok-1".to_owned()),
                ),
                Step::Err(LakeScanError::Transport("boom".to_owned())),
            ]),
            target(),
            Config::default(),
            Format::Text,
            Some(Severity::High),
            None::<Content<MemoryReader>>,
            Outputs {
                summary: &mut summary,
                findings: None::<Vec<u8>>,
                progress: Some(&mut progress),
                warnings: None::<Vec<u8>>,
                errors: Vec::<u8>::new(),
            },
        )
        .await;

        assert!(matches!(result, Err(LakeScanError::Transport(_))));
        assert_eq!(summary, Vec::<u8>::new());
        assert!(progress.ends_with(CLEAR_LINE.as_bytes()));
    }

    /// What one content scan wrote: exit code, summary, findings stream,
    /// warnings and errors.
    struct ContentRun {
        code: ExitCode,
        summary: String,
        findings: String,
        warnings: String,
        errors: String,
    }

    /// Lists `files` (key, body) as one page and scans them with `--pii`,
    /// reading everything at or below `whole_file_max` whole.
    async fn content_run(
        files: &[(&str, Vec<u8>)],
        config: Config,
        format: Format,
        whole_file_max: u64,
    ) -> Result<ContentRun, Box<dyn std::error::Error>> {
        let mut reader = MemoryReader::default();
        let mut listed = Vec::new();
        for (key, body) in files {
            reader = reader.with(key, body.clone());
            listed.push(object(
                key,
                u64::try_from(body.len())?,
                StorageClass::Standard,
            ));
        }
        let (mut summary, mut findings, mut warnings, mut errors) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        let code = scan(
            source(vec![Step::Page(listed, None)]),
            target(),
            config,
            format,
            Some(Severity::High),
            Some(Content {
                reader,
                whole_file_max,
            }),
            Outputs {
                summary: &mut summary,
                findings: Some(&mut findings),
                progress: None::<Vec<u8>>,
                warnings: Some(&mut warnings),
                errors: &mut errors,
            },
        )
        .await?;
        Ok(ContentRun {
            code,
            summary: String::from_utf8(summary)?,
            findings: String::from_utf8(findings)?,
            warnings: String::from_utf8(warnings)?,
            errors: String::from_utf8(errors)?,
        })
    }

    fn customers_file(rows: usize) -> Result<Vec<u8>, parquet::errors::ParquetError> {
        parquet_file(
            &[
                ("email", Values::Text(emails(rows))),
                ("mobile_no", Values::Int64(mobiles(rows))),
                ("aadhaar_no", Values::Int64(aadhaars(rows))),
            ],
            Layout::default(),
        )
    }

    #[tokio::test]
    async fn a_pii_scan_reports_columns_and_fails_on_confirmed_pii()
    -> Result<(), Box<dyn std::error::Error>> {
        let run = content_run(
            &[("crm/customers.parquet", customers_file(200)?)],
            Config::default(),
            Format::Json,
            8 * 1024 * 1024,
        )
        .await?;
        assert_eq!(run.code, ExitCode::FindingsExceedThreshold);
        let summary: serde_json::Value = serde_json::from_str(&run.summary)?;
        assert_eq!(
            summary.pointer("/content/files_eligible"),
            Some(&serde_json::json!(1))
        );
        assert_eq!(
            summary.pointer("/content/scanned_whole"),
            Some(&serde_json::json!(1))
        );
        assert_eq!(
            summary.pointer("/samples/pii-email/0/column"),
            Some(&serde_json::json!("email"))
        );
        assert_eq!(
            summary.pointer("/samples/pii-email/0/confidence"),
            Some(&serde_json::json!("confirmed"))
        );
        let rules: Vec<String> = run
            .findings
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).map(|record| {
                    record
                        .get("rule")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                })
            })
            .collect::<Result<_, _>>()?;
        assert_eq!(rules, ["pii-email", "pii-phone", "pii-in-aadhaar"]);
        Ok(())
    }

    #[tokio::test]
    async fn without_pii_no_object_is_read_and_there_is_no_content_section()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut summary = Vec::new();
        scan(
            source(vec![Step::Page(
                vec![object("a.parquet", 100, StorageClass::Standard)],
                None,
            )]),
            target(),
            Config::default(),
            Format::Json,
            None,
            None::<Content<MemoryReader>>,
            Outputs {
                summary: &mut summary,
                findings: None::<Vec<u8>>,
                progress: None::<Vec<u8>>,
                warnings: None::<Vec<u8>>,
                errors: Vec::<u8>::new(),
            },
        )
        .await?;
        let summary: serde_json::Value = serde_json::from_slice(&summary)?;
        assert_eq!(summary.get("content"), Some(&serde_json::Value::Null));
        Ok(())
    }

    #[tokio::test]
    async fn exit_six_when_no_eligible_file_could_be_scanned()
    -> Result<(), Box<dyn std::error::Error>> {
        let run = content_run(
            &[
                ("bad/notes.parquet", b"not parquet at all".to_vec()),
                ("bad/half.parq", b"PAR1 and then nothing".to_vec()),
                ("ok.csv", b"a,b".to_vec()),
            ],
            Config::default(),
            Format::Text,
            8 * 1024 * 1024,
        )
        .await?;
        assert_eq!(run.code, ExitCode::ContentNotScanned);
        assert!(run.summary.contains("CONTENT"), "{}", run.summary);
        assert!(
            run.summary.contains("not-parquet=1, unreadable=1"),
            "{}",
            run.summary
        );
        assert_eq!(
            run.errors,
            "lakescan: no Parquet file could be content-scanned \
             (2 eligible: not-parquet=1, unreadable=1)\n"
        );
        assert_eq!(run.findings.lines().count(), 2);
        Ok(())
    }

    #[test]
    fn mostly_refused_files_name_the_permissions_needed() -> std::io::Result<()> {
        let mut summary = crate::aggregate::Aggregates::new(SystemTime::UNIX_EPOCH);
        let scan = |reason| crate::content::FileScan {
            outcome: crate::content::FileOutcome::NotScanned(reason),
            columns: Vec::new(),
            stats: crate::content::FileStats::default(),
        };
        summary.observe_content(&scan(NotScannedReason::AccessDenied));
        summary.observe_content(&scan(NotScannedReason::AccessDenied));
        summary.observe_content(&scan(NotScannedReason::NotParquet));
        let mut out = Vec::new();
        if let Some(content) = summary.content() {
            super::write_not_scanned(&mut out, content)?;
        }
        let out = String::from_utf8_lossy(&out);
        assert!(out.contains("not-parquet=1, access-denied=2"), "{out}");
        assert!(out.contains("s3:GetObject"), "{out}");
        assert!(out.contains("kms:Decrypt"), "{out}");
        Ok(())
    }

    #[tokio::test]
    async fn files_whose_every_column_was_skipped_exit_six()
    -> Result<(), Box<dyn std::error::Error>> {
        // One email data page over the page cap, and a double column: the
        // file is Parquet and opens, but no value could be examined.
        let rows = 300_000;
        let too_large = parquet_file(
            &[
                ("email", Values::Text(emails(rows))),
                ("amount", Values::Double(vec![1.0; rows])),
            ],
            Layout {
                dictionary: false,
                page_bytes: usize::MAX,
                ..Layout::default()
            },
        )?;
        let run = content_run(
            &[("big.parquet", too_large)],
            Config::default(),
            Format::Text,
            64 * 1024 * 1024,
        )
        .await?;
        assert_eq!(run.code, ExitCode::ContentNotScanned);
        assert_eq!(
            run.errors,
            "lakescan: no Parquet file could be content-scanned \
             (1 eligible: no-column-examined=1)\n"
        );
        assert!(run.summary.contains("page-too-large=1"), "{}", run.summary);
        Ok(())
    }

    #[tokio::test]
    async fn one_scanned_file_is_enough_to_avoid_exit_six() -> Result<(), Box<dyn std::error::Error>>
    {
        let run = content_run(
            &[
                ("bad.parquet", b"nope".to_vec()),
                ("good.parquet", customers_file(50)?),
            ],
            Config::default(),
            Format::Text,
            8 * 1024 * 1024,
        )
        .await?;
        assert_eq!(run.code, ExitCode::FindingsExceedThreshold);
        Ok(())
    }

    #[tokio::test]
    async fn a_column_suppression_covers_one_column_only() -> Result<(), Box<dyn std::error::Error>>
    {
        let config = Config::parse(
            r#"
version = 1

[[suppress]]
rule = "pii-email"
prefix = "crm/"
column = "email"
reason = "Marketing contacts, consented"

[[suppress]]
rule = "pii-phone"
prefix = ""
column = "no_such_column"
reason = "Never matches"
"#,
            "test.toml",
        )?;
        let run = content_run(
            &[("crm/customers.parquet", customers_file(100)?)],
            config,
            Format::Json,
            8 * 1024 * 1024,
        )
        .await?;
        let summary: serde_json::Value = serde_json::from_str(&run.summary)?;
        let email = summary
            .get("findings")
            .and_then(serde_json::Value::as_array)
            .and_then(|all| {
                all.iter()
                    .find(|e| e.get("rule") == Some(&serde_json::json!("pii-email")))
            })
            .ok_or("pii-email missing")?;
        assert_eq!(email.pointer("/counts/high"), Some(&serde_json::json!(0)));
        assert_eq!(
            email.pointer("/suppressed/count"),
            Some(&serde_json::json!(1))
        );
        assert!(!run.findings.contains("pii-email"));
        assert!(run.findings.contains("pii-phone"));
        assert_eq!(
            summary.pointer("/suppressions/unused/0/column"),
            Some(&serde_json::json!("no_such_column"))
        );
        assert!(
            run.warnings.contains("column \"no_such_column\""),
            "{}",
            run.warnings
        );
        Ok(())
    }

    /// The no-values guarantee: seed known personal data into files, run
    /// every output (text and JSON summaries, the findings stream,
    /// warnings, errors) and check none of it appears anywhere.
    #[tokio::test]
    async fn no_sampled_value_reaches_any_output() -> Result<(), Box<dyn std::error::Error>> {
        let rows = 300;
        let seeded_emails = emails(rows);
        let seeded_phones = mobiles(rows);
        let seeded_aadhaar = aadhaars(rows);
        let names: Vec<Option<String>> = (0..rows)
            .map(|i| Some(format!("Seeded Person {i:03}")))
            .collect();
        let body = parquet_file(
            &[
                ("email", Values::Text(seeded_emails.clone())),
                ("mobile_no", Values::Int64(seeded_phones.clone())),
                ("c9", Values::Int64(seeded_aadhaar.clone())),
                ("full_name", Values::Text(names.clone())),
            ],
            Layout {
                row_group_rows: 100,
                ..Layout::default()
            },
        )?;
        let mut values: Vec<String> = seeded_emails.into_iter().flatten().collect();
        values.extend(seeded_phones.into_iter().flatten().map(|n| n.to_string()));
        values.extend(seeded_aadhaar.into_iter().flatten().map(|n| n.to_string()));
        values.extend(names.into_iter().flatten());

        let config = Config::parse(
            "version = 1\n[[suppress]]\nrule = \"pii-phone\"\nprefix = \"zzz/\"\n\
             column = \"mobile_no\"\nreason = \"unused on purpose\"\n",
            "test.toml",
        )?;
        let files = [
            ("pii/a.parquet", body.clone()),
            ("pii/b.parquet", body),
            ("pii/broken.parquet", b"PAR1 truncated".to_vec()),
        ];
        let mut outputs = String::new();
        for (format, whole_file_max) in [(Format::Text, 8 * 1024 * 1024), (Format::Json, 0)] {
            let run = content_run(&files, config.clone(), format, whole_file_max).await?;
            assert_eq!(run.code, ExitCode::FindingsExceedThreshold);
            for text in [run.summary, run.findings, run.warnings, run.errors] {
                outputs.push_str(&text);
            }
        }
        assert!(outputs.contains("mobile_no"), "the outputs were produced");
        for value in &values {
            assert!(
                !outputs.contains(value.as_str()),
                "{value:?} leaked into an output"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_suppressed_high_finding_no_longer_fails_the_run()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::parse(
            r#"
version = 1

[[suppress]]
rule = "sensitive-key"
key = "id_rsa"
reason = "Test key"

[[suppress]]
rule = "stale-standard"
prefix = ""
reason = "Never matches anything in this scan"
"#,
            "test.toml",
        )?;

        let mut summary = Vec::new();
        let mut findings = Vec::new();
        let mut warnings = Vec::new();
        let code = scan(
            two_pages(),
            target(),
            config,
            Format::Json,
            Some(Severity::High),
            None::<Content<MemoryReader>>,
            Outputs {
                summary: &mut summary,
                findings: Some(&mut findings),
                progress: None::<Vec<u8>>,
                warnings: Some(&mut warnings),
                errors: Vec::<u8>::new(),
            },
        )
        .await?;

        // The only High finding was suppressed; the zero-byte Info remains.
        assert_eq!(code, ExitCode::Ok);

        let findings = String::from_utf8(findings)?;
        assert!(!findings.contains("id_rsa"), "{findings}");
        assert_eq!(findings.lines().count(), 1);

        let summary: serde_json::Value = serde_json::from_slice(&summary)?;
        assert_eq!(
            summary.pointer("/verdict/worst_severity"),
            Some(&serde_json::json!("info"))
        );
        let sensitive = summary
            .get("findings")
            .and_then(serde_json::Value::as_array)
            .and_then(|all| {
                all.iter()
                    .find(|entry| entry.get("rule") == Some(&serde_json::json!("sensitive-key")))
            })
            .ok_or("sensitive-key missing from the summary")?;
        assert_eq!(
            sensitive.pointer("/counts/high"),
            Some(&serde_json::json!(0))
        );
        assert_eq!(
            sensitive.get("suppressed"),
            Some(&serde_json::json!({ "count": 1, "bytes": 512 }))
        );
        assert_eq!(
            summary.pointer("/suppressions/unused/0/rule"),
            Some(&serde_json::json!("stale-standard"))
        );

        let warnings = String::from_utf8(warnings)?;
        assert_eq!(
            warnings,
            "lakescan: warning: unused suppression for stale-standard, prefix \"\": \
             \"Never matches anything in this scan\"\n"
        );
        Ok(())
    }
}
