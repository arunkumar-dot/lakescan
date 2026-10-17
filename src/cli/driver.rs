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

use std::collections::VecDeque;
use std::io::Write;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use super::target::Target;
use crate::aggregate::{Aggregates, ContentSummary};
use crate::aggregate::{MAX_ENTRIES, MAX_TABLES};
use crate::content::{
    self, FileOutcome, FileScan, MemoryBudget, ObjectReader, ScanOptions, Scope, Sniff,
};
use crate::error::{ExitCode, LakeScanError};
use crate::model::RuleId;
use crate::model::{Finding, NotScannedReason, ObjectMeta, Severity};
use crate::report::{self, FindingsWriter, Format, PiiSettings, ScanInfo, ScanSettings};
use crate::rules::{self, EvalContext};
use crate::scanner::{PageSource, Scanner};
use crate::suppress::{Config, Date, Entry, Outcome, Suppressor};

/// Clears the current terminal line: carriage return, then ANSI "erase
/// entire line".
const CLEAR_LINE: &str = "\r\x1b[2K";

/// Content scanning for one run: where object contents come from, how
/// files are read, how many at once, and the memory they share.
pub(crate) struct Content<R> {
    /// Reads object byte ranges.
    pub(crate) reader: R,
    /// The whole-file maximum and the coalescing gap.
    pub(crate) options: ScanOptions,
    /// Files scanned at once (`--concurrency`), at least 1.
    pub(crate) concurrency: usize,
    /// The bytes in-flight scans may hold (`--memory-budget`).
    pub(crate) budget: Arc<MemoryBudget>,
    /// Which objects without a Parquet extension are sniffed.
    pub(crate) sniff: Sniff,
}

/// How many listed objects may wait behind an unfinished file scan, on top
/// of `--concurrency`: bounds the ordered window (an `ObjectMeta` each,
/// about 1 KiB at most), so a slow file never makes the queue grow with
/// the bucket.
const LOOKAHEAD: usize = 1024;

/// Where one scan's output goes.
pub(crate) struct Outputs<O, F, P, D, E> {
    /// The summary destination, written once after the scan.
    pub(crate) summary: O,
    /// The JSON Lines findings stream, if one was requested.
    pub(crate) findings: Option<F>,
    /// The PII inventory as CSV (`--inventory`), if requested; written
    /// after the summary.
    pub(crate) inventory: Option<F>,
    /// The HTML report (`--html`), if requested; written after the CSV.
    pub(crate) html: Option<F>,
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
/// [`ExitCode::ContentNotScanned`] when `content` was given and at least
/// one eligible Parquet file was not scanned without its
/// `content-not-scanned` finding being suppressed (fail closed; this wins
/// over a failing severity);
/// [`ExitCode::FindingsExceedThreshold`] when the worst finding's severity
/// is at or above `fail_on`; otherwise [`ExitCode::Ok`]. `fail_on` of
/// `None` never fails on findings.
///
/// With `content`, every eligible object (see [`content::is_eligible`]) is
/// content-scanned as it is listed, up to `concurrency` files at once,
/// and its findings take the same path as listing findings. Objects are
/// applied (aggregates, suppressor, findings stream) strictly in listing
/// order through an ordered window, so every output is the same for any
/// concurrency.
///
/// "Now" is captured once, at the start, and shared by the rule engine, the
/// aggregates, and the suppressor (whose expiry check uses its UTC date),
/// so every stage agrees on it. Every finding passes through the
/// suppressor: a suppressed one is counted by
/// [`Aggregates::observe_suppressed`] (which also records a PII finding in
/// the inventory as documented) and goes nowhere else — not the findings
/// matrix, not the verdict, not the findings stream.
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
    let settings = ScanSettings {
        pii: content.as_ref().map(|content| PiiSettings {
            whole_file_max: content.options.whole_file_max,
            sniff: content.sniff,
            coalesce_gap: content.options.coalesce_gap,
            concurrency: content.concurrency,
            memory_budget: content.budget.total(),
        }),
        fail_on,
        config: config.fingerprint().cloned(),
    };
    let mut suppressor = Suppressor::new(config, &target.bucket, Date::utc_of(started_at));
    if content.is_some() {
        aggregates.enable_content();
    }

    let Outputs {
        summary,
        findings,
        inventory,
        html,
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
    let object_count = listed?;
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
        settings,
    };
    // Decided before any report is written, so the HTML report can state
    // it; a report that then fails to write still ends the run with 5.
    let code = decide(&aggregates, fail_on);
    report::write_summary(summary, format, &info, &aggregates)?;
    if let Some(out) = inventory {
        report::write_inventory_csv(out, &info, &aggregates)?;
    }
    if let Some(out) = html {
        report::write_html(out, &info, &aggregates, code)?;
    }

    if let Some(mut out) = warnings {
        // Best effort, like progress: the summary already carries these.
        let _ = write_warnings(&mut out, &info.suppressions);
    }
    if let Some(inventory) = aggregates.pii_inventory()
        && inventory.truncated()
    {
        // Always, `--quiet` or not: it changes how every output reads.
        let _ = writeln!(
            errors,
            "lakescan: warning: the PII inventory is truncated: {} files and {} findings were \
             left out over its caps ({MAX_TABLES} tables, {MAX_ENTRIES} entries), so its tables \
             and the --inventory CSV are incomplete; scan narrower prefixes",
            inventory.left_out_files(),
            inventory.left_out_findings()
        )
        .and_then(|()| errors.flush());
    }

    if object_count == 0 {
        // Always, `--quiet` or not: a mistyped prefix lists nothing and
        // would otherwise pass as a clean scan. Best effort, like the rest.
        let _ = write_nothing_listed(&mut errors, &info);
    }

    if code == ExitCode::ContentNotScanned
        && let Some(content) = aggregates.content()
    {
        // Best effort: the exit code carries the verdict regardless.
        let _ = write_not_scanned(&mut errors, content);
    }
    Ok(code)
}

/// The run's exit code from what it found: [`ExitCode::ContentNotScanned`]
/// when an eligible file was not scanned and no suppression documents it
/// (fail closed, winning over a failing severity), else the verdict.
fn decide(aggregates: &Aggregates, fail_on: Option<Severity>) -> ExitCode {
    match aggregates.coverage() {
        Some(coverage) if coverage.not_scanned_unsuppressed > 0 => ExitCode::ContentNotScanned,
        _ => verdict(aggregates.worst_severity(), fail_on),
    }
}

/// Warns that the listing returned no objects, naming the target.
fn write_nothing_listed<E: Write>(out: &mut E, info: &ScanInfo) -> std::io::Result<()> {
    writeln!(
        out,
        "lakescan: no objects found under s3://{}/{}; check that the prefix is correct",
        info.bucket,
        info.prefix.as_deref().unwrap_or_default()
    )?;
    out.flush()
}

/// Explains [`ExitCode::ContentNotScanned`]: the undocumented files by
/// reason, how to document them, and, when most were refused, the
/// permissions content scanning needs.
fn write_not_scanned<E: Write>(out: &mut E, content: &ContentSummary) -> std::io::Result<()> {
    let coverage = content.coverage();
    let reasons: Vec<String> = NotScannedReason::ALL
        .into_iter()
        .filter(|&reason| content.not_scanned_unsuppressed(reason) > 0)
        .map(|reason| {
            format!(
                "{}={}",
                reason.code(),
                content.not_scanned_unsuppressed(reason)
            )
        })
        .collect();
    writeln!(
        out,
        "lakescan: {} of {} eligible Parquet files could not be content-scanned and are not \
         documented ({})",
        coverage.not_scanned_unsuppressed,
        coverage.files_eligible,
        reasons.join(", ")
    )?;
    writeln!(
        out,
        "lakescan: to accept a file that cannot be scanned, document it in --config with a \
         {} suppression: rule, key or prefix, reason, and optionally expires",
        RuleId::ContentNotScanned.code()
    )?;
    let denied = content.not_scanned_unsuppressed(NotScannedReason::AccessDenied);
    if denied.saturating_mul(2) > coverage.not_scanned_unsuppressed {
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
    /// Routes `finding`; returns whether a suppression covered it.
    fn route(&mut self, finding: Finding<'_>) -> Result<bool, LakeScanError> {
        if let Some(entry) = self.suppressor.matching(&finding) {
            self.aggregates.observe_suppressed(finding, entry);
            return Ok(true);
        }
        self.aggregates.observe_finding(finding);
        if let Some(writer) = self.findings.as_deref_mut() {
            writer.write(finding)?;
        }
        self.finding_count = self.finding_count.saturating_add(1);
        Ok(false)
    }
}

/// Pulls every page from `scanner`, feeding each object into the
/// aggregates and each finding it raises (listing rules, then, for an
/// eligible Parquet object, content scanning) through `sinks`, in listing
/// order, and rewrites the progress line after every page. Eligible files
/// are scanned as tasks, at most `concurrency` at once, their buffers held
/// only under the shared memory budget. Returns how many objects were
/// listed.
async fn walk<S, R, F, P>(
    scanner: &mut Scanner<S>,
    ctx: &EvalContext,
    content: Option<&mut Content<R>>,
    sinks: &mut Sinks<'_, F>,
    mut progress: Option<&mut P>,
) -> Result<u64, LakeScanError>
where
    S: PageSource,
    R: ObjectReader,
    F: Write,
    P: Write,
{
    let mut object_count: u64 = 0;
    let mut window = Window::default();

    while let Some(page) = scanner.next_page().await? {
        for object in page {
            let Some(content) = content.as_deref() else {
                // No content scanning: nothing to wait for, so no window.
                Window::apply_listed(object, ctx, sinks)?;
                continue;
            };
            match content::scope_of(object, content.sniff) {
                scope @ (Scope::Parquet | Scope::Sniff) => {
                    while window.scanning >= content.concurrency {
                        window.apply_front(ctx, sinks).await?;
                    }
                    window.push_scan(object, content, scope == Scope::Sniff);
                }
                scope => {
                    sinks.aggregates.observe_out_of_scope(&scope);
                    window.push(Slot::Listed(object.clone()));
                }
            }
            while window.slots.len() > content.concurrency + LOOKAHEAD {
                window.apply_front(ctx, sinks).await?;
            }
        }
        object_count = object_count.saturating_add(u64::try_from(page.len()).unwrap_or(u64::MAX));

        if let Some(out) = progress.as_deref_mut() {
            let files = if content.is_some() {
                format!(", {} parquet files", window.files_done)
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
    while !window.slots.is_empty() {
        window.apply_front(ctx, sinks).await?;
    }

    Ok(object_count)
}

/// A spawned file scan, aborted if dropped unfinished (a listing error
/// ends the run), which frees its permits.
struct ScanTask(tokio::task::JoinHandle<FileScan>);

impl Drop for ScanTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// One listed object waiting its turn.
enum Slot {
    /// Nothing to wait for.
    Listed(ObjectMeta),
    /// An eligible Parquet file being scanned.
    Scanning(ObjectMeta, ScanTask),
}

/// The ordered window: listed objects, in listing order, applied only from
/// the front, so results reach the sinks in listing order whatever order
/// the scans finish in.
#[derive(Default)]
struct Window {
    slots: VecDeque<Slot>,
    /// Scans in the window.
    scanning: usize,
    /// Scans applied.
    files_done: u64,
}

impl Window {
    fn push(&mut self, slot: Slot) {
        self.slots.push_back(slot);
    }

    /// Starts scanning `object` as a task, under its own budget account,
    /// sniffing it first if it has no Parquet extension.
    fn push_scan<R: ObjectReader>(
        &mut self,
        object: &ObjectMeta,
        content: &Content<R>,
        sniff: bool,
    ) {
        let reader = content.reader.clone();
        let file = object.clone();
        let options = content.options;
        let budget = content.budget.for_file();
        let task = tokio::spawn(async move {
            if sniff {
                content::sniff_and_scan(reader, &file, options, budget).await
            } else {
                content::scan_file(reader, &file, options, budget).await
            }
        });
        self.scanning += 1;
        self.slots
            .push_back(Slot::Scanning(object.clone(), ScanTask(task)));
    }

    /// Applies one listed object that needs no content scan: the
    /// aggregates and every listing finding.
    fn apply_listed<F: Write>(
        object: &ObjectMeta,
        ctx: &EvalContext,
        sinks: &mut Sinks<'_, F>,
    ) -> Result<(), LakeScanError> {
        sinks.aggregates.observe_object(object);
        for finding in rules::evaluate(object, ctx) {
            sinks.route(finding)?;
        }
        Ok(())
    }

    /// Applies the front object, waiting for its scan if it has one. A
    /// scan task that panicked or was cancelled is `unreadable`.
    async fn apply_front<F: Write>(
        &mut self,
        ctx: &EvalContext,
        sinks: &mut Sinks<'_, F>,
    ) -> Result<(), LakeScanError> {
        let Some(slot) = self.slots.pop_front() else {
            return Ok(());
        };
        match slot {
            Slot::Listed(object) => Self::apply_listed(&object, ctx, sinks),
            Slot::Scanning(object, mut task) => {
                Self::apply_listed(&object, ctx, sinks)?;
                let scan = (&mut task.0).await.unwrap_or_else(|_| FileScan {
                    outcome: FileOutcome::NotScanned(NotScannedReason::Unreadable),
                    columns: Vec::new(),
                    not_examined: Vec::new(),
                    stats: content::FileStats::default(),
                });
                self.scanning -= 1;
                self.files_done += 1;
                // Whether the file's content-not-scanned finding, if any,
                // was suppressed: that decides the exit code.
                let mut suppressed = false;
                for finding in scan.findings(&object) {
                    let covered = sinks.route(finding)?;
                    if finding.rule == RuleId::ContentNotScanned {
                        suppressed = covered;
                    }
                }
                sinks.aggregates.observe_content(&object, &scan, suppressed);
                Ok(())
            }
        }
    }
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
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use super::{CLEAR_LINE, Content, Outputs, scan, verdict};
    use crate::cli::target::Target;
    use crate::content::testing::{
        Layout, MemoryReader, Values, aadhaars, emails, mobiles, parquet_file,
    };
    use crate::content::{MemoryBudget, ScanOptions};
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
                inventory: None,
                html: None,
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
                    inventory: None,
                    html: None,
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
                inventory: None,
                html: None,
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
    async fn an_empty_listing_warns_on_stderr_and_still_exits_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        for (prefix, shown) in [
            (Some("does-not-exist/"), "s3://test-bucket/does-not-exist/"),
            (None, "s3://test-bucket/"),
        ] {
            let mut errors = Vec::new();
            let code = scan(
                source(vec![Step::Page(Vec::new(), None)]),
                Target {
                    bucket: "test-bucket".to_owned(),
                    prefix: prefix.map(str::to_owned),
                },
                Config::default(),
                Format::Text,
                Some(Severity::High),
                None::<Content<MemoryReader>>,
                Outputs {
                    summary: Vec::new(),
                    findings: None::<Vec<u8>>,
                    inventory: None,
                    html: None,
                    progress: None::<Vec<u8>>,
                    warnings: None::<Vec<u8>>,
                    errors: &mut errors,
                },
            )
            .await?;
            assert_eq!(code, ExitCode::Ok);
            assert_eq!(
                String::from_utf8(errors)?,
                format!(
                    "lakescan: no objects found under {shown}; check that the prefix is correct\n"
                )
            );
        }

        // A listing with objects says nothing.
        let mut errors = Vec::new();
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
                inventory: None,
                html: None,
                progress: None::<Vec<u8>>,
                warnings: None::<Vec<u8>>,
                errors: &mut errors,
            },
        )
        .await?;
        assert_eq!(errors, Vec::<u8>::new());
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
                inventory: None,
                html: None,
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
    /// inventory CSV, warnings and errors.
    struct ContentRun {
        code: ExitCode,
        summary: String,
        findings: String,
        inventory: String,
        html: String,
        warnings: String,
        errors: String,
    }

    /// How a test content run is set up.
    struct RunSettings {
        whole_file_max: u64,
        concurrency: usize,
        coalesce_gap: u64,
        memory_budget: u64,
        latency: crate::content::Latency,
        seed: u64,
        failing: Vec<&'static str>,
        /// Listing page size: files split into pages of this many.
        page: usize,
        sniff: crate::content::Sniff,
    }

    impl Default for RunSettings {
        fn default() -> Self {
            Self {
                whole_file_max: 8 * 1024 * 1024,
                concurrency: 4,
                coalesce_gap: crate::content::DEFAULT_COALESCE_GAP,
                memory_budget: crate::content::DEFAULT_MEMORY_BUDGET,
                latency: crate::content::Latency::NONE,
                seed: 1,
                failing: Vec::new(),
                page: 1000,
                sniff: crate::content::Sniff::Unknown,
            }
        }
    }

    /// Lists `files` (key, body) and scans them with `--pii` under
    /// `settings`; also returns the store and the budget, to inspect.
    async fn content_run_with(
        files: &[(&str, Vec<u8>)],
        config: Config,
        format: Format,
        settings: &RunSettings,
    ) -> Result<(ContentRun, MemoryReader, Arc<MemoryBudget>), Box<dyn std::error::Error>> {
        let reader = MemoryReader::new(settings.latency);
        reader.set_latency(settings.latency, settings.seed);
        let mut listed = Vec::new();
        for (key, body) in files {
            reader.insert(key, Arc::new(body.clone()));
            let mut listed_object = object(key, u64::try_from(body.len())?, StorageClass::Standard);
            // A fixed date, so runs compare equal.
            listed_object.last_modified = SystemTime::UNIX_EPOCH + Duration::from_hours(480_000);
            listed.push(listed_object);
        }
        for key in &settings.failing {
            reader.fail(key);
        }
        let budget = Arc::new(
            MemoryBudget::new(
                settings.memory_budget,
                settings.concurrency,
                crate::content::file_need(settings.whole_file_max),
            )
            .map_err(|_| "budget too small")?,
        );
        reader.watch(&budget);
        let mut pages: Vec<Step> = Vec::new();
        let chunks: Vec<Vec<ObjectMeta>> = listed
            .chunks(settings.page.max(1))
            .map(<[ObjectMeta]>::to_vec)
            .collect();
        let count = chunks.len();
        for (index, chunk) in chunks.into_iter().enumerate() {
            let token = (index + 1 < count).then(|| format!("tok-{index}"));
            pages.push(Step::Page(chunk, token));
        }
        if pages.is_empty() {
            pages.push(Step::Page(Vec::new(), None));
        }
        let (mut summary, mut findings, mut inventory, mut html, mut warnings, mut errors) = (
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let code = scan(
            source(pages),
            target(),
            config,
            format,
            Some(Severity::High),
            Some(Content {
                reader: reader.clone(),
                options: ScanOptions {
                    whole_file_max: settings.whole_file_max,
                    coalesce_gap: settings.coalesce_gap,
                },
                concurrency: settings.concurrency,
                budget: Arc::clone(&budget),
                sniff: settings.sniff,
            }),
            Outputs {
                summary: &mut summary,
                findings: Some(&mut findings),
                inventory: Some(&mut inventory),
                html: Some(&mut html),
                progress: None::<Vec<u8>>,
                warnings: Some(&mut warnings),
                errors: &mut errors,
            },
        )
        .await?;
        let run = ContentRun {
            code,
            summary: String::from_utf8(summary)?,
            findings: String::from_utf8(findings)?,
            inventory: String::from_utf8(inventory)?,
            html: String::from_utf8(html)?,
            warnings: String::from_utf8(warnings)?,
            errors: String::from_utf8(errors)?,
        };
        Ok((run, reader, budget))
    }

    /// Lists `files` (key, body) as one page and scans them with `--pii`,
    /// four at a time, reading everything at or below `whole_file_max`
    /// whole.
    async fn content_run(
        files: &[(&str, Vec<u8>)],
        config: Config,
        format: Format,
        whole_file_max: u64,
    ) -> Result<ContentRun, Box<dyn std::error::Error>> {
        let settings = RunSettings {
            whole_file_max,
            ..RunSettings::default()
        };
        Ok(content_run_with(files, config, format, &settings).await?.0)
    }

    /// Every committed fixture (tests/fixtures/parquet) under a lake-like
    /// key, several times over: readable files of four writers and three
    /// codecs, an escalation file, two bad files and a fully skipped one.
    /// `(key, body)` of each listed object.
    type Lake = Vec<(String, Vec<u8>)>;

    fn fixture_lake(copies: usize) -> Result<Lake, Box<dyn std::error::Error>> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/parquet");
        let paths = [
            "pyarrow/customers.parquet",
            "polars/customers.parquet",
            "duckdb/customers.parquet",
            "spark/customers.parquet",
            "gzip/pyarrow/customers.parquet",
            "gzip/spark/customers.parquet",
            "brotli/pyarrow/customers.parquet",
            "escalation.parquet",
            "bad/truncated.parquet",
            "bad/not_parquet.parquet",
            "skipped/too_large.parquet",
        ];
        let mut out = Vec::new();
        for copy in 0..copies {
            for (index, path) in paths.iter().enumerate() {
                let body = std::fs::read(root.join(path))?;
                out.push((format!("lake/t{index}/dt={copy}/part-0.parquet"), body));
                // A listing-only object between files: its findings must
                // keep their place in the stream.
                out.push((format!("lake/t{index}/dt={copy}/id_rsa"), b"key".to_vec()));
            }
        }
        Ok(out)
    }

    /// `text` without the lines and fields that time a run.
    fn untimed(text: &str) -> String {
        text.lines()
            .filter(|line| {
                !line.starts_with("started:")
                    && !line.starts_with("elapsed:")
                    && !line.contains("class=\"timing\"")
            })
            .map(|line| {
                let mut line = line.to_owned();
                // The settings record --concurrency, which these runs vary.
                for field in [
                    "\"started_at\":\"",
                    "\"startedAt\":\"",
                    "\"elapsed_ms\":",
                    "\"elapsedSeconds\":",
                    "\"concurrency\":",
                    "concurrency=",
                ] {
                    if let Some(at) = line.find(field) {
                        let from = at + field.len();
                        let end = line
                            .get(from..)
                            .and_then(|rest| rest.find([',', '}', ' ']))
                            .map_or(line.len(), |len| from + len);
                        line.replace_range(from..end, "");
                    }
                }
                line
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_output_is_identical_for_any_concurrency()
    -> Result<(), Box<dyn std::error::Error>> {
        let lake = fixture_lake(2)?;
        let files: Vec<(&str, Vec<u8>)> = lake
            .iter()
            .map(|(key, body)| (key.as_str(), body.clone()))
            .collect();
        let mut outputs = Vec::new();
        for (concurrency, seed, whole_file_max) in
            [(1, 7, 0), (64, 11, 0), (1, 3, 8 << 20), (64, 5, 8 << 20)]
        {
            // Random latency, so files finish in a different order each run.
            let settings = RunSettings {
                concurrency,
                whole_file_max,
                seed,
                latency: crate::content::Latency {
                    per_request: Duration::from_micros(100),
                    bytes_per_second: 0,
                    jitter: Duration::from_millis(3),
                },
                page: 7,
                ..RunSettings::default()
            };
            let mut runs = Vec::new();
            for format in [Format::Text, Format::Json] {
                let (run, _, _) =
                    content_run_with(&files, Config::default(), format, &settings).await?;
                runs.push(run);
            }
            outputs.push((whole_file_max, runs));
        }
        let render = |runs: &[ContentRun]| {
            runs.iter()
                .map(|run| {
                    format!(
                        "{:?}\n{}\n{}\n{}\n{}\n{}",
                        run.code,
                        untimed(&run.summary),
                        run.findings,
                        run.inventory,
                        untimed(&run.html),
                        run.errors
                    )
                })
                .collect::<Vec<_>>()
        };
        for pair in outputs.chunks(2) {
            let [(_, sequential), (_, concurrent)] = pair else {
                return Err("expected pairs".into());
            };
            assert_eq!(render(sequential), render(concurrent));
        }
        // And the runs did something: findings, both kinds of file.
        let first = outputs
            .first()
            .and_then(|(_, runs)| runs.first())
            .ok_or("no run")?;
        assert!(first.findings.contains("pii-email"));
        assert!(first.findings.contains("sensitive-key"));
        assert_eq!(first.code, ExitCode::ContentNotScanned);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn in_flight_bytes_never_exceed_the_memory_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let lake = fixture_lake(2)?;
        let files: Vec<(&str, Vec<u8>)> = lake
            .iter()
            .map(|(key, body)| (key.as_str(), body.clone()))
            .collect();
        // Partial reads (escalation and concurrent ranges included) and
        // whole ones, at a budget just above one file's need, with many
        // files in flight.
        for whole_file_max in [0, 8 << 20] {
            let need = crate::content::file_need(whole_file_max);
            let settings = RunSettings {
                concurrency: 32,
                whole_file_max,
                memory_budget: need + (4 << 20),
                latency: crate::content::Latency {
                    per_request: Duration::from_micros(200),
                    bytes_per_second: 0,
                    jitter: Duration::from_millis(2),
                },
                ..RunSettings::default()
            };
            let (run, store, budget) =
                content_run_with(&files, Config::default(), Format::Text, &settings).await?;
            assert!(run.summary.contains("PII INVENTORY"));
            assert!(store.requests() > 0);
            assert_eq!(store.unpermitted(), 0, "a fetch without permits");
            assert_eq!(store.over_budget(), 0, "over budget");
            assert!(
                budget.peak() <= settings.memory_budget,
                "peak {} over budget {}",
                budget.peak(),
                settings.memory_budget
            );
            assert!(budget.peak() > 0);
            assert_eq!(budget.held(), 0, "every permit released");
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_fetch_is_fetch_failed_and_fails_closed_unless_documented()
    -> Result<(), Box<dyn std::error::Error>> {
        let files = [
            ("lake/a.parquet", customers_file(50)?),
            ("lake/b.parquet", customers_file(50)?),
        ];
        let settings = RunSettings {
            failing: vec!["lake/b.parquet"],
            ..RunSettings::default()
        };
        let (run, _, _) =
            content_run_with(&files, Config::default(), Format::Json, &settings).await?;
        assert_eq!(run.code, ExitCode::ContentNotScanned);
        assert!(run.errors.contains("(fetch-failed=1)"), "{}", run.errors);
        assert!(
            run.findings.contains(r#""reason":"fetch-failed""#),
            "{}",
            run.findings
        );
        let summary: serde_json::Value = serde_json::from_str(&run.summary)?;
        assert_eq!(
            summary.pointer("/content/not_scanned/fetch-failed"),
            Some(&serde_json::json!(1))
        );

        let config = Config::parse(
            "version = 1\n[[suppress]]\nrule = \"content-not-scanned\"\n\
             key = \"lake/b.parquet\"\nreason = \"Restored from backup, INC-9\"\n",
            "test.toml",
        )?;
        let (run, _, _) = content_run_with(&files, config, Format::Json, &settings).await?;
        assert_eq!(run.code, ExitCode::FindingsExceedThreshold);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_panicking_decode_costs_one_file_under_concurrency()
    -> Result<(), Box<dyn std::error::Error>> {
        let rows = 100;
        let armed = parquet_file(
            &[
                ("email", Values::Text(emails(rows))),
                ("blows_up", Values::Text(emails(rows))),
            ],
            Layout::default(),
        )?;
        let mut files = vec![("lake/armed.parquet", armed)];
        let keys: Vec<String> = (0..12).map(|i| format!("lake/ok-{i:02}.parquet")).collect();
        for key in &keys {
            files.push((key.as_str(), customers_file(rows)?));
        }
        crate::content::read_fault::arm("blows_up");
        let settings = RunSettings {
            concurrency: 8,
            ..RunSettings::default()
        };
        let result = content_run_with(&files, Config::default(), Format::Json, &settings).await;
        crate::content::read_fault::disarm("blows_up");
        let (run, _, _) = result?;
        let summary: serde_json::Value = serde_json::from_str(&run.summary)?;
        assert_eq!(
            summary.pointer("/content/not_scanned/unreadable"),
            Some(&serde_json::json!(1))
        );
        assert_eq!(
            summary.pointer("/coverage/files_scanned"),
            Some(&serde_json::json!(12))
        );
        Ok(())
    }

    #[tokio::test]
    async fn hostile_names_render_as_inert_text_in_the_html_report()
    -> Result<(), Box<dyn std::error::Error>> {
        let hostile = [
            "<script>alert(1)</script>",
            "</script>",
            "\"><img src=x onerror=alert(1)>",
            "esc\u{1b}[31m",
            "rtl\u{202e}gnp.exe",
        ];
        let rows = 100;
        let columns: Vec<(&str, Values)> = hostile
            .iter()
            .map(|name| (*name, Values::Text(emails(rows))))
            .collect();
        let body = parquet_file(&columns, Layout::default())?;
        let keys: Vec<String> = hostile
            .iter()
            .map(|name| format!("lake/{name}/dt=1/part-0.parquet"))
            .collect();
        let mut files: Vec<(&str, Vec<u8>)> = keys
            .iter()
            .map(|key| (key.as_str(), body.clone()))
            .collect();
        // A documented reason that is hostile too, and an unreadable file
        // under a hostile name.
        let bad = "lake/<b>bad</b>/x.parquet";
        files.push((bad, b"PAR1 not really".to_vec()));
        let config = Config::parse(
            "version = 1\n[[suppress]]\nrule = \"pii-email\"\nprefix = \"lake/\"\n\
             column = \"</script>\"\nreason = \"<script>alert('reason')</script>\"\n",
            "test.toml",
        )?;
        let (run, _, _) =
            content_run_with(&files, config, Format::Text, &RunSettings::default()).await?;
        let html = run.html;
        let data = html
            .lines()
            .find(|line| line.trim_start().starts_with("const DATA = "))
            .and_then(|line| line.trim_start().strip_prefix("const DATA = "))
            .and_then(|line| line.strip_suffix(';'))
            .ok_or("no DATA line")?;
        assert!(!data.contains('<'), "{data}");
        assert!(data.contains("\\u003c/script>"), "{data}");
        let value: serde_json::Value = serde_json::from_str(data)?;
        let columns = value
            .get("columns")
            .and_then(serde_json::Value::as_array)
            .ok_or("no columns")?;
        let names: Vec<&str> = columns
            .iter()
            .filter_map(|row| row.get("column").and_then(serde_json::Value::as_str))
            .collect();
        for name in &hostile {
            assert!(names.contains(name), "{name:?} missing from {names:?}");
        }
        let reason = columns
            .iter()
            .find(|row| row.get("column").and_then(serde_json::Value::as_str) == Some("</script>"));
        assert_eq!(
            reason
                .and_then(|row| row.get("reason"))
                .and_then(serde_json::Value::as_str),
            Some("<script>alert('reason')</script>")
        );
        assert!(data.contains("\\u001b"), "{data}");
        for raw in ["<script>alert", "<img", "<b>", "\u{1b}"] {
            assert!(!html.contains(raw), "{raw:?} reached the page");
        }
        assert_eq!(
            html.matches("<script").count(),
            2,
            "only the page's two scripts"
        );
        assert_eq!(html.matches("</script>").count(), 2);
        Ok(())
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
                inventory: None,
                html: None,
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
            "lakescan: 2 of 2 eligible Parquet files could not be content-scanned and are not \
             documented (not-parquet=1, unreadable=1)\n\
             lakescan: to accept a file that cannot be scanned, document it in --config with a \
             content-not-scanned suppression: rule, key or prefix, reason, and optionally \
             expires\n"
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
            not_examined: Vec::new(),
            stats: crate::content::FileStats::default(),
        };
        let file = object("t/a.parquet", 10, StorageClass::Standard);
        summary.observe_content(&file, &scan(NotScannedReason::AccessDenied), false);
        summary.observe_content(&file, &scan(NotScannedReason::AccessDenied), false);
        summary.observe_content(&file, &scan(NotScannedReason::NotParquet), false);
        // A documented file is left out of the message.
        summary.observe_content(&file, &scan(NotScannedReason::Encrypted), true);
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
        let rows = 340_000;
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
        assert!(
            run.errors.starts_with(
                "lakescan: 1 of 1 eligible Parquet files could not be content-scanned and are \
                 not documented (no-column-examined=1)\n"
            ),
            "{}",
            run.errors
        );
        assert!(run.summary.contains("page-too-large=1"), "{}", run.summary);
        Ok(())
    }

    #[tokio::test]
    async fn one_undocumented_unscannable_file_fails_closed_until_it_is_documented()
    -> Result<(), Box<dyn std::error::Error>> {
        let files = [
            ("lake/t/dt=1/bad.parquet", b"nope".to_vec()),
            ("lake/t/dt=2/good.parquet", customers_file(50)?),
            ("lake/t/dt=3/good.parquet", customers_file(50)?),
        ];
        // One bad file among readable ones fails closed, and exit 6 wins
        // over the confirmed (High) PII that would otherwise give exit 1.
        let run = content_run(&files, Config::default(), Format::Text, 8 * 1024 * 1024).await?;
        assert_eq!(run.code, ExitCode::ContentNotScanned);
        assert!(run.errors.contains("1 of 3 eligible"), "{}", run.errors);
        assert!(run.summary.contains("COVERAGE"), "{}", run.summary);
        assert!(
            run.summary.contains("scanned:        2 (66.6%)"),
            "{}",
            run.summary
        );

        // Documented, the file no longer fails the run: it exits by
        // severity, and coverage says why.
        let config = Config::parse(
            "version = 1\n[[suppress]]\nrule = \"content-not-scanned\"\n\
             key = \"lake/t/dt=1/bad.parquet\"\nreason = \"Known corrupt export\"\n",
            "test.toml",
        )?;
        let run = content_run(&files, config, Format::Json, 8 * 1024 * 1024).await?;
        assert_eq!(run.code, ExitCode::FindingsExceedThreshold);
        assert_eq!(run.errors, "");
        let summary: serde_json::Value = serde_json::from_str(&run.summary)?;
        assert_eq!(
            summary.get("coverage"),
            Some(&serde_json::json!({
                "files_eligible": 3,
                "files_scanned": 2,
                "not_scanned_suppressed": 1,
                "not_scanned_unsuppressed": 0,
                "percent": 66.6,
                "columns_not_examined": {
                    "total": 0,
                    "files": 0,
                    "tables": 0,
                    "by_reason": {
                        "unsupported-type": 0,
                        "page-too-large": 0,
                        "unreadable": 0,
                        "unsupported-codec": 0
                    },
                    "examples": [],
                    "examples_truncated": false
                },
                "out_of_scope": {
                    "objects": 0,
                    "by_extension": [],
                    "other_extensions": 0,
                    "sniffed_not_parquet": 0,
                    "empty": 0
                },
                "sampling": {
                    "method": crate::report::SAMPLING_METHOD,
                    "exhaustive": false
                }
            }))
        );
        assert_eq!(
            summary.pointer("/pii_inventory/tables/0/not_scanned/not-parquet"),
            Some(&serde_json::json!({ "suppressed": 1, "unsuppressed": 0 }))
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_inventory_groups_files_into_tables_and_exports_csv()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = Config::parse(
            r#"
version = 1

[[suppress]]
rule = "pii-email"
prefix = "lake/crm/"
column = "email"
reason = "Consented contacts, see DPA-12"
"#,
            "test.toml",
        )?;
        let run = content_run(
            &[
                ("lake/crm/dt=2026-01-01/a.parquet", customers_file(100)?),
                ("lake/crm/dt=2026-01-02/b.parquet", customers_file(100)?),
                ("lake/=bad,\"name\"/data/c.parquet", customers_file(100)?),
            ],
            config,
            Format::Text,
            8 * 1024 * 1024,
        )
        .await?;
        assert!(
            run.summary.contains(
                "  lake/crm  files: 2 scanned, 0 not scanned; files dated 2024-10-04 to \
                 2024-10-04\n    example: lake/crm/dt=2026-01-01/a.parquet\n"
            ),
            "{}",
            run.summary
        );
        assert!(
            run.summary.contains(
                "    email  pii-email  confirmed  evidence=values  2 files, documented: Consented \
                 contacts, see DPA-12\n"
            ),
            "{}",
            run.summary
        );
        let rows = crate::report::parse_csv(&run.inventory).ok_or("invalid CSV")?;
        assert_eq!(
            rows.first().map(|header| header.join(",")),
            Some(
                "table,column,rule,highest_confidence,evidence,files_confirmed,files_likely,\
                 files_possible,files_suppressed,status,reason,example_key,oldest_file,\
                 newest_file,expires,not_examined_reason"
                    .to_owned()
            )
        );
        let cells = |table: &str, column: &str| {
            rows.iter()
                .find(|row| {
                    row.first().map(String::as_str) == Some(table)
                        && row.get(1).map(String::as_str) == Some(column)
                })
                .cloned()
                .unwrap_or_default()
        };
        assert_eq!(
            cells("lake/crm", "email"),
            [
                "lake/crm",
                "email",
                "pii-email",
                "confirmed",
                "values",
                "0",
                "0",
                "0",
                "2",
                "documented",
                "Consented contacts, see DPA-12",
                "lake/crm/dt=2026-01-01/a.parquet",
                "2024-10-04T00:00:00Z",
                "2024-10-04T00:00:00Z",
                "",
                ""
            ]
        );
        let odd = cells("lake/=bad,\"name\"", "mobile_no");
        assert_eq!(odd.get(9).map(String::as_str), Some("UNDOCUMENTED"));
        assert_eq!(odd.get(5).map(String::as_str), Some("1"));
        // 3 columns in each of 2 tables, plus the header.
        assert_eq!(rows.len(), 7);
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
    /// every output (text and JSON summaries, the findings stream, the
    /// inventory CSV, the HTML report, warnings, errors) and check none of
    /// it appears anywhere: not from flat columns, not from a repeated one
    /// (read since M12), not from one that could not be examined (a phone
    /// stored as a double), whose state every output reports instead.
    #[tokio::test]
    async fn no_sampled_value_reaches_any_output() -> Result<(), Box<dyn std::error::Error>> {
        let rows = 300;
        let seeded_emails = emails(rows);
        let seeded_phones = mobiles(rows);
        let seeded_aadhaar = aadhaars(rows);
        let names: Vec<Option<String>> = (0..rows)
            .map(|i| Some(format!("Seeded Person {i:03}")))
            .collect();
        let listed: Vec<Vec<String>> = (0..rows)
            .map(|i| vec![format!("listed.{i}@mail.example")])
            .collect();
        let home_phones: Vec<f64> = (0..rows)
            .map(|i| 9_123_000_000.0 + f64::from(u32::try_from(i).unwrap_or(0)))
            .collect();
        let unchecked = parquet_file(
            &[
                ("contact_emails", Values::List(listed.clone())),
                ("home_phone", Values::Double(home_phones.clone())),
            ],
            Layout::default(),
        )?;
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
        values.extend(listed.into_iter().flatten());
        values.extend(home_phones.iter().map(f64::to_string));

        let config = Config::parse(
            "version = 1\n[[suppress]]\nrule = \"pii-phone\"\nprefix = \"zzz/\"\n\
             column = \"mobile_no\"\nreason = \"unused on purpose\"\n",
            "test.toml",
        )?;
        let files = [
            ("pii/a.parquet", body.clone()),
            ("pii/b.parquet", body),
            ("pii/broken.parquet", b"PAR1 truncated".to_vec()),
            ("unchecked/a.parquet", unchecked),
        ];
        let mut outputs = String::new();
        for (format, whole_file_max) in [(Format::Text, 8 * 1024 * 1024), (Format::Json, 0)] {
            let run = content_run(&files, config.clone(), format, whole_file_max).await?;
            // The broken file is undocumented, so the run fails closed.
            assert_eq!(run.code, ExitCode::ContentNotScanned);
            assert!(run.html.contains("PII inventory"));
            for text in [
                run.summary,
                run.findings,
                run.inventory,
                run.html,
                run.warnings,
                run.errors,
            ] {
                outputs.push_str(&text);
            }
        }
        assert!(outputs.contains("mobile_no"), "the outputs were produced");
        // The repeated column was read and found; the double is reported
        // as not examined, in every format.
        assert!(outputs.contains("contact_emails.list.element"));
        for state in [
            "columns not examined: 1 in 1 file (unsupported-type=1)",
            "\"columns_not_examined\"",
            "NOT_EXAMINED",
            "\"unsupportedType\":1",
        ] {
            assert!(
                outputs.contains(state),
                "{state:?} missing from the outputs"
            );
        }
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
                inventory: None,
                html: None,
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

    /// A lake as Athena CTAS writes it: Parquet files with no extension,
    /// beside a `_SUCCESS` marker, a CSV export with no extension, and a
    /// JSON log.
    type LakeFile = (&'static str, Vec<u8>);

    fn athena_lake() -> Result<Vec<LakeFile>, Box<dyn std::error::Error>> {
        Ok(vec![
            (
                "athena/crm/20261016_101010_00007_abcde_0b3f",
                customers_file(100)?,
            ),
            ("athena/crm/_SUCCESS", Vec::new()),
            (
                "athena/exports/today",
                b"customer_id,email\n1,someone@example.org\n".to_vec(),
            ),
            ("logs/app.json", b"{\"level\":\"info\"}\n".to_vec()),
        ])
    }

    #[tokio::test]
    async fn extensionless_parquet_is_sniffed_scanned_and_its_cost_counted()
    -> Result<(), Box<dyn std::error::Error>> {
        let files = athena_lake()?;
        let run = content_run(&files, Config::default(), Format::Json, 8 << 20).await?;
        assert_eq!(run.code, ExitCode::FindingsExceedThreshold);
        let summary: serde_json::Value = serde_json::from_str(&run.summary)?;
        let at = |pointer: &str| summary.pointer(pointer).cloned();
        assert_eq!(at("/content/files_eligible"), Some(serde_json::json!(1)));
        // Both extensionless objects were sniffed: one GET each, counted.
        assert_eq!(at("/content/sniffed"), Some(serde_json::json!(2)));
        assert_eq!(
            at("/coverage/out_of_scope"),
            Some(serde_json::json!({
                "objects": 3,
                "by_extension": [{ "extension": "json", "count": 1 }],
                "other_extensions": 0,
                "sniffed_not_parquet": 1,
                "empty": 1
            }))
        );
        // Every listed object is either a Parquet file or out of scope.
        assert_eq!(at("/inventory/object_count"), Some(serde_json::json!(4)));
        assert_eq!(
            at("/pii_inventory/tables/0/table"),
            Some(serde_json::json!("athena/crm"))
        );
        assert_eq!(
            at("/pii_inventory/tables/0/status"),
            Some(serde_json::json!("pii_found"))
        );
        assert_eq!(
            at("/scan/settings/pii_sniff"),
            Some(serde_json::json!("unknown"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn without_sniffing_an_extensionless_lake_is_reported_out_of_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let files = athena_lake()?;
        let settings = RunSettings {
            sniff: crate::content::Sniff::None,
            ..RunSettings::default()
        };
        let (run, store, _) =
            content_run_with(&files, Config::default(), Format::Text, &settings).await?;
        // Nothing scanned and nothing found: exit 0, but the summary says
        // what was left out instead of reading as clean.
        assert_eq!(run.code, ExitCode::Ok);
        assert_eq!(store.requests(), 0);
        assert!(
            run.summary.contains(
                "  Not in scope for --pii: 2 (no extension), 1 .json (LakeScan reads Parquet \
                 content only)\n"
            ),
            "{}",
            run.summary
        );
        assert!(run.summary.contains("sniff=none"), "{}", run.summary);
        Ok(())
    }

    #[tokio::test]
    async fn pii_only_in_an_unsampled_row_group_is_missed_and_the_result_says_sampled()
    -> Result<(), Box<dyn std::error::Error>> {
        // The adversarial file: row group 0 holds 1,000 plain references,
        // clearly not PII, so sampling stops there; emails fill row groups
        // 1 to 3, which the read plan never reaches.
        let mut values: Vec<Option<String>> =
            (0..1000).map(|i| Some(format!("ref-{i:05}"))).collect();
        values.extend(emails(3000));
        let body = parquet_file(
            &[("note_ref", Values::Text(values))],
            Layout {
                row_group_rows: 1000,
                ..Layout::default()
            },
        )?;
        let files = [("lake/hidden/part-0.parquet", body)];
        for whole_file_max in [0, 8 << 20] {
            let json = content_run(&files, Config::default(), Format::Json, whole_file_max).await?;
            assert_eq!(json.code, ExitCode::Ok, "no finding");
            assert_eq!(json.findings, "");
            let summary: serde_json::Value = serde_json::from_str(&json.summary)?;
            assert_eq!(
                summary.pointer("/pii_inventory/tables/0/status"),
                Some(&serde_json::json!("no_pii_in_scanned_files"))
            );
            assert_eq!(
                summary.pointer("/coverage/sampling/exhaustive"),
                Some(&serde_json::json!(false))
            );
            let text = content_run(&files, Config::default(), Format::Text, whole_file_max).await?;
            assert!(
                text.summary
                    .contains("    No structured PII detected in sampled data from 1 file\n"),
                "{}",
                text.summary
            );
            assert!(text.summary.contains("  inspection:     sampled: "));
            assert!(text.html.contains("Inspection is sampled: "));
        }
        // And the README's limitations describe exactly this case.
        let readme = include_str!("../../README.md");
        let limitations = readme
            .split("\n## Limitations\n")
            .nth(1)
            .and_then(|rest| rest.split("\n## ").next())
            .unwrap_or_default();
        assert!(
            limitations.contains(
                "Personal data that appears only in row groups or pages the sample does not \
                 reach is missed"
            ),
            "{limitations}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_truncated_inventory_is_warned_about_on_stderr()
    -> Result<(), Box<dyn std::error::Error>> {
        // One more table than the inventory holds. The files need not be
        // Parquet: unscannable ones count in their tables all the same.
        let keys: Vec<String> = (0..=crate::aggregate::MAX_TABLES)
            .map(|n| format!("lake/t{n:05}/part-0.parquet"))
            .collect();
        let files: Vec<(&str, Vec<u8>)> = keys
            .iter()
            .map(|key| (key.as_str(), b"not parquet at all".to_vec()))
            .collect();
        let run = content_run(&files, Config::default(), Format::Json, 8 << 20).await?;
        assert!(
            run.errors.contains(
                "lakescan: warning: the PII inventory is truncated: 1 files and 0 findings were \
                 left out over its caps (4096 tables, 16384 entries)"
            ),
            "{}",
            run.errors
        );
        let summary: serde_json::Value = serde_json::from_str(&run.summary)?;
        assert_eq!(
            summary.pointer("/pii_inventory/truncated"),
            Some(&serde_json::json!(true))
        );
        Ok(())
    }
}
