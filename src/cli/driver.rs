//! The scan driver: wires `scanner` → `rules` → `suppress` → `aggregate` →
//! `report` for one run and decides the run's [`ExitCode`].
//!
//! The driver never opens a destination itself. The summary, the optional
//! findings stream, the optional progress line, and the optional
//! suppression warnings all arrive as writers,
//! which is what lets the tests below run a whole scan against in-memory
//! buffers and a scripted [`PageSource`].

use std::io::Write;
use std::time::{Instant, SystemTime};

use super::target::Target;
use crate::aggregate::Aggregates;
use crate::error::{ExitCode, LakeScanError};
use crate::model::Severity;
use crate::report::{self, FindingsWriter, Format, ScanInfo};
use crate::rules::{self, EvalContext};
use crate::scanner::{PageSource, Scanner};
use crate::suppress::{Config, Date, Entry, Outcome, Suppressor};

/// Clears the current terminal line: carriage return, then ANSI "erase
/// entire line".
const CLEAR_LINE: &str = "\r\x1b[2K";

/// Where one scan's output goes.
pub(crate) struct Outputs<O, F, P, D> {
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
}

/// Runs one scan of `source` to completion and returns its verdict:
/// [`ExitCode::FindingsExceedThreshold`] when the worst finding's severity
/// is at or above `fail_on`, otherwise [`ExitCode::Ok`]. `fail_on` of
/// `None` never fails on findings.
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
pub(crate) async fn scan<S, O, F, P, D>(
    source: S,
    target: Target,
    config: Config,
    format: Format,
    fail_on: Option<Severity>,
    outputs: Outputs<O, F, P, D>,
) -> Result<ExitCode, LakeScanError>
where
    S: PageSource,
    O: Write,
    F: Write,
    P: Write,
    D: Write,
{
    let started_at = SystemTime::now();
    let clock = Instant::now();
    let ctx = EvalContext { now: started_at };
    // Boxed: `Aggregates` is ~110 KiB of fixed-size summaries, which would
    // otherwise sit inline in this function's future.
    let mut aggregates = Box::new(Aggregates::new(started_at));
    let mut suppressor = Suppressor::new(config, &target.bucket, Date::utc_of(started_at));

    let Outputs {
        summary,
        findings,
        mut progress,
        warnings,
    } = outputs;
    let mut findings = findings.map(FindingsWriter::new);

    let listed = walk(
        &mut Scanner::new(source),
        &ctx,
        &mut aggregates,
        &mut suppressor,
        findings.as_mut(),
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

    Ok(verdict(aggregates.worst_severity(), fail_on))
}

/// One line per expired, then per unused, suppression entry.
fn write_warnings<D: Write>(out: &mut D, outcome: &Outcome) -> std::io::Result<()> {
    let line = |out: &mut D, state: &str, entry: &Entry| {
        let expires = entry
            .expires
            .map(|date| format!(" (expires {date})"))
            .unwrap_or_default();
        writeln!(
            out,
            "lakescan: warning: {state} suppression for {}, {}{expires}: {:?}",
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

/// Pulls every page from `scanner`, feeding each object into `aggregates`
/// and each finding it raises through `suppressor` — suppressed ones to
/// [`Aggregates::observe_suppressed`], the rest to the findings matrix and
/// `findings`, if given — and rewrites the progress line after every page.
async fn walk<S, F, P>(
    scanner: &mut Scanner<S>,
    ctx: &EvalContext,
    aggregates: &mut Aggregates,
    suppressor: &mut Suppressor,
    mut findings: Option<&mut FindingsWriter<F>>,
    mut progress: Option<&mut P>,
) -> Result<(), LakeScanError>
where
    S: PageSource,
    F: Write,
    P: Write,
{
    let mut object_count: u64 = 0;
    let mut finding_count: u64 = 0;

    while let Some(page) = scanner.next_page().await? {
        for object in page {
            aggregates.observe_object(object);
            for finding in rules::evaluate(object, ctx) {
                if suppressor.suppresses(&finding) {
                    aggregates.observe_suppressed(finding);
                    continue;
                }
                aggregates.observe_finding(finding);
                if let Some(writer) = findings.as_deref_mut() {
                    writer.write(finding)?;
                }
                finding_count = finding_count.saturating_add(1);
            }
        }
        object_count = object_count.saturating_add(u64::try_from(page.len()).unwrap_or(u64::MAX));

        if let Some(out) = progress.as_deref_mut() {
            // Best effort, as above.
            let _ = write!(
                out,
                "{CLEAR_LINE}scanned {object_count} objects, {finding_count} findings"
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

    use super::{CLEAR_LINE, Outputs, scan, verdict};
    use crate::cli::target::Target;
    use crate::error::{ExitCode, LakeScanError};
    use crate::model::{ObjectMeta, Severity, StorageClass};
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
            Outputs {
                summary: &mut summary,
                findings: Some(&mut findings),
                progress: None::<Vec<u8>>,
                warnings: None::<Vec<u8>>,
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
                Outputs {
                    summary: Vec::new(),
                    findings: None::<Vec<u8>>,
                    progress: None::<Vec<u8>>,
                    warnings: None::<Vec<u8>>,
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
            Outputs {
                summary: Vec::new(),
                findings: None::<Vec<u8>>,
                progress: Some(&mut progress),
                warnings: None::<Vec<u8>>,
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
            Outputs {
                summary: &mut summary,
                findings: None::<Vec<u8>>,
                progress: Some(&mut progress),
                warnings: None::<Vec<u8>>,
            },
        )
        .await;

        assert!(matches!(result, Err(LakeScanError::Transport(_))));
        assert_eq!(summary, Vec::<u8>::new());
        assert!(progress.ends_with(CLEAR_LINE.as_bytes()));
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
            Outputs {
                summary: &mut summary,
                findings: Some(&mut findings),
                progress: None::<Vec<u8>>,
                warnings: Some(&mut warnings),
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
