//! What `lakescan scan` adds for a person at a terminal: the `--color`
//! decision and the result block printed on stderr at the end.
//!
//! Everything here is for stderr and for stdout-as-a-terminal only. The
//! rendering functions take plain values (a [`Style`], `bool`s, paths) and
//! return a `String`, so they are tested without a real terminal. Nothing
//! here is ever applied to bucket-derived text: the block holds `LakeScan`'s
//! own words, numbers from the run's aggregates, and the paths the person
//! gave on the command line.

use std::path::{Path, PathBuf};

use clap::ValueEnum;

use super::driver::RunFacts;
use crate::error::ExitCode;
use crate::model::Severity;
use crate::report::{Style, escaped};

/// `--color`.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ColorChoice {
    Auto,
    Always,
    Never,
}

/// What the environment says about the terminal.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct TermEnv {
    /// `NO_COLOR` is set to a non-empty value.
    pub(super) no_color: bool,
    /// `TERM` is `dumb`: no colour, and no way to redraw a line.
    pub(super) dumb: bool,
}

impl TermEnv {
    /// Reads `NO_COLOR` and `TERM` from the process environment.
    pub(super) fn from_env() -> Self {
        Self {
            no_color: std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()),
            dumb: std::env::var_os("TERM").is_some_and(|value| value == "dumb"),
        }
    }
}

/// Whether to colour a stream: `always` and `never` are absolute, `auto`
/// colours a terminal unless `NO_COLOR` is set or `TERM` is `dumb`.
pub(super) fn style_for(choice: ColorChoice, is_terminal: bool, env: TermEnv) -> Style {
    Style::new(match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => is_terminal && !env.no_color && !env.dumb,
    })
}

/// Whether the text summary is the compact one: only when it goes to
/// stdout, stdout is a terminal, and `--full` was not given.
pub(super) const fn summary_is_compact(to_stdout: bool, is_terminal: bool, full: bool) -> bool {
    to_stdout && is_terminal && !full
}

/// The files a run wrote, for the block's next steps.
#[derive(Debug, Default)]
pub(super) struct Written {
    /// `--html`, if it went to a file.
    pub(super) html: Option<PathBuf>,
    /// Every file written (summary, findings, inventory, HTML), in that
    /// order; stdout is not a file.
    pub(super) files: Vec<PathBuf>,
}

/// The command that opens a file in the default application on this OS.
pub(super) const fn opener() -> Option<&'static str> {
    if cfg!(target_os = "macos") {
        Some("open")
    } else if cfg!(target_os = "linux") {
        Some("xdg-open")
    } else {
        None
    }
}

/// The result block: a verdict that never calls a scan clean, what needs
/// attention, how much was inspected, and what to do next. Each line starts
/// with a newline-free label so the block reads as a short list; it ends
/// with a newline.
pub(super) fn result_block(
    facts: &RunFacts,
    written: &Written,
    style: Style,
    opener: Option<&str>,
) -> String {
    let mut lines = vec![String::new(), verdict_line(facts, style)];

    if let Some(pii) = &facts.pii {
        lines.push(if pii.undocumented == 0 {
            "  No undocumented PII columns in the sampled data.".to_owned()
        } else {
            let noun = if pii.undocumented == 1 {
                "column is"
            } else {
                "columns are"
            };
            format!(
                "  {} PII {noun} undocumented ({} confirmed, {} likely, {} possible).",
                pii.undocumented,
                pii.undocumented_confirmed,
                pii.undocumented_likely,
                pii.undocumented_possible
            )
        });
    } else {
        lines.push(
            "  Scope: object listing only (keys, sizes, dates, storage classes). No object \
             contents were read; add --pii to scan Parquet files for personal data."
                .to_owned(),
        );
    }
    if let Some(coverage) = &facts.coverage {
        let percent = coverage
            .percent
            .map_or_else(String::new, |percent| format!(" ({percent:.1}%)"));
        lines.push(format!(
            "  Coverage: {} of {} Parquet files scanned{percent}. Inspection is sampled: a \
             column or file with no finding may still hold personal data in rows that were not \
             read.",
            coverage.files_scanned, coverage.files_eligible
        ));
    }

    lines.push(style.heading("Next steps:"));
    if let (Some(html), Some(opener)) = (&written.html, opener) {
        lines.push(format!(
            "  Open the dashboard:  {opener} {}",
            shell_quoted(html)
        ));
    }
    lines.push(
        "  To record a reviewed finding or a file that cannot be scanned, see the Suppressions \
         section of the README (--config)."
            .to_owned(),
    );
    if !written.files.is_empty() {
        let files: Vec<String> = written.files.iter().map(|path| shown(path)).collect();
        lines.push(format!("  Wrote:  {}", files.join(", ")));
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// The first line: the exit code and what it means for this run.
fn verdict_line(facts: &RunFacts, style: Style) -> String {
    let code = facts.code.as_i32();
    match facts.code {
        ExitCode::Ok => {
            let meaning = match facts.fail_on {
                Some(level) => format!(
                    "no unsuppressed finding reached --fail-on {}. That is a statement about \
                     this threshold, not a clean bill of health.",
                    level.code()
                ),
                None => "--fail-on none: findings do not fail the run. Read the summary for \
                         what was found."
                    .to_owned(),
            };
            format!(
                "{} {meaning}",
                style.heading(&format!("Result: exit {code}."))
            )
        }
        ExitCode::FindingsExceedThreshold => {
            let level = facts.fail_on.map_or("the threshold", Severity::code);
            let worst = facts
                .worst
                .map_or_else(String::new, |worst| format!(" Worst: {}.", worst.code()));
            format!(
                "{} An unsuppressed finding reached --fail-on {level}.{worst}",
                style.heading(&format!("Result: exit {code}."))
            )
        }
        _ => format!(
            "{} Coverage is incomplete (details above), so the run fails whatever the findings \
             say.",
            style.alert(&format!("Result: exit {code}."))
        ),
    }
}

/// `path` for display: control characters escaped.
fn shown(path: &Path) -> String {
    escaped(&path.to_string_lossy())
}

/// `path` as one shell word: bare if it only has safe characters, else in
/// single quotes. Control characters are escaped first.
fn shell_quoted(path: &Path) -> String {
    let text = shown(path);
    let safe = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./:@+,=~".contains(c));
    if safe {
        text
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        ColorChoice, TermEnv, Written, result_block, shell_quoted, style_for, summary_is_compact,
    };
    use crate::aggregate::{Coverage, InventorySummary};
    use crate::cli::driver::RunFacts;
    use crate::error::ExitCode;
    use crate::model::Severity;
    use crate::report::Style;

    fn summary(undocumented: u64) -> InventorySummary {
        InventorySummary {
            tables_with_pii: 2,
            pii_columns: 30,
            undocumented,
            undocumented_confirmed: undocumented.min(24),
            undocumented_likely: undocumented.saturating_sub(24).min(4),
            undocumented_possible: undocumented.saturating_sub(28),
            documented: 30 - undocumented.min(30),
            tables_not_fully_scanned: 0,
            tables_not_fully_scanned_documented: 0,
            tables_with_columns_not_examined: 0,
        }
    }

    fn facts(code: ExitCode) -> RunFacts {
        RunFacts {
            code,
            fail_on: Some(Severity::High),
            worst: Some(Severity::High),
            pii: Some(summary(30)),
            coverage: Some(Coverage {
                files_eligible: 11,
                files_scanned: 9,
                not_scanned_suppressed: 0,
                not_scanned_unsuppressed: u64::from(code == ExitCode::ContentNotScanned) * 2,
                percent: Some(81.8),
            }),
        }
    }

    fn block(facts: &RunFacts, style: Style) -> String {
        let written = Written {
            html: Some(PathBuf::from("report.html")),
            files: vec![PathBuf::from("report.html"), PathBuf::from("inv.csv")],
        };
        result_block(facts, &written, style, Some("open"))
    }

    #[test]
    fn only_a_terminal_summary_without_full_is_compact() {
        assert!(summary_is_compact(true, true, false));
        // --full on a terminal: the whole summary.
        assert!(!summary_is_compact(true, true, true));
        // Piped or redirected stdout, or --output: the whole summary.
        assert!(!summary_is_compact(true, false, false));
        assert!(!summary_is_compact(false, true, false));
        assert!(!summary_is_compact(false, false, false));
    }

    #[test]
    fn plain_style_emits_no_escape_bytes() {
        for code in [
            ExitCode::Ok,
            ExitCode::FindingsExceedThreshold,
            ExitCode::ContentNotScanned,
        ] {
            let text = block(&facts(code), Style::PLAIN);
            assert!(!text.contains('\x1b'), "{code:?}: {text:?}");
        }
    }

    #[test]
    fn colour_only_when_asked_and_allowed() {
        let env = TermEnv::default();
        assert!(style_for(ColorChoice::Auto, true, env).is_on());
        assert!(!style_for(ColorChoice::Auto, false, env).is_on());
        assert!(!style_for(ColorChoice::Never, true, env).is_on());
        assert!(style_for(ColorChoice::Always, false, env).is_on());
    }

    #[test]
    fn no_color_and_a_dumb_terminal_turn_auto_off() {
        let no_color = TermEnv {
            no_color: true,
            dumb: false,
        };
        let dumb = TermEnv {
            no_color: false,
            dumb: true,
        };
        assert!(!style_for(ColorChoice::Auto, true, no_color).is_on());
        assert!(!style_for(ColorChoice::Auto, true, dumb).is_on());
        // An explicit flag beats the environment.
        assert!(style_for(ColorChoice::Always, true, no_color).is_on());
    }

    #[test]
    fn exit_0_says_the_threshold_was_not_reached_and_never_says_clean() {
        let mut run = facts(ExitCode::Ok);
        run.worst = Some(Severity::Low);
        let text = block(&run, Style::PLAIN);
        assert!(
            text.contains("Result: exit 0. no unsuppressed finding reached --fail-on high"),
            "{text}"
        );
        assert!(text.contains("not a clean bill of health"), "{text}");
    }

    #[test]
    fn exit_0_with_fail_on_none_says_findings_do_not_fail_the_run() {
        let mut run = facts(ExitCode::Ok);
        run.fail_on = None;
        let text = block(&run, Style::PLAIN);
        assert!(
            text.contains("--fail-on none: findings do not fail"),
            "{text}"
        );
    }

    #[test]
    fn exit_1_names_the_threshold_and_the_worst_severity() {
        let text = block(&facts(ExitCode::FindingsExceedThreshold), Style::PLAIN);
        assert!(
            text.contains(
                "Result: exit 1. An unsuppressed finding reached --fail-on high. Worst: high."
            ),
            "{text}"
        );
    }

    #[test]
    fn exit_6_says_coverage_is_incomplete_and_does_not_restate_the_counts() {
        let text = block(&facts(ExitCode::ContentNotScanned), Style::PLAIN);
        assert!(
            text.contains("Result: exit 6. Coverage is incomplete"),
            "{text}"
        );
        assert!(!text.contains("could not be content-scanned"), "{text}");
    }

    #[test]
    fn the_numbers_come_from_the_facts() {
        let text = block(&facts(ExitCode::FindingsExceedThreshold), Style::PLAIN);
        assert!(
            text.contains("30 PII columns are undocumented (24 confirmed, 4 likely, 2 possible)."),
            "{text}"
        );
        assert!(
            text.contains("Coverage: 9 of 11 Parquet files scanned (81.8%). Inspection is sampled"),
            "{text}"
        );
    }

    #[test]
    fn a_listing_only_run_says_no_contents_were_read() {
        let mut run = facts(ExitCode::Ok);
        run.pii = None;
        run.coverage = None;
        let text = block(&run, Style::PLAIN);
        assert!(text.contains("No object contents were read"), "{text}");
        assert!(!text.contains("Coverage:"), "{text}");
    }

    #[test]
    fn next_steps_open_the_report_and_point_at_suppressions() {
        let text = block(&facts(ExitCode::Ok), Style::PLAIN);
        assert!(text.contains("open report.html"), "{text}");
        assert!(
            text.contains("Suppressions section of the README"),
            "{text}"
        );
        assert!(text.contains("Wrote:  report.html, inv.csv"), "{text}");
    }

    #[test]
    fn a_path_is_quoted_and_escaped_for_the_shell_and_the_terminal() {
        assert_eq!(
            shell_quoted(&PathBuf::from("out/report.html")),
            "out/report.html"
        );
        assert_eq!(
            shell_quoted(&PathBuf::from("my report.html")),
            "'my report.html'"
        );
        assert_eq!(shell_quoted(&PathBuf::from("it's.html")), "'it'\\''s.html'");
        assert_eq!(
            shell_quoted(&PathBuf::from("a\x1b[2Jb.html")),
            "'a\\u{001b}[2Jb.html'"
        );
    }

    #[test]
    fn colour_wraps_only_lakescan_s_own_words() {
        let text = block(&facts(ExitCode::FindingsExceedThreshold), Style::new(true));
        // Bold, not red: red is for the exit 6 verdict.
        assert!(text.contains("\x1b[1mResult: exit 1.\x1b[0m"), "{text}");
        assert!(text.contains("Worst: high."), "{text}");
        assert!(
            !text.contains("\x1b[31m") && !text.contains("\x1b[1;31m"),
            "{text}"
        );
        let six = block(&facts(ExitCode::ContentNotScanned), Style::new(true));
        assert_eq!(six.matches("\x1b[1;31m").count(), 1, "{six}");
        // The paths the person typed are never wrapped.
        assert!(text.contains("open report.html\n"), "{text}");
    }
}
