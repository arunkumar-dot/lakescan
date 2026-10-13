//! The `lakescan` command line: argument parsing, destinations, and the
//! mapping of every outcome to one [`ExitCode`].
//!
//! ```text
//! lakescan scan <TARGET> [OPTIONS]   scan s3://bucket[/prefix]
//! lakescan rules                     list every rule's code and title
//! ```
//!
//! [`run`] is the whole program; `main.rs` only collects the arguments and
//! hands back what this returns. Every exit goes through [`ExitCode`]:
//! clap's parse errors become [`LakeScanError::Usage`], `--help` and
//! `--version` succeed, and nothing calls `std::process::exit`. A failed run
//! prints exactly one line to stderr, `lakescan: <error>`, using only the
//! error's `Display`: every [`LakeScanError`] variant already includes its
//! cause, so walking the source chain as well would print it twice.

mod driver;
mod target;

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use clap::error::ErrorKind;
use clap::{Args, Parser, Subcommand, ValueEnum};

use self::driver::Outputs;
use self::target::Target;
use crate::error::{ExitCode, LakeScanError};
use crate::model::{RuleId, Severity};
use crate::report::Format;
use crate::scanner::S3Source;

/// High-throughput S3 audit tool.
#[derive(Parser, Debug)]
#[command(name = "lakescan", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan a bucket (or one prefix of it) and report what the rules find.
    Scan(ScanArgs),
    /// List every rule's code and title.
    Rules,
}

#[derive(Args, Debug)]
struct ScanArgs {
    // An explicit `help` rather than a doc comment, which rustdoc lints
    // would want to turn into a link.
    #[arg(help = "What to scan: s3://bucket or s3://bucket/prefix")]
    target: String,

    /// Summary format.
    #[arg(long, value_enum, default_value_t = FormatArg::Text)]
    format: FormatArg,

    /// Write the summary to PATH instead of stdout.
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,

    /// Also stream every finding as JSON Lines to PATH ("-" for stdout,
    /// which requires --output to name a file).
    #[arg(long, value_name = "PATH")]
    findings: Option<PathBuf>,

    /// Exit 1 when the worst finding is at or above LEVEL; "none" never
    /// fails on findings.
    #[arg(long, value_enum, value_name = "LEVEL", default_value_t = FailOn::High)]
    fail_on: FailOn,

    /// AWS region, overriding the configured one.
    #[arg(long)]
    region: Option<String>,

    /// S3-compatible endpoint URL; implies path-style addressing.
    #[arg(long, value_name = "URL")]
    endpoint_url: Option<String>,

    /// No progress output.
    #[arg(long)]
    quiet: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum FormatArg {
    Text,
    Json,
}

impl From<FormatArg> for Format {
    fn from(format: FormatArg) -> Self {
        match format {
            FormatArg::Text => Self::Text,
            FormatArg::Json => Self::Json,
        }
    }
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum FailOn {
    Info,
    Low,
    Medium,
    High,
    Critical,
    #[value(name = "none")]
    Never,
}

impl FailOn {
    /// The lowest severity that fails the run, or `None` for never.
    fn threshold(self) -> Option<Severity> {
        match self {
            Self::Info => Some(Severity::Info),
            Self::Low => Some(Severity::Low),
            Self::Medium => Some(Severity::Medium),
            Self::High => Some(Severity::High),
            Self::Critical => Some(Severity::Critical),
            Self::Never => None,
        }
    }
}

/// Runs `lakescan` with `args` (including the program name, as
/// [`std::env::args_os`] yields them) and returns the process exit code.
///
/// On failure, prints `lakescan: <error>` to stderr first.
pub async fn run<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match execute(args).await {
        Ok(code) => code,
        Err(err) => {
            // If stderr itself is gone there is nowhere left to report to;
            // the exit code still carries the failure.
            let _ = writeln!(io::stderr(), "lakescan: {err}");
            ExitCode::from(&err)
        }
    }
}

async fn execute<I, T>(args: I) -> Result<ExitCode, LakeScanError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => return clap_outcome(&err),
    };

    match cli.command {
        Command::Scan(args) => scan(args).await,
        Command::Rules => {
            write_rules(io::stdout())?;
            Ok(ExitCode::Ok)
        }
    }
}

/// `--help` and `--version` arrive from clap as errors; they print and
/// succeed. Every other clap error is a [`LakeScanError::Usage`] carrying
/// the first paragraph of clap's message, joined onto one line.
fn clap_outcome(err: &clap::Error) -> Result<ExitCode, LakeScanError> {
    if matches!(
        err.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    ) {
        ignore_broken_pipe(err.print())?;
        return Ok(ExitCode::Ok);
    }

    let rendered = err.render().to_string();
    let message = rendered
        .lines()
        .map(str::trim)
        .take_while(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let message = message.strip_prefix("error: ").unwrap_or(&message);
    Err(LakeScanError::Usage(format!(
        "{message}; try 'lakescan --help'"
    )))
}

async fn scan(args: ScanArgs) -> Result<ExitCode, LakeScanError> {
    let target: Target = args.target.parse()?;

    let summary_to_stdout = args.output.as_deref().is_none_or(is_stdout);
    let findings_to_stdout = args.findings.as_deref().is_some_and(is_stdout);
    if summary_to_stdout && findings_to_stdout {
        return Err(LakeScanError::Usage(
            "--findings - streams findings to stdout, so --output must name a file".to_owned(),
        ));
    }
    if args.region.as_deref().is_some_and(str::is_empty) {
        return Err(LakeScanError::Usage(
            "--region must not be empty".to_owned(),
        ));
    }
    if let Some(url) = &args.endpoint_url
        && !(url.starts_with("http://") || url.starts_with("https://"))
    {
        return Err(LakeScanError::Usage(format!(
            "invalid --endpoint-url {url:?}: expected an http:// or https:// URL"
        )));
    }

    let source = S3Source::new(
        target.bucket.clone(),
        target.prefix.clone(),
        args.region,
        args.endpoint_url,
    )
    .await?;

    // Opened before the scan, so a bad path fails in a second rather than
    // after a long listing.
    let summary = open_destination(args.output.as_deref())?;
    let findings = args
        .findings
        .as_deref()
        .map(|path| open_destination(Some(path)))
        .transpose()?;

    let stderr = io::stderr();
    let progress = (!args.quiet && stderr.is_terminal()).then_some(stderr);

    driver::scan(
        source,
        target,
        args.format.into(),
        args.fail_on.threshold(),
        Outputs {
            summary,
            findings,
            progress,
        },
    )
    .await
}

/// `-` names stdout, for `--findings` and (for symmetry) `--output`.
fn is_stdout(path: &Path) -> bool {
    path == Path::new("-")
}

/// Opens `path` for writing, truncating it, or stdout for `None` or `-`.
fn open_destination(path: Option<&Path>) -> Result<Box<dyn Write>, LakeScanError> {
    match path {
        None => Ok(Box::new(io::stdout())),
        Some(path) if is_stdout(path) => Ok(Box::new(io::stdout())),
        Some(path) => match File::create(path) {
            Ok(file) => Ok(Box::new(file)),
            Err(err) => Err(LakeScanError::Report(io::Error::new(
                err.kind(),
                format!("cannot open {}: {err}", path.display()),
            ))),
        },
    }
}

/// Writes each rule's code and title, one per line, in [`RuleId::ALL`]
/// order, with the titles aligned.
fn write_rules<W: Write>(out: W) -> Result<(), LakeScanError> {
    let mut out = io::BufWriter::new(out);
    let width = RuleId::ALL
        .iter()
        .map(|rule| rule.code().len())
        .max()
        .unwrap_or(0);
    let written = RuleId::ALL
        .iter()
        .try_for_each(|rule| writeln!(out, "{:<width$}  {}", rule.code(), rule.title()))
        .and_then(|()| out.flush());
    ignore_broken_pipe(written)
}

/// A closed reader (`lakescan rules | head -1`) is not a failure; any
/// other write error is a [`LakeScanError::Report`].
fn ignore_broken_pipe(result: io::Result<()>) -> Result<(), LakeScanError> {
    match result {
        Err(err) if err.kind() != io::ErrorKind::BrokenPipe => Err(LakeScanError::Report(err)),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::{execute, write_rules};
    use crate::error::{ExitCode, LakeScanError};
    use crate::model::RuleId;

    async fn usage_error(args: &[&str]) -> Option<String> {
        match execute(args.iter().copied()).await {
            Err(LakeScanError::Usage(message)) => Some(message),
            _ => None,
        }
    }

    #[test]
    fn rules_lists_every_rule_in_order() -> Result<(), Box<dyn std::error::Error>> {
        let mut out = Vec::new();
        write_rules(&mut out)?;
        let out = String::from_utf8(out)?;

        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), RuleId::ALL.len());
        for (line, rule) in lines.iter().zip(RuleId::ALL) {
            assert!(line.starts_with(rule.code()), "{line:?}");
            assert!(line.ends_with(rule.title()), "{line:?}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn help_and_version_succeed() -> Result<(), LakeScanError> {
        for args in [
            ["lakescan", "--help"].as_slice(),
            &["lakescan", "--version"],
            &["lakescan", "scan", "--help"],
        ] {
            assert_eq!(
                execute(args.iter().copied()).await?,
                ExitCode::Ok,
                "{args:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn parse_errors_are_one_line_usage_errors() {
        for args in [
            ["lakescan"].as_slice(),
            &["lakescan", "frobnicate"],
            &["lakescan", "scan"],
            &["lakescan", "scan", "s3://b", "--format", "xml"],
            &["lakescan", "scan", "s3://b", "--fail-on", "severe"],
            &["lakescan", "scan", "s3://b", "--no-such-flag"],
        ] {
            let message = usage_error(args).await;
            assert!(
                message.as_ref().is_some_and(|m| !m.contains('\n')),
                "{args:?} gave {message:?}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_targets_and_option_combinations_are_usage_errors() {
        for args in [
            ["lakescan", "scan", "my-bucket"].as_slice(),
            &["lakescan", "scan", "s3://"],
            &["lakescan", "scan", "s3://b", "--findings", "-"],
            &[
                "lakescan",
                "scan",
                "s3://b",
                "--findings",
                "-",
                "--output",
                "-",
            ],
            &[
                "lakescan",
                "scan",
                "s3://b",
                "--endpoint-url",
                "localhost:5000",
            ],
            &["lakescan", "scan", "s3://b", "--region", ""],
        ] {
            assert!(usage_error(args).await.is_some(), "{args:?}");
        }
    }
}
