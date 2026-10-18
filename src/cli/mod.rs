//! The `lakescan` command line: argument parsing, destinations, and the
//! mapping of every outcome to one [`ExitCode`].
//!
//! ```text
//! lakescan scan <TARGET> [OPTIONS]   scan s3://bucket[/prefix]
//!                                    (--config <PATH> for suppressions,
//!                                    --pii to scan Parquet content,
//!                                    --inventory <PATH> for its CSV)
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
use std::fs::{File, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use clap::error::ErrorKind;
use clap::{Args, Parser, Subcommand, ValueEnum};

use self::driver::{Content, Outputs};
use self::target::Target;
use std::sync::Arc;

use crate::content::{
    BudgetError, DEFAULT_COALESCE_GAP, DEFAULT_CONCURRENCY, DEFAULT_MEMORY_BUDGET,
    DEFAULT_WHOLE_FILE_MAX, MAX_CONCURRENCY, MAX_MEMORY_BUDGET, MAX_WHOLE_FILE_MAX, MemoryBudget,
    ObjectReader, S3ObjectReader, ScanOptions, Sniff, file_need,
};
use crate::error::{ExitCode, LakeScanError};
use crate::model::{RuleId, Severity};
use crate::preflight::{self, AwsProbe};
use crate::report::Format;
use crate::scanner::PageSource;
use crate::scanner::S3Source;
use crate::suppress::Config;

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
    Scan(Box<ScanArgs>),
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

    /// Suppression config file (TOML); see the README for the format.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// No progress output and no suppression warnings.
    #[arg(long)]
    quiet: bool,

    /// Also scan Parquet files for personal data: keys ending in .parquet
    /// or .parq, and (see --pii-sniff) objects without such an extension
    /// that turn out to be Parquet. Reads object contents: needs
    /// s3:GetObject.
    #[arg(long)]
    pii: bool,

    /// With --pii, which objects without a .parquet or .parq extension to
    /// sniff for the Parquet magic, one 8-byte ranged GET each: "unknown"
    /// (no extension, or one not known to be another format) or "none".
    #[arg(
        long,
        value_enum,
        value_name = "WHICH",
        default_value_t = SniffArg::Unknown,
        requires = "pii"
    )]
    pii_sniff: SniffArg,

    /// With --pii, read Parquet files of at most BYTES whole, in one
    /// request; larger ones are read partially. 0 to 67108864 (64 MiB).
    #[arg(
        long,
        value_name = "BYTES",
        default_value_t = DEFAULT_WHOLE_FILE_MAX,
        requires = "pii"
    )]
    pii_whole_file_max: u64,

    /// With --pii, scan up to N Parquet files at once. 1 to 256.
    #[arg(
        long,
        value_name = "N",
        default_value_t = DEFAULT_CONCURRENCY_FLAG,
        value_parser = clap::value_parser!(u16).range(1..=256),
        requires = "pii"
    )]
    concurrency: u16,

    /// With --pii, the most BYTES in-flight file scans may hold at once.
    /// Must cover the most one file can need (see the README); at most
    /// 68719476736 (64 GiB).
    #[arg(
        long,
        value_name = "BYTES",
        default_value_t = DEFAULT_MEMORY_BUDGET,
        requires = "pii"
    )]
    memory_budget: u64,

    /// With --pii, read page ranges of a file at most BYTES apart as one
    /// request (each at most 8 MiB). 0 reads each range alone.
    #[arg(
        long,
        value_name = "BYTES",
        default_value_t = DEFAULT_COALESCE_GAP,
        requires = "pii"
    )]
    coalesce_gap: u64,

    /// With --pii, also write the PII inventory as CSV to PATH, one row
    /// per (table, column, rule) ("-" for stdout, which requires --output
    /// to name a file and --findings not to be "-").
    #[arg(long, value_name = "PATH", requires = "pii")]
    inventory: Option<PathBuf>,

    /// Also write a self-contained HTML report to PATH ("-" for stdout,
    /// which requires every other output to go to a file).
    #[arg(long, value_name = "PATH")]
    html: Option<PathBuf>,
}

/// `--concurrency`'s default, as the flag's type; equal to
/// [`DEFAULT_CONCURRENCY`] (a test checks).
const DEFAULT_CONCURRENCY_FLAG: u16 = 16;

#[derive(ValueEnum, Clone, Copy, Debug)]
enum SniffArg {
    Unknown,
    None,
}

impl From<SniffArg> for Sniff {
    fn from(sniff: SniffArg) -> Self {
        match sniff {
            SniffArg::Unknown => Self::Unknown,
            SniffArg::None => Self::None,
        }
    }
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
    install_panic_hook();
    let stdout = io::stdout();
    // Help is colored only where clap itself would color it: on a
    // terminal, and not with NO_COLOR set.
    let color = stdout.is_terminal() && std::env::var_os("NO_COLOR").is_none();
    match execute(args, stdout, color).await {
        Ok(code) => code,
        Err(err) => {
            // If stderr itself is gone there is nowhere left to report to;
            // the exit code still carries the failure.
            let _ = writeln!(io::stderr(), "lakescan: {err}");
            ExitCode::from(&err)
        }
    }
}

/// Replaces the default panic hook with one that says where a panic
/// happened but never what its message was: a panic inside the `parquet`
/// parser (contained by `content`, see `lib.rs`) could quote bytes of the
/// file being scanned, and no scanned value may reach any output.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let at = info
            .location()
            .map(|location| format!(" at {}:{}", location.file(), location.line()))
            .unwrap_or_default();
        let _ = writeln!(
            io::stderr(),
            "lakescan: internal panic{at}; its message is withheld because it may quote \
             scanned data"
        );
    }));
}

/// Parses `args` and runs the chosen command. `--help`, `--version`, and
/// `lakescan rules` write to `out` (stdout, outside tests), with help in
/// ANSI color when `color`; a scan opens its own destinations.
async fn execute<I, T, W>(args: I, out: W, color: bool) -> Result<ExitCode, LakeScanError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
    W: Write,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => return clap_outcome(&err, out, color),
    };

    match cli.command {
        Command::Scan(args) => scan(*args).await,
        Command::Rules => {
            write_rules(out)?;
            Ok(ExitCode::Ok)
        }
    }
}

/// `--help` and `--version` arrive from clap as errors; they are written to
/// `out` and succeed. Every other clap error is a
/// [`LakeScanError::Usage`] carrying the first paragraph of clap's
/// message, joined onto one line.
fn clap_outcome<W: Write>(
    err: &clap::Error,
    mut out: W,
    color: bool,
) -> Result<ExitCode, LakeScanError> {
    if matches!(
        err.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    ) {
        let rendered = err.render();
        let written = if color {
            write!(out, "{}", rendered.ansi())
        } else {
            write!(out, "{rendered}")
        };
        ignore_broken_pipe(written.and_then(|()| out.flush()))?;
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
    let config = args
        .config
        .as_deref()
        .map(Config::load)
        .transpose()?
        .unwrap_or_default();

    check_stdout(&args)?;
    check_limits(&args)?;

    let concurrency = usize::from(args.concurrency);
    let budget = content_budget(args.memory_budget, concurrency, args.pii_whole_file_max)?;
    if args.pii
        && !args.quiet
        && let Some(warning) = share_warning(&budget, concurrency, args.pii_whole_file_max)
    {
        // Best effort: a warning that cannot be printed changes nothing.
        let _ = writeln!(io::stderr(), "{warning}");
    }

    let source = S3Source::new(
        target.bucket.clone(),
        target.prefix.clone(),
        args.region,
        args.endpoint_url,
    )
    .await?;

    // Before any listing: unusable credentials or a wrong bucket fail here
    // with a message that says what to fix.
    let probe = AwsProbe::new(source.sts_client(), source.client(), &target.bucket);
    let mut stderr_log = io::stderr();
    let debug = std::env::var_os("LAKESCAN_DEBUG")
        .is_some()
        .then_some(&mut stderr_log as &mut dyn Write);
    preflight::check(&probe, &target.bucket, debug).await?;
    if args.pii && !args.quiet {
        // Best effort: a hint that cannot be printed changes nothing.
        let _ = writeln!(io::stderr(), "{}", preflight::pii_hint(&target.bucket));
    }

    // Opened before the scan, so a bad path fails in a second rather than
    // after a long listing. Files are written beside their destination and
    // renamed into place only if the run completes (see `Destination`).
    let mut summary = open_destination(args.output.as_deref())?;
    let mut findings = args
        .findings
        .as_deref()
        .map(|path| open_destination(Some(path)))
        .transpose()?;
    let mut inventory = args
        .inventory
        .as_deref()
        .map(|path| open_destination(Some(path)))
        .transpose()?;
    let mut html = args
        .html
        .as_deref()
        .map(|path| open_destination(Some(path)))
        .transpose()?;

    let stderr = io::stderr();
    let progress = (!args.quiet && stderr.is_terminal()).then_some(io::stderr());
    let warnings = (!args.quiet).then_some(io::stderr());
    let content = args.pii.then(|| Content {
        reader: S3ObjectReader::new(&source.client(), &target.bucket),
        options: ScanOptions {
            whole_file_max: args.pii_whole_file_max,
            coalesce_gap: args.coalesce_gap,
        },
        concurrency,
        budget,
        sniff: args.pii_sniff.into(),
    });

    let code = driver::scan(
        source,
        target,
        config,
        args.format.into(),
        args.fail_on.threshold(),
        content,
        Outputs {
            summary: &mut summary,
            findings: findings.as_mut(),
            inventory: inventory.as_mut(),
            html: html.as_mut(),
            progress,
            warnings,
            errors: stderr,
        },
    )
    .await?;
    // The run completed (whatever its verdict): every file takes its
    // place. On an error above, dropping them removes the temporaries.
    for destination in [Some(summary), findings, inventory, html]
        .into_iter()
        .flatten()
    {
        destination.commit()?;
    }
    Ok(code)
}

/// At most one output may go to stdout. The summary does unless
/// `--output` names a file; `--findings`, `--inventory` and `--html` do
/// when given `-`.
fn check_stdout(args: &ScanArgs) -> Result<(), LakeScanError> {
    let mut on_stdout: Vec<&str> = Vec::new();
    if args.output.as_deref().is_none_or(is_stdout) {
        on_stdout.push("the summary");
    }
    for (flag, path) in [
        ("--findings -", &args.findings),
        ("--inventory -", &args.inventory),
        ("--html -", &args.html),
    ] {
        if path.as_deref().is_some_and(is_stdout) {
            on_stdout.push(flag);
        }
    }
    match on_stdout.as_slice() {
        [] | [_] => Ok(()),
        ["the summary", flag, ..] => Err(LakeScanError::Usage(format!(
            "{flag} writes to stdout, so --output must name a file"
        ))),
        [first, second, ..] => Err(LakeScanError::Usage(format!(
            "{first} and {second} cannot both write to stdout"
        ))),
    }
}

/// Flags whose ranges clap does not check.
fn check_limits(args: &ScanArgs) -> Result<(), LakeScanError> {
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
    if args.memory_budget > MAX_MEMORY_BUDGET {
        return Err(LakeScanError::Usage(format!(
            "--memory-budget {} is too large: at most {MAX_MEMORY_BUDGET} (64 GiB)",
            args.memory_budget
        )));
    }
    if args.pii_whole_file_max > MAX_WHOLE_FILE_MAX {
        return Err(LakeScanError::Usage(format!(
            "--pii-whole-file-max {} is too large: at most {MAX_WHOLE_FILE_MAX} (64 MiB)",
            args.pii_whole_file_max
        )));
    }
    Ok(())
}

/// The run's memory budget, refused (a usage error) if it is below the
/// most one file can need, since that file could then never get its
/// permits.
fn content_budget(
    memory_budget: u64,
    concurrency: usize,
    whole_file_max: u64,
) -> Result<Arc<MemoryBudget>, LakeScanError> {
    MemoryBudget::new(memory_budget, concurrency, file_need(whole_file_max))
        .map(Arc::new)
        .map_err(|err| match err {
            BudgetError::TooSmall { file_need } => LakeScanError::Usage(format!(
                "--memory-budget {memory_budget} is below the most one file can need, \
                 {file_need} bytes at --pii-whole-file-max {whole_file_max}"
            )),
            BudgetError::TooLarge { max } => LakeScanError::Usage(format!(
                "--memory-budget {memory_budget} is too large: at most {max}"
            )),
        })
}

/// The startup warning for a budget whose per-file share is below the
/// whole-file maximum: files read whole would then take turns in the
/// budget's overflow lane, one at a time (see `content::MemoryBudget`).
fn share_warning(budget: &MemoryBudget, concurrency: usize, whole_file_max: u64) -> Option<String> {
    (budget.quota() < whole_file_max).then(|| {
        format!(
            "lakescan: warning: --memory-budget {} leaves each of --concurrency {concurrency} \
             files {} bytes, less than --pii-whole-file-max {whole_file_max}, so larger files \
             will be scanned one at a time; use a larger --memory-budget or a lower \
             --concurrency",
            budget.total(),
            budget.quota()
        )
    })
}

/// Content scanning settings for [`scan_with`].
#[derive(Debug, Clone, Copy)]
pub struct ContentSettings {
    /// `--pii-whole-file-max`.
    pub whole_file_max: u64,
    /// `--concurrency`.
    pub concurrency: usize,
    /// `--memory-budget`.
    pub memory_budget: u64,
    /// `--coalesce-gap`.
    pub coalesce_gap: u64,
    /// `--pii-sniff`.
    pub sniff: Sniff,
}

impl Default for ContentSettings {
    fn default() -> Self {
        Self {
            whole_file_max: DEFAULT_WHOLE_FILE_MAX,
            concurrency: DEFAULT_CONCURRENCY,
            memory_budget: DEFAULT_MEMORY_BUDGET,
            coalesce_gap: DEFAULT_COALESCE_GAP,
            sniff: Sniff::Unknown,
        }
    }
}

/// Runs one scan of `bucket` from any listing source and, with `content`,
/// any object reader, writing the summary (in `format`) to `summary` and,
/// if given, the findings stream to `findings`. No config, no failing
/// threshold. For benchmarks and embedding; the `lakescan` command uses
/// the same driver.
///
/// # Errors
/// [`LakeScanError::Usage`] for a budget below one file's need, and
/// whatever the scan itself returns.
pub async fn scan_with<S, R, O, F>(
    source: S,
    bucket: &str,
    content: Option<(R, ContentSettings)>,
    format: Format,
    summary: O,
    findings: Option<F>,
) -> Result<ExitCode, LakeScanError>
where
    S: PageSource,
    R: ObjectReader,
    O: Write,
    F: Write,
{
    let content = match content {
        Some((reader, settings)) => Some(Content {
            reader,
            options: ScanOptions {
                whole_file_max: settings.whole_file_max,
                coalesce_gap: settings.coalesce_gap,
            },
            concurrency: settings.concurrency.clamp(1, MAX_CONCURRENCY),
            budget: content_budget(
                settings.memory_budget,
                settings.concurrency.clamp(1, MAX_CONCURRENCY),
                settings.whole_file_max,
            )?,
            sniff: settings.sniff,
        }),
        None => None,
    };
    driver::scan(
        source,
        Target {
            bucket: bucket.to_owned(),
            prefix: None,
        },
        Config::default(),
        format,
        None,
        content,
        Outputs {
            summary,
            findings,
            inventory: None,
            html: None,
            progress: None::<io::Sink>,
            warnings: None::<io::Sink>,
            errors: io::sink(),
        },
    )
    .await
}

/// `-` names stdout, for `--findings` and (for symmetry) `--output`.
fn is_stdout(path: &Path) -> bool {
    path == Path::new("-")
}

/// Stdout for `None` or `-`, else an [`AtomicFile`] for `path`.
fn open_destination(path: Option<&Path>) -> Result<Destination, LakeScanError> {
    match path {
        None => Ok(Destination::Stdout(io::stdout())),
        Some(path) if is_stdout(path) => Ok(Destination::Stdout(io::stdout())),
        Some(path) => AtomicFile::create(path)
            .map(Destination::File)
            .map_err(|err| {
                LakeScanError::Report(io::Error::new(
                    err.kind(),
                    format!("cannot open {}: {err}", path.display()),
                ))
            }),
    }
}

/// Where one output goes. Stdout is written as the run goes; a file is
/// only complete, at its path, after [`Destination::commit`].
enum Destination {
    Stdout(io::Stdout),
    File(AtomicFile),
}

impl Destination {
    /// Puts a file in place; nothing to do for stdout.
    fn commit(self) -> Result<(), LakeScanError> {
        match self {
            Self::Stdout(_) => Ok(()),
            Self::File(file) => file.commit(),
        }
    }
}

impl Write for Destination {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Stdout(out) => out.write(buf),
            Self::File(file) => file.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Stdout(out) => out.flush(),
            Self::File(file) => file.flush(),
        }
    }
}

/// An output file written to a temporary file beside its destination
/// (same directory, so the rename cannot cross filesystems) and renamed
/// over it by [`AtomicFile::commit`]. Dropped uncommitted, it removes the
/// temporary file, so a failed run never leaves a partial report at the
/// destination, nor replaces an earlier complete one.
struct AtomicFile {
    file: Option<File>,
    temp: PathBuf,
    path: PathBuf,
}

impl AtomicFile {
    fn create(path: &Path) -> io::Result<Self> {
        if path.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a file name"))?
            .to_string_lossy();
        let dir = path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut last = io::Error::new(io::ErrorKind::AlreadyExists, "no free temporary name");
        for attempt in 0..64 {
            let temp = dir.join(format!(
                ".{name}.{}.{attempt}.lakescan-tmp",
                std::process::id()
            ));
            match OpenOptions::new().write(true).create_new(true).open(&temp) {
                Ok(file) => {
                    return Ok(Self {
                        file: Some(file),
                        temp,
                        path: path.to_owned(),
                    });
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => last = err,
                Err(err) => return Err(err),
            }
        }
        Err(last)
    }

    /// Flushes the file to disk and renames it over the destination.
    fn commit(mut self) -> Result<(), LakeScanError> {
        let report = |err: io::Error, path: &Path| {
            LakeScanError::Report(io::Error::new(
                err.kind(),
                format!("cannot write {}: {err}", path.display()),
            ))
        };
        if let Some(file) = self.file.take() {
            file.sync_all().map_err(|err| report(err, &self.path))?;
        }
        std::fs::rename(&self.temp, &self.path).map_err(|err| report(err, &self.path))?;
        // In place: nothing for `Drop` to remove.
        self.temp = PathBuf::new();
        Ok(())
    }
}

impl Write for AtomicFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.file {
            Some(file) => file.write(buf),
            None => Err(io::Error::other("already committed")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.file {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

impl Drop for AtomicFile {
    fn drop(&mut self) {
        drop(self.file.take());
        if !self.temp.as_os_str().is_empty() {
            // Best effort: nothing left to report to.
            let _ = std::fs::remove_file(&self.temp);
        }
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
        match execute(args.iter().copied(), Vec::new(), false).await {
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
    async fn help_and_version_succeed_and_write_to_the_given_output()
    -> Result<(), Box<dyn std::error::Error>> {
        for (args, expected) in [
            (["lakescan", "--help"].as_slice(), "Usage: lakescan"),
            (&["lakescan", "--version"], "lakescan 0.1.0"),
            (&["lakescan", "scan", "--help"], "--config <PATH>"),
        ] {
            let mut out = Vec::new();
            assert_eq!(
                execute(args.iter().copied(), &mut out, false).await?,
                ExitCode::Ok,
                "{args:?}"
            );
            let out = String::from_utf8(out)?;
            assert!(out.contains(expected), "{args:?} printed {out:?}");
            assert!(!out.contains('\x1b'), "uncolored output has no ANSI codes");
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_bad_config_is_a_usage_error_before_any_network_call() {
        for config in ["/nonexistent/lakescan.toml", "Cargo.toml"] {
            let message = usage_error(&["lakescan", "scan", "s3://b", "--config", config]).await;
            assert!(
                message.as_ref().is_some_and(|m| m.contains("config")),
                "{config}: {message:?}"
            );
        }
    }

    #[test]
    fn a_small_per_file_share_warns_once_and_the_defaults_do_not() {
        use crate::content::{
            DEFAULT_CONCURRENCY, DEFAULT_MEMORY_BUDGET, DEFAULT_WHOLE_FILE_MAX, MemoryBudget,
            file_need,
        };
        let need = file_need(DEFAULT_WHOLE_FILE_MAX);
        let quiet = MemoryBudget::new(DEFAULT_MEMORY_BUDGET, DEFAULT_CONCURRENCY, need);
        assert!(quiet.as_ref().is_ok_and(|b| {
            super::share_warning(b, DEFAULT_CONCURRENCY, DEFAULT_WHOLE_FILE_MAX).is_none()
        }));
        let crowded = MemoryBudget::new(DEFAULT_MEMORY_BUDGET, 64, need);
        let warning = crowded
            .as_ref()
            .ok()
            .and_then(|b| super::share_warning(b, 64, DEFAULT_WHOLE_FILE_MAX));
        assert!(
            warning
                .as_ref()
                .is_some_and(|w| w.starts_with("lakescan: warning:")
                    && w.contains("--concurrency 64")
                    && w.contains("larger --memory-budget")
                    && !w.contains('\n')),
            "{warning:?}"
        );
    }

    /// A fresh, empty directory for one test.
    fn scratch_dir(test: &str) -> Result<std::path::PathBuf, std::io::Error> {
        let dir = std::env::temp_dir().join(format!("lakescan-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// The names in `dir`, sorted.
    fn names_in(dir: &std::path::Path) -> Result<Vec<String>, std::io::Error> {
        let mut names = std::fs::read_dir(dir)?
            .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        Ok(names)
    }

    #[test]
    fn an_output_file_appears_only_when_committed() -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;
        let dir = scratch_dir("atomic-commit")?;
        let path = dir.join("summary.txt");
        let mut file = super::AtomicFile::create(&path)?;
        file.write_all(b"complete report\n")?;
        // Written, but not yet in place.
        assert!(!path.exists());
        file.commit()?;
        assert_eq!(std::fs::read_to_string(&path)?, "complete report\n");
        assert_eq!(names_in(&dir)?, ["summary.txt"], "no temporary left");
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn a_failed_run_leaves_the_previous_output_and_no_temporary()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;
        let dir = scratch_dir("atomic-drop")?;
        let path = dir.join("report.html");
        std::fs::write(&path, "yesterday's complete report")?;
        let mut file = super::AtomicFile::create(&path)?;
        file.write_all(b"<html>half a rep")?;
        // The run failed: dropped without a commit.
        drop(file);
        assert_eq!(
            std::fs::read_to_string(&path)?,
            "yesterday's complete report"
        );
        assert_eq!(names_in(&dir)?, ["report.html"], "the temporary is removed");
        // A directory is refused when opened, before any scan.
        assert!(super::AtomicFile::create(&dir).is_err());
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[tokio::test]
    async fn a_memory_budget_over_64_gib_and_a_bad_sniff_mode_are_usage_errors() {
        let over = (crate::content::MAX_MEMORY_BUDGET + 1).to_string();
        let message = usage_error(&[
            "lakescan",
            "scan",
            "s3://b",
            "--pii",
            "--memory-budget",
            &over,
        ])
        .await;
        assert!(
            message
                .as_ref()
                .is_some_and(|m| m.contains("too large") && m.contains("68719476736")),
            "{message:?}"
        );
        for args in [
            ["lakescan", "scan", "s3://b", "--pii-sniff", "none"].as_slice(),
            &["lakescan", "scan", "s3://b", "--pii", "--pii-sniff", "all"],
        ] {
            assert!(usage_error(args).await.is_some(), "{args:?}");
        }
    }

    #[tokio::test]
    async fn a_memory_budget_below_one_file_s_need_is_a_usage_error() {
        let need = crate::content::file_need(crate::content::DEFAULT_WHOLE_FILE_MAX);
        let budget = (need - 1).to_string();
        let message = usage_error(&[
            "lakescan",
            "scan",
            "s3://b",
            "--pii",
            "--memory-budget",
            &budget,
        ])
        .await;
        assert!(
            message
                .as_ref()
                .is_some_and(|m| m.contains("below the most one file can need")
                    && m.contains(&need.to_string())),
            "{message:?}"
        );
        // A bigger whole-file maximum needs more.
        let big = usage_error(&[
            "lakescan",
            "scan",
            "s3://b",
            "--pii",
            "--pii-whole-file-max",
            "67108864",
            "--memory-budget",
            &need.to_string(),
        ])
        .await;
        assert!(big.is_some(), "{big:?}");
        assert_eq!(
            usize::from(super::DEFAULT_CONCURRENCY_FLAG),
            crate::content::DEFAULT_CONCURRENCY
        );
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
    async fn only_one_output_may_write_to_stdout() {
        for args in [
            // --html - needs stdout to itself.
            ["lakescan", "scan", "s3://b", "--html", "-"].as_slice(),
            &[
                "lakescan",
                "scan",
                "s3://b",
                "--html",
                "-",
                "--findings",
                "-",
                "--output",
                "summary.txt",
            ],
            &[
                "lakescan",
                "scan",
                "s3://b",
                "--pii",
                "--html",
                "-",
                "--inventory",
                "-",
                "--output",
                "summary.txt",
            ],
        ] {
            assert!(usage_error(args).await.is_some(), "{args:?}");
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
            &[
                "lakescan",
                "scan",
                "s3://b",
                "--pii",
                "--pii-whole-file-max",
                "67108865",
            ],
            &[
                "lakescan",
                "scan",
                "s3://b",
                "--pii",
                "--pii-whole-file-max",
                "-1",
            ],
            &["lakescan", "scan", "s3://b", "--pii-whole-file-max", "1024"],
            // --concurrency is 1 to 256; the M9 flags need --pii.
            &["lakescan", "scan", "s3://b", "--pii", "--concurrency", "0"],
            &[
                "lakescan",
                "scan",
                "s3://b",
                "--pii",
                "--concurrency",
                "257",
            ],
            &["lakescan", "scan", "s3://b", "--concurrency", "4"],
            &[
                "lakescan",
                "scan",
                "s3://b",
                "--memory-budget",
                "1000000000",
            ],
            &["lakescan", "scan", "s3://b", "--coalesce-gap", "0"],
            // --inventory needs --pii, and stdout to itself.
            &["lakescan", "scan", "s3://b", "--inventory", "inv.csv"],
            &["lakescan", "scan", "s3://b", "--pii", "--inventory", "-"],
            &[
                "lakescan",
                "scan",
                "s3://b",
                "--pii",
                "--inventory",
                "-",
                "--output",
                "-",
            ],
            &[
                "lakescan",
                "scan",
                "s3://b",
                "--pii",
                "--inventory",
                "-",
                "--findings",
                "-",
                "--output",
                "summary.txt",
            ],
        ] {
            assert!(usage_error(args).await.is_some(), "{args:?}");
        }
    }
}
