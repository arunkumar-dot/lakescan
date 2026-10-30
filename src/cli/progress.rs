//! The live progress line: one line on stderr, redrawn in place.
//!
//! Everything that draws a line goes through [`Line`], which owns "is my
//! line on the screen" and a process-wide lock on the screen. An interrupt
//! takes that lock for good (see [`take_screen`]), so nothing draws over
//! its clean-up.
//!
//! Only numbers that are live and true are shown: objects listed, files
//! whose check has finished (with `--pii`; whatever the outcome, so a file
//! that could not be scanned, or a sniffed object that is not Parquet,
//! counts: the label is "checked", never "scanned"), findings (without it:
//! with `--pii`, content findings are only known once files are applied in
//! listing order, so a count would sit below the real one), and elapsed
//! time. No percentage and no ETA: the total is unknown while the listing
//! streams.

use std::future::Future;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::{Duration, Instant};

use tokio::time::{Interval, MissedTickBehavior};

/// Clears the current terminal line: carriage return, then ANSI "erase
/// entire line".
pub(crate) const CLEAR_LINE: &str = "\r\x1b[2K";

/// How often the line is redrawn between listing pages.
const TICK: Duration = Duration::from_millis(100);

/// The spinner's frames; plain ASCII, so any terminal draws them.
const SPINNER: [char; 4] = ['|', '/', '-', '\\'];

/// What `lakescan scan` shows before the first listing frame, while
/// credentials and bucket access are checked. Constant on purpose: it never
/// names the bucket or anything else derived from one.
pub(crate) const CHECKING: &str = "Checking credentials and bucket access";

/// Whether any line is currently on the screen, for the panic hook to clear
/// before it prints. Each [`Line`] also tracks its own.
static LINE_SHOWN: AtomicBool = AtomicBool::new(false);

/// The screen lock. `true` once an interrupt has taken the screen: after
/// that no line is drawn.
static SCREEN: Mutex<bool> = Mutex::new(false);

fn lock_screen() -> MutexGuard<'static, bool> {
    SCREEN.lock().unwrap_or_else(PoisonError::into_inner)
}

fn write_clear() {
    let mut stderr = std::io::stderr();
    // Best effort: nothing is left to report to.
    let _ = stderr
        .write_all(CLEAR_LINE.as_bytes())
        .and_then(|()| stderr.flush());
}

/// Clears the line if one is on the screen. For the panic hook, which must
/// not print over it; it never waits for the screen lock, since the panic
/// may have happened while this thread held it.
pub(crate) fn clear_if_shown() {
    let free = match SCREEN.try_lock() {
        Ok(guard) => Some(guard),
        Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
        Err(TryLockError::WouldBlock) => None,
    };
    if free.is_none_or(|guard| !*guard) && LINE_SHOWN.swap(false, Ordering::SeqCst) {
        write_clear();
    }
}

/// Takes the screen for an interrupt: clears whatever line is showing and
/// stops every [`Line`] from drawing again. The guard is held until the
/// process exits.
pub(crate) fn take_screen() -> MutexGuard<'static, bool> {
    let mut guard = lock_screen();
    *guard = true;
    if LINE_SHOWN.swap(false, Ordering::SeqCst) {
        write_clear();
    }
    guard
}

/// One line on a terminal: drawn in place, erased when done or dropped, so
/// every exit path leaves the terminal clean.
pub(crate) struct Line<P: Write> {
    out: P,
    shown: bool,
}

impl<P: Write> Line<P> {
    pub(crate) fn new(out: P) -> Self {
        Self { out, shown: false }
    }

    /// Replaces the line with `text`.
    pub(crate) fn draw(&mut self, text: &str) {
        let taken = lock_screen();
        if *taken {
            return;
        }
        self.shown = true;
        LINE_SHOWN.store(true, Ordering::SeqCst);
        // Best effort: a line that cannot be drawn is cosmetic.
        let _ = write!(self.out, "{CLEAR_LINE}{text}").and_then(|()| self.out.flush());
    }

    /// Erases the line, if it is on the screen. Safe to call twice.
    pub(crate) fn clear(&mut self) {
        if !self.shown {
            return;
        }
        self.shown = false;
        let taken = lock_screen();
        if *taken {
            return;
        }
        LINE_SHOWN.store(false, Ordering::SeqCst);
        let _ = self
            .out
            .write_all(CLEAR_LINE.as_bytes())
            .and_then(|()| self.out.flush());
    }
}

impl<P: Write> Drop for Line<P> {
    fn drop(&mut self) {
        self.clear();
    }
}

/// The counters the line shows. Atomics, so the futures that update them
/// and the redraw can each hold a shared reference.
#[derive(Default)]
pub(crate) struct Live {
    /// Objects listed so far.
    pub(crate) objects: AtomicU64,
    /// Unsuppressed findings routed so far.
    pub(crate) findings: AtomicU64,
    /// File checks that have finished, in any order, whatever their outcome.
    pub(crate) files_scanned: Arc<AtomicU64>,
}

/// The progress line's writer, its redraw timer and its spinner.
pub(crate) struct Progress<P: Write> {
    line: Line<P>,
    /// Whether `--pii` is on: files instead of findings are shown.
    pii: bool,
    started: Instant,
    frame: usize,
    timer: Interval,
}

impl<P: Write> Progress<P> {
    /// A line for a scan that starts now.
    pub(crate) fn new(out: P, pii: bool) -> Self {
        let mut timer = tokio::time::interval_at(tokio::time::Instant::now() + TICK, TICK);
        // A slow write must not be followed by a burst of redraws.
        timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Self {
            line: Line::new(out),
            pii,
            started: Instant::now(),
            frame: 0,
            timer,
        }
    }

    /// Redraws the line from `counters`.
    pub(crate) fn draw(&mut self, counters: &Live) {
        let text = render(
            self.frame,
            self.started.elapsed(),
            counters.objects.load(Ordering::Relaxed),
            if self.pii {
                Counted::Files(counters.files_scanned.load(Ordering::Relaxed))
            } else {
                Counted::Findings(counters.findings.load(Ordering::Relaxed))
            },
        );
        self.frame = self.frame.wrapping_add(1);
        self.line.draw(&text);
    }

    /// Erases the line, if it is on the screen. Safe to call twice.
    pub(crate) fn clear(&mut self) {
        self.line.clear();
    }
}

/// Runs `work`, redrawing the line from `live` on every tick that comes
/// before it finishes. `work` is polled first, so a future that is ready
/// is never delayed by a redraw. Without a `progress`, just awaits `work`.
pub(crate) async fn with_progress<T, P: Write>(
    mut progress: Option<&mut Progress<P>>,
    live: &Live,
    work: impl Future<Output = T>,
) -> T {
    tokio::pin!(work);
    loop {
        tokio::select! {
            biased;
            output = &mut work => return output,
            () = async {
                match progress.as_deref_mut() {
                    Some(progress) => {
                        progress.timer.tick().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            } => {
                if let Some(progress) = progress.as_deref_mut() {
                    progress.draw(live);
                }
            }
        }
    }
}

/// The count that differs between scans with and without `--pii`.
#[derive(Clone, Copy)]
enum Counted {
    /// files whose check has finished.
    Files(u64),
    /// Findings routed so far.
    Findings(u64),
}

/// One frame: `| listed 2413 objects, 11 files checked, 7s`.
fn render(frame: usize, elapsed: Duration, objects: u64, counted: Counted) -> String {
    let spinner = SPINNER.get(frame % SPINNER.len()).copied().unwrap_or('|');
    let counted = match counted {
        Counted::Files(files) => format!("{files} files checked"),
        Counted::Findings(findings) => format!("{findings} findings"),
    };
    format!(
        "{spinner} listed {objects} objects, {counted}, {}",
        elapsed_text(elapsed)
    )
}

/// `7s`, `1m 05s`, `2h 03m`.
fn elapsed_text(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    match (secs / 3600, secs / 60 % 60, secs % 60) {
        (0, 0, s) => format!("{s}s"),
        (0, m, s) => format!("{m}m {s:02}s"),
        (h, m, _) => format!("{h}h {m:02}m"),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{CHECKING, CLEAR_LINE, Counted, Line, elapsed_text, render};

    #[test]
    fn elapsed_time_is_whole_units() {
        assert_eq!(elapsed_text(Duration::from_millis(900)), "0s");
        assert_eq!(elapsed_text(Duration::from_secs(7)), "7s");
        assert_eq!(elapsed_text(Duration::from_secs(65)), "1m 05s");
        assert_eq!(elapsed_text(Duration::from_secs(3723)), "1h 02m");
    }

    #[test]
    fn a_pii_scan_shows_files_and_no_findings() {
        let line = render(0, Duration::from_secs(7), 2413, Counted::Files(11));
        assert_eq!(line, "| listed 2413 objects, 11 files checked, 7s");
        assert!(!line.contains("findings"));
    }

    #[test]
    fn a_listing_only_scan_shows_findings_and_no_files() {
        let line = render(1, Duration::from_secs(1), 5, Counted::Findings(3));
        assert_eq!(line, "/ listed 5 objects, 3 findings, 1s");
        assert!(!line.contains("files"));
    }

    #[test]
    fn the_line_has_no_percentage_and_no_estimate() {
        let line = render(2, Duration::from_secs(70), 10, Counted::Findings(0));
        assert!(!line.contains('%') && !line.contains("ETA"), "{line}");
    }

    #[test]
    fn the_checking_frame_names_nothing_from_a_bucket() {
        assert_eq!(CHECKING, "Checking credentials and bucket access");
        let mut out = Vec::new();
        {
            let mut line = Line::new(&mut out);
            line.draw(CHECKING);
        }
        // Drawn, then erased when the line is dropped.
        assert_eq!(
            String::from_utf8_lossy(&out),
            format!("{CLEAR_LINE}{CHECKING}{CLEAR_LINE}")
        );
    }

    /// A stand-in for a preflight that fails: the early return must still
    /// leave the terminal clean.
    fn fails_while_checking(out: &mut Vec<u8>) -> Result<(), &'static str> {
        let mut line = Line::new(out);
        line.draw(CHECKING);
        Err("auth")?;
        line.clear();
        Ok(())
    }

    #[test]
    fn an_error_while_checking_clears_the_line_before_it_is_reported() {
        let mut out = Vec::new();
        assert_eq!(fails_while_checking(&mut out), Err("auth"));
        assert!(
            String::from_utf8_lossy(&out).ends_with(CLEAR_LINE),
            "{out:?}"
        );
    }

    #[test]
    fn clearing_twice_erases_once() {
        let mut out = Vec::new();
        let mut line = Line::new(&mut out);
        line.draw("x");
        line.clear();
        line.clear();
        drop(line);
        assert_eq!(String::from_utf8_lossy(&out).matches(CLEAR_LINE).count(), 2);
    }
}
