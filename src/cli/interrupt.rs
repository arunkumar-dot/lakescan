//! Ctrl-C and `kill`: clean up and leave with the conventional status.
//!
//! A run that is interrupted prints nothing, erases its progress line,
//! removes every temporary output file it created, and exits 130 (SIGINT)
//! or 143 (SIGTERM). Output files that were already renamed into place
//! stay, and so does any earlier file at an output path: those are only
//! ever replaced by a rename.
//!
//! The handler runs as a task on the runtime's other threads, so it works
//! while the main task is inside a blocking write or the final renames. It
//! cannot rely on destructors, because it ends the process, so every
//! temporary file is recorded in a registry of live paths:
//!
//! - [`register`] when a temporary file is created;
//! - [`rename_into_place`] holds the registry's lock across the rename and
//!   the removal of its entry, so the handler sees either "not yet renamed"
//!   (and removes the temporary file) or "renamed and unregistered" (and has
//!   nothing to remove), never a half state;
//! - [`discard`] when a temporary file is dropped unfinished.
//!
//! This is the one place that calls `std::process::exit`: a signal can land
//! while the main task is mid-write, and the handler must be able to end the
//! process from another thread.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::progress;

/// The temporary files of the current run that have not been renamed into
/// place or discarded.
#[derive(Debug, Default)]
pub(super) struct Registry {
    paths: Vec<PathBuf>,
}

impl Registry {
    fn add(&mut self, path: &Path) {
        self.paths.push(path.to_owned());
    }

    fn remove(&mut self, path: &Path) {
        self.paths.retain(|known| known != path);
    }

    /// Removes every registered file and forgets it. A file that is
    /// already gone is not an error.
    fn remove_all(&mut self) {
        for path in self.paths.drain(..) {
            let _ = fs::remove_file(path);
        }
    }
}

static TEMPS: Mutex<Registry> = Mutex::new(Registry { paths: Vec::new() });

fn lock(registry: &Mutex<Registry>) -> MutexGuard<'_, Registry> {
    registry.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Records a temporary file just created.
pub(super) fn register(path: &Path) {
    lock(&TEMPS).add(path);
}

/// Removes a temporary file that will not be renamed, and forgets it.
pub(super) fn discard(path: &Path) {
    discard_in(&TEMPS, path);
}

/// Renames `temp` over `dest` and forgets `temp`, as one step as far as the
/// handler can tell.
pub(super) fn rename_into_place(temp: &Path, dest: &Path) -> io::Result<()> {
    rename_in(&TEMPS, temp, dest)
}

fn discard_in(registry: &Mutex<Registry>, path: &Path) {
    let mut registry = lock(registry);
    let _ = fs::remove_file(path);
    registry.remove(path);
}

fn rename_in(registry: &Mutex<Registry>, temp: &Path, dest: &Path) -> io::Result<()> {
    let mut registry = lock(registry);
    let renamed = fs::rename(temp, dest);
    if renamed.is_ok() {
        registry.remove(temp);
    }
    renamed
}

#[cfg(test)]
fn remove_all_in(registry: &Mutex<Registry>) {
    lock(registry).remove_all();
}

/// Starts listening for SIGINT and SIGTERM. Call inside the runtime, before
/// the first temporary file is created.
pub(super) fn install() {
    tokio::spawn(async {
        let code = wait().await;
        exit_cleanly(code)
    });
}

/// Which signal arrived, as the exit status to leave with.
#[cfg(unix)]
async fn wait() -> i32 {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut interrupt), Ok(mut terminate)) = (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    ) else {
        // No handler could be installed: the default action stays.
        return std::future::pending().await;
    };
    tokio::select! {
        _ = interrupt.recv() => 130,
        _ = terminate.recv() => 143,
    }
}

#[cfg(not(unix))]
async fn wait() -> i32 {
    match tokio::signal::ctrl_c().await {
        Ok(()) => 130,
        Err(_) => std::future::pending().await,
    }
}

/// Removes the temporary files, erases the progress line, and ends the
/// process with `code`. Holds both locks until then, so a commit in
/// progress finishes first and nothing is drawn afterwards.
fn exit_cleanly(code: i32) -> ! {
    let mut temps = lock(&TEMPS);
    temps.remove_all();
    let _screen = progress::take_screen();
    std::process::exit(code)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use super::{Registry, discard_in, remove_all_in, rename_in};

    /// A fresh empty directory under the system temp dir.
    fn scratch(name: &str) -> Result<PathBuf, std::io::Error> {
        let dir =
            std::env::temp_dir().join(format!("lakescan-interrupt-{name}-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn temp_file(dir: &Path, name: &str, registry: &Mutex<Registry>) -> std::io::Result<PathBuf> {
        let path = dir.join(name);
        fs::write(&path, b"partial")?;
        registry
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .add(&path);
        Ok(path)
    }

    #[test]
    fn removing_all_deletes_every_registered_file_and_nothing_else() -> std::io::Result<()> {
        let dir = scratch("all")?;
        let registry = Mutex::new(Registry::default());
        let (a, b) = (
            temp_file(&dir, ".a.tmp", &registry)?,
            temp_file(&dir, ".b.tmp", &registry)?,
        );
        let unrelated = dir.join("keep.txt");
        fs::write(&unrelated, b"previous output")?;

        remove_all_in(&registry);

        assert!(!a.exists() && !b.exists());
        assert_eq!(fs::read(&unrelated)?, b"previous output");
        // The registry is empty: a second clean-up is a no-op.
        remove_all_in(&registry);
        fs::remove_dir_all(dir)
    }

    #[test]
    fn a_file_already_renamed_into_place_stays() -> std::io::Result<()> {
        let dir = scratch("renamed")?;
        let registry = Mutex::new(Registry::default());
        let done = temp_file(&dir, ".done.tmp", &registry)?;
        let pending = temp_file(&dir, ".pending.tmp", &registry)?;
        let dest = dir.join("done.txt");

        rename_in(&registry, &done, &dest)?;
        remove_all_in(&registry);

        assert_eq!(fs::read(&dest)?, b"partial", "renamed file stays");
        assert!(!pending.exists(), "unfinished one is removed");
        fs::remove_dir_all(dir)
    }

    #[test]
    fn a_previous_output_is_untouched_until_the_rename() -> std::io::Result<()> {
        let dir = scratch("previous")?;
        let registry = Mutex::new(Registry::default());
        let dest = dir.join("report.html");
        fs::write(&dest, b"old complete report")?;
        let temp = temp_file(&dir, ".report.html.tmp", &registry)?;

        // Interrupted before the rename.
        remove_all_in(&registry);

        assert_eq!(fs::read(&dest)?, b"old complete report");
        assert!(!temp.exists());
        fs::remove_dir_all(dir)
    }

    #[test]
    fn a_failed_rename_stays_registered_for_clean_up() -> std::io::Result<()> {
        let dir = scratch("failed")?;
        let registry = Mutex::new(Registry::default());
        let temp = temp_file(&dir, ".x.tmp", &registry)?;
        // The destination's directory does not exist.
        let dest = dir.join("missing").join("x.txt");

        assert!(rename_in(&registry, &temp, &dest).is_err());
        assert!(temp.exists());
        remove_all_in(&registry);
        assert!(!temp.exists());
        fs::remove_dir_all(dir)
    }

    #[test]
    fn discarding_removes_the_file_and_its_entry() -> std::io::Result<()> {
        let dir = scratch("discard")?;
        let registry = Mutex::new(Registry::default());
        let temp = temp_file(&dir, ".d.tmp", &registry)?;

        discard_in(&registry, &temp);

        assert!(!temp.exists());
        // Nothing left for a later clean-up (which would otherwise try to
        // remove a path that a new run could have reused).
        fs::write(&temp, b"a different file at the same path")?;
        remove_all_in(&registry);
        assert!(temp.exists());
        fs::remove_dir_all(dir)
    }
}
