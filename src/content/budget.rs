//! [`MemoryBudget`]: the byte-counting semaphore that bounds what in-flight
//! content scans hold (`--memory-budget`).
//!
//! Every fetch acquires permits for the bytes it will return, and every
//! decode for the pages' declared sizes, before it starts; a [`Permit`]
//! releases them when the buffers it guards are dropped. No fetch or
//! decode happens without permits. The semaphore is created with exactly
//! the budget's byte count as permits, never silently clamped: a budget it
//! cannot represent, or over [`MAX_MEMORY_BUDGET`], is refused.
//!
//! **No deadlock.** Files acquire permits a little at a time while holding
//! others (a footer while its pages are read), and two files that each
//! hold part of a budget while waiting for the rest could wait forever.
//! So permits come in two tiers. Each in-flight file may hold up to its
//! *share* (`quota`) freely. A file that needs more first takes the one
//! *overflow lane*, and may then hold up to the largest single-file need
//! ([`file_need`](super::file_need)). With at most `concurrency` files in
//! flight,
//!
//! ```text
//! (concurrency - 1) × quota + file_need  <=  budget
//! ```
//!
//! so every acquisition can be granted at once, and a file waits only for
//! the lane, whose holder never waits on anyone. The quota is the largest
//! value that keeps that true; a budget below one file's need is a usage
//! error, caught at startup.
//!
//! **The lane is released early.** A file gives the lane back as soon as
//! what it holds drops to its quota or below, not when it finishes. The
//! inequality above only needs "a file over its quota holds the lane",
//! and that stays true: a file's count includes the permits it is still
//! waiting for (they are reserved before the wait), and the check that
//! releases the lane and the reservation that would need it take the same
//! lock, so the lane is never released while the file is, or is about to
//! be, over its quota. A file that later grows past its quota again waits
//! for the lane like any other, holding no more than its quota meanwhile.
//!
//! **No wait lasts forever.** One acquisition (the lane and the permits)
//! waits at most [`BUDGET_WAIT`]; past it, the acquisition is
//! [`Refused::TimedOut`] and the file becomes `content-not-scanned` with
//! reason `budget-timeout`, so a stalled file elsewhere cannot hold up the
//! whole run.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use tokio::sync::{Mutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore};

/// The longest one acquisition waits for the overflow lane and its
/// permits together.
pub const BUDGET_WAIT: Duration = Duration::from_mins(10);

/// The largest `--memory-budget` accepted: 64 GiB.
pub const MAX_MEMORY_BUDGET: u64 = 64 * 1024 * 1024 * 1024;

/// The shared budget for one run.
#[derive(Debug)]
pub struct MemoryBudget {
    semaphore: Arc<Semaphore>,
    lane: Arc<Mutex<()>>,
    total: u64,
    quota: u64,
    file_need: u64,
    held: AtomicU64,
    peak: AtomicU64,
}

/// Why a budget cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BudgetError {
    /// Below the most one file can need: that file could wait forever.
    #[error("below the most one file can need, {file_need} bytes")]
    TooSmall {
        /// The most one file can need.
        file_need: u64,
    },
    /// Over [`MAX_MEMORY_BUDGET`], or more permits than the semaphore can
    /// represent on this platform.
    #[error("too large: at most {max} bytes")]
    TooLarge {
        /// The largest budget accepted here.
        max: u64,
    },
}

/// Why an acquisition was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// It would put the file over the largest single-file need, which the
    /// caps rule out: a file that somehow asked for more is refused rather
    /// than left waiting.
    OverNeed,
    /// It waited longer than [`BUDGET_WAIT`].
    TimedOut,
}

impl MemoryBudget {
    /// A budget of `total` bytes for `concurrency` files in flight, each
    /// needing at most `file_need`.
    ///
    /// # Errors
    /// [`BudgetError::TooSmall`] if `total` is below `file_need`, and
    /// [`BudgetError::TooLarge`] if it is over [`MAX_MEMORY_BUDGET`] or
    /// does not fit the semaphore exactly.
    pub fn new(total: u64, concurrency: usize, file_need: u64) -> Result<Self, BudgetError> {
        if total < file_need {
            return Err(BudgetError::TooSmall { file_need });
        }
        let max = MAX_MEMORY_BUDGET.min(u64::try_from(Semaphore::MAX_PERMITS).unwrap_or(u64::MAX));
        let permits = usize::try_from(total)
            .ok()
            .filter(|_| total <= max)
            .ok_or(BudgetError::TooLarge { max })?;
        let others = u64::try_from(concurrency.saturating_sub(1)).unwrap_or(u64::MAX);
        let quota = (total - file_need)
            .checked_div(others)
            .map_or(file_need, |share| share.min(file_need));
        Ok(Self {
            semaphore: Arc::new(Semaphore::new(permits)),
            lane: Arc::new(Mutex::new(())),
            total,
            quota,
            file_need,
            held: AtomicU64::new(0),
            peak: AtomicU64::new(0),
        })
    }

    /// A budget of exactly one file's need, for one file at a time: for
    /// tests, which then need no error path.
    #[cfg(test)]
    pub(crate) fn single(file_need: u64) -> Arc<Self> {
        let permits = usize::try_from(file_need).unwrap_or(usize::MAX);
        Arc::new(Self {
            semaphore: Arc::new(Semaphore::new(permits)),
            lane: Arc::new(Mutex::new(())),
            total: file_need,
            quota: file_need,
            file_need,
            held: AtomicU64::new(0),
            peak: AtomicU64::new(0),
        })
    }

    /// The budget, in bytes.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }

    /// What each in-flight file may hold without the overflow lane.
    #[must_use]
    pub fn quota(&self) -> u64 {
        self.quota
    }

    /// Bytes held by every permit now.
    #[must_use]
    pub fn held(&self) -> u64 {
        self.held.load(Ordering::SeqCst)
    }

    /// The most bytes ever held at once.
    #[must_use]
    pub fn peak(&self) -> u64 {
        self.peak.load(Ordering::SeqCst)
    }

    /// Permits the semaphore could grant right now: the budget minus what
    /// is held, exactly.
    #[must_use]
    pub fn available(&self) -> u64 {
        u64::try_from(self.semaphore.available_permits()).unwrap_or(u64::MAX)
    }

    /// A new file's account against this budget.
    #[must_use]
    pub fn for_file(self: &Arc<Self>) -> FileBudget {
        FileBudget {
            budget: Arc::clone(self),
            state: Arc::new(FileState::default()),
        }
    }
}

/// What one file holds, shared with its permits so dropping one can give
/// the lane back.
#[derive(Debug, Default)]
struct FileState {
    /// Bytes held, plus bytes reserved by an acquisition still waiting.
    held: AtomicU64,
    /// The overflow lane, while this file holds it.
    lane: std::sync::Mutex<Option<OwnedMutexGuard<()>>>,
}

impl FileState {
    /// Gives the lane back if this file is within `quota`. Takes the same
    /// lock as an acquisition's reservation, so the two never interleave.
    fn release_lane_within(&self, quota: u64) {
        let mut lane = self.lane.lock().unwrap_or_else(PoisonError::into_inner);
        if self.held.load(Ordering::SeqCst) <= quota {
            lane.take();
        }
    }
}

/// Bytes an acquisition reserved before waiting, given back (with the lane,
/// if that brings the file within its share) unless the acquisition
/// succeeds and forgets this.
struct Reservation {
    state: Arc<FileState>,
    bytes: u64,
    quota: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.state.held.fetch_sub(self.bytes, Ordering::SeqCst);
        self.state.release_lane_within(self.quota);
    }
}

/// One file's account: what it holds, and the overflow lane while it needs
/// it.
#[derive(Debug)]
pub struct FileBudget {
    budget: Arc<MemoryBudget>,
    state: Arc<FileState>,
}

impl FileBudget {
    /// Acquires `bytes` permits, taking the overflow lane first if they
    /// would put this file over its share, and waiting at most
    /// [`BUDGET_WAIT`] for both.
    ///
    /// # Errors
    /// [`Refused::OverNeed`] past the largest single-file need, and
    /// [`Refused::TimedOut`] after waiting [`BUDGET_WAIT`].
    pub async fn acquire(&mut self, bytes: u64) -> Result<Permit, Refused> {
        let budget = Arc::clone(&self.budget);
        let state = Arc::clone(&self.state);
        let count = u32::try_from(bytes).map_err(|_| Refused::OverNeed)?;
        // Reserve first, under the lane lock (see the module doc).
        let needs_lane = {
            let lane = state.lane.lock().unwrap_or_else(PoisonError::into_inner);
            let held = state.held.load(Ordering::SeqCst);
            let after = held.checked_add(bytes).ok_or(Refused::OverNeed)?;
            if after > budget.file_need {
                return Err(Refused::OverNeed);
            }
            state.held.fetch_add(bytes, Ordering::SeqCst);
            after > budget.quota && lane.is_none()
        };
        // Undone if this acquisition fails, times out or is cancelled.
        let reservation = Reservation {
            state: Arc::clone(&state),
            bytes,
            quota: budget.quota,
        };
        let wait = async {
            if needs_lane {
                let guard = Arc::clone(&budget.lane).lock_owned().await;
                let mut lane = state.lane.lock().unwrap_or_else(PoisonError::into_inner);
                if state.held.load(Ordering::SeqCst) > budget.quota {
                    *lane = Some(guard);
                }
            }
            if count == 0 {
                return None;
            }
            Arc::clone(&budget.semaphore)
                .acquire_many_owned(count)
                .await
                .ok()
        };
        let semaphore = match tokio::time::timeout(BUDGET_WAIT, wait).await {
            Ok(Some(permit)) => Some(permit),
            Ok(None) if count == 0 => None,
            Ok(None) | Err(_) => return Err(Refused::TimedOut),
        };
        // The reserved bytes are now held: the permit gives them back.
        std::mem::forget(reservation);
        let now = budget.held.fetch_add(bytes, Ordering::SeqCst) + bytes;
        budget.peak.fetch_max(now, Ordering::SeqCst);
        Ok(Permit {
            semaphore,
            bytes,
            file: state,
            budget,
        })
    }

    /// Whether this file holds the overflow lane now.
    #[cfg(test)]
    fn holds_lane(&self) -> bool {
        self.state
            .lane
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }
}

/// Permits for `bytes`, released when dropped.
#[derive(Debug)]
pub struct Permit {
    semaphore: Option<OwnedSemaphorePermit>,
    bytes: u64,
    file: Arc<FileState>,
    budget: Arc<MemoryBudget>,
}

impl Permit {
    /// One permit covering both `self`'s bytes and `other`'s.
    #[must_use]
    pub fn join(mut self, mut other: Self) -> Self {
        // `other` gives up its bytes to `self`; its semaphore permits are
        // merged so nothing is released early.
        match (&mut self.semaphore, other.semaphore.take()) {
            (Some(mine), Some(theirs)) => mine.merge(theirs),
            (mine @ None, theirs) => *mine = theirs,
            (Some(_), None) => {}
        }
        self.bytes += other.bytes;
        other.bytes = 0;
        self
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.file.held.fetch_sub(self.bytes, Ordering::SeqCst);
        self.budget.held.fetch_sub(self.bytes, Ordering::SeqCst);
        // The semaphore permits go back when `self.semaphore` drops, right
        // after this; the lane goes back now if the file is within quota.
        self.file.release_lane_within(self.budget.quota);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::{BUDGET_WAIT, BudgetError, MAX_MEMORY_BUDGET, MemoryBudget, Refused};

    #[test]
    fn a_budget_below_one_file_s_need_is_refused() {
        assert_eq!(
            MemoryBudget::new(99, 4, 100).map(|b| b.total()),
            Err(BudgetError::TooSmall { file_need: 100 })
        );
    }

    #[test]
    fn the_semaphore_holds_exactly_the_requested_permits() -> Result<(), BudgetError> {
        for total in [100, 512 << 20, MAX_MEMORY_BUDGET] {
            let budget = MemoryBudget::new(total, 16, 100)?;
            assert_eq!(budget.available(), total);
            assert_eq!(budget.total(), total);
        }
        assert_eq!(
            MemoryBudget::new(MAX_MEMORY_BUDGET + 1, 16, 100).map(|b| b.total()),
            Err(BudgetError::TooLarge {
                max: MAX_MEMORY_BUDGET
            })
        );
        Ok(())
    }

    #[test]
    fn the_share_leaves_room_for_one_file_at_full_need() -> Result<(), BudgetError> {
        for (total, concurrency, need) in [(1000, 16, 100), (100, 16, 100), (1000, 1, 100)] {
            let budget = MemoryBudget::new(total, concurrency, need)?;
            let others = u64::try_from(concurrency - 1).unwrap_or(0);
            assert!(others * budget.quota() + need <= total);
        }
        assert_eq!(MemoryBudget::new(1000, 1, 100)?.quota(), 100);
        assert_eq!(MemoryBudget::new(1000, 16, 100)?.quota(), 60);
        Ok(())
    }

    #[tokio::test]
    async fn permits_are_counted_while_held_and_released_on_drop() -> Result<(), BudgetError> {
        let budget = Arc::new(MemoryBudget::new(1000, 4, 600)?);
        let mut a = budget.for_file();
        let mut b = budget.for_file();
        let small = a.acquire(100).await;
        // Over a's share: a takes the lane.
        let big = a.acquire(450).await;
        assert!(small.is_ok() && big.is_ok());
        assert!(a.holds_lane());
        assert_eq!(budget.held(), 550);
        assert_eq!(budget.available(), 450);
        // Over one file's need: refused, not left waiting.
        assert_eq!(a.acquire(100).await.err(), Some(Refused::OverNeed));
        let other = b.acquire(100).await;
        assert!(other.is_ok());
        drop((small, big, other));
        assert_eq!(budget.held(), 0);
        assert_eq!(budget.available(), 1000);
        assert_eq!(budget.peak(), 650);
        assert!(!a.holds_lane());
        Ok(())
    }

    #[tokio::test]
    async fn the_lane_is_released_as_soon_as_a_file_is_back_within_its_share()
    -> Result<(), Box<dyn std::error::Error>> {
        // Share: (1000 - 600) / 3 = 133.
        let budget = Arc::new(MemoryBudget::new(1000, 4, 600)?);
        let mut slow = budget.for_file();
        let base = slow.acquire(100).await;
        let burst = slow.acquire(100).await;
        assert!(slow.holds_lane(), "200 is over the share");
        drop(burst);
        assert!(!slow.holds_lane(), "back to 100, within the share");
        // The slow file is still running, but another file can take the
        // lane at once.
        let mut other = budget.for_file();
        let first = other.acquire(100).await;
        let over = tokio::time::timeout(Duration::from_secs(5), other.acquire(300)).await?;
        assert!(over.is_ok() && other.holds_lane());
        // And the slow file, needing the lane again, waits for it.
        let waiting = tokio::time::timeout(Duration::from_millis(50), slow.acquire(100)).await;
        assert!(waiting.is_err(), "the lane is taken");
        drop((over, first, base));
        assert!(!other.holds_lane());
        assert_eq!(budget.held(), 0);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn many_files_needing_more_than_their_share_all_finish() -> Result<(), BudgetError> {
        // Each file holds 30, then asks for 60 more: over its share (10),
        // so files take turns in the lane; none waits forever.
        let budget = Arc::new(MemoryBudget::new(160, 8, 100)?);
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let budget = Arc::clone(&budget);
            tasks.spawn(async move {
                let mut file = budget.for_file();
                let first = file.acquire(30).await;
                tokio::task::yield_now().await;
                let second = file.acquire(60).await;
                first.is_ok() && second.is_ok()
            });
        }
        let mut finished = 0;
        while let Some(done) = tasks.join_next().await {
            assert_eq!(done.ok(), Some(true));
            finished += 1;
        }
        assert_eq!(finished, 32);
        assert!(budget.peak() <= 160);
        assert_eq!(budget.held(), 0);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn files_that_briefly_exceed_their_share_and_drop_back_all_finish()
    -> Result<(), BudgetError> {
        // Each file bursts over its share (12), drops back, works a while
        // within it, bursts again: the lane changes hands mid-file, and
        // the budget is never exceeded.
        let budget = Arc::new(MemoryBudget::new(200, 8, 116)?);
        assert_eq!(budget.quota(), 12);
        // At most 8 files in flight, as the driver's window guarantees:
        // the budget's arithmetic assumes it.
        let in_flight = Arc::new(tokio::sync::Semaphore::new(8));
        let mut tasks = tokio::task::JoinSet::new();
        for n in 0..32_u64 {
            let budget = Arc::clone(&budget);
            let in_flight = Arc::clone(&in_flight);
            tasks.spawn(async move {
                let Ok(_slot) = in_flight.acquire_owned().await else {
                    return false;
                };
                let mut file = budget.for_file();
                let base = file.acquire(10).await;
                for round in 0..3 {
                    let burst = file.acquire(40 + (n + round) % 60).await;
                    tokio::task::yield_now().await;
                    let ok = burst.is_ok();
                    drop(burst);
                    if !ok || file.holds_lane() {
                        return false;
                    }
                    tokio::task::yield_now().await;
                }
                base.is_ok()
            });
        }
        while let Some(done) = tasks.join_next().await {
            assert_eq!(done.ok(), Some(true));
        }
        assert!(budget.peak() <= 200, "{}", budget.peak());
        assert_eq!(budget.held(), 0);
        assert_eq!(budget.available(), 200);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_wait_past_the_limit_is_refused_as_timed_out() -> Result<(), BudgetError> {
        // One file stalls holding the whole budget; the other gives up
        // after BUDGET_WAIT (paused time: no real waiting).
        let budget = Arc::new(MemoryBudget::new(100, 2, 100)?);
        let mut stalled = budget.for_file();
        let held = stalled.acquire(100).await;
        assert!(held.is_ok());
        let mut waiting = budget.for_file();
        let started = tokio::time::Instant::now();
        assert_eq!(waiting.acquire(10).await.err(), Some(Refused::TimedOut));
        assert!(started.elapsed() >= BUDGET_WAIT);
        assert!(!waiting.holds_lane());
        drop(held);
        assert_eq!(budget.held(), 0);
        // With the stall gone, the same file gets its permits.
        assert!(waiting.acquire(10).await.is_ok());
        Ok(())
    }
}
