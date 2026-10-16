//! [`MemoryBudget`]: the byte-counting semaphore that bounds what in-flight
//! content scans hold (`--memory-budget`).
//!
//! Every fetch acquires permits for the bytes it will return, and every
//! decode for the pages' declared sizes, before it starts; a [`Permit`]
//! releases them when the buffers it guards are dropped. No fetch or
//! decode happens without permits.
//!
//! **No deadlock.** Files acquire permits a little at a time while holding
//! others (a footer while its pages are read), and two files that each
//! hold part of a budget while waiting for the rest could wait forever.
//! So permits come in two tiers. Each in-flight file may hold up to its
//! *share* (`quota`) freely. A file that needs more first takes the one
//! *overflow lane* and keeps it until it finishes, and may then hold up to
//! the largest single-file need ([`file_need`](super::file_need)). With at
//! most `concurrency` files in flight,
//!
//! ```text
//! (concurrency - 1) × quota + file_need  <=  budget
//! ```
//!
//! so every acquisition can be granted at once, and a file waits only for
//! the lane, whose holder never waits on anyone. The quota is the largest
//! value that keeps that true; a budget below one file's need is a usage
//! error, caught at startup.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{Mutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetTooSmall {
    /// The most one file can need.
    pub file_need: u64,
}

impl MemoryBudget {
    /// A budget of `total` bytes for `concurrency` files in flight, each
    /// needing at most `file_need`.
    ///
    /// # Errors
    /// [`BudgetTooSmall`] if `total` is below `file_need`: one file could
    /// then wait for permits forever.
    pub fn new(total: u64, concurrency: usize, file_need: u64) -> Result<Self, BudgetTooSmall> {
        if total < file_need {
            return Err(BudgetTooSmall { file_need });
        }
        let others = u64::try_from(concurrency.saturating_sub(1)).unwrap_or(u64::MAX);
        let quota = (total - file_need)
            .checked_div(others)
            .map_or(file_need, |share| share.min(file_need));
        let permits = usize::try_from(total)
            .unwrap_or(usize::MAX)
            .min(Semaphore::MAX_PERMITS);
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
        let permits = usize::try_from(file_need)
            .unwrap_or(usize::MAX)
            .min(Semaphore::MAX_PERMITS);
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

    /// A new file's account against this budget.
    #[must_use]
    pub fn for_file(self: &Arc<Self>) -> FileBudget {
        FileBudget {
            budget: Arc::clone(self),
            held: Arc::new(AtomicU64::new(0)),
            lane: None,
        }
    }
}

/// One file's account: what it holds, and the overflow lane if it took it.
#[derive(Debug)]
pub struct FileBudget {
    budget: Arc<MemoryBudget>,
    held: Arc<AtomicU64>,
    lane: Option<OwnedMutexGuard<()>>,
}

impl FileBudget {
    /// Acquires `bytes` permits, taking the overflow lane first if they
    /// would put this file over its share. `None` if they would put it
    /// over the largest single-file need, which the caps rule out: a file
    /// that somehow asked for more is refused rather than left waiting.
    pub async fn acquire(&mut self, bytes: u64) -> Option<Permit> {
        let held = self.held.load(Ordering::SeqCst);
        let after = held.checked_add(bytes)?;
        if after > self.budget.file_need {
            return None;
        }
        if after > self.budget.quota && self.lane.is_none() {
            self.lane = Some(Arc::clone(&self.budget.lane).lock_owned().await);
        }
        let permit = if bytes == 0 {
            None
        } else {
            let count = u32::try_from(bytes).ok()?;
            Some(
                Arc::clone(&self.budget.semaphore)
                    .acquire_many_owned(count)
                    .await
                    .ok()?,
            )
        };
        self.held.fetch_add(bytes, Ordering::SeqCst);
        let now = self.budget.held.fetch_add(bytes, Ordering::SeqCst) + bytes;
        self.budget.peak.fetch_max(now, Ordering::SeqCst);
        Some(Permit {
            semaphore: permit,
            bytes,
            file: Arc::clone(&self.held),
            budget: Arc::clone(&self.budget),
        })
    }
}

/// Permits for `bytes`, released when dropped.
#[derive(Debug)]
pub struct Permit {
    semaphore: Option<OwnedSemaphorePermit>,
    bytes: u64,
    file: Arc<AtomicU64>,
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
        self.file.fetch_sub(self.bytes, Ordering::SeqCst);
        self.budget.held.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{BudgetTooSmall, MemoryBudget};

    #[test]
    fn a_budget_below_one_file_s_need_is_refused() {
        assert_eq!(
            MemoryBudget::new(99, 4, 100).map(|b| b.total()),
            Err(BudgetTooSmall { file_need: 100 })
        );
    }

    #[test]
    fn the_share_leaves_room_for_one_file_at_full_need() -> Result<(), BudgetTooSmall> {
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
    async fn permits_are_counted_while_held_and_released_on_drop() -> Result<(), BudgetTooSmall> {
        let budget = Arc::new(MemoryBudget::new(1000, 4, 600)?);
        let mut a = budget.for_file();
        let mut b = budget.for_file();
        let small = a.acquire(100).await;
        // Over a's share: a takes the lane.
        let big = a.acquire(450).await;
        assert!(small.is_some() && big.is_some());
        assert_eq!(budget.held(), 550);
        // Over one file's need: refused, not left waiting.
        assert!(a.acquire(100).await.is_none());
        let other = b.acquire(100).await;
        assert!(other.is_some());
        drop((small, big, other));
        assert_eq!(budget.held(), 0);
        assert_eq!(budget.peak(), 650);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn many_files_needing_more_than_their_share_all_finish() -> Result<(), BudgetTooSmall> {
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
                first.is_some() && second.is_some()
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
}
