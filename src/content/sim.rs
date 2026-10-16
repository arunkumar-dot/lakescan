//! [`SimStore`]: an in-memory [`ObjectReader`] with a simulated S3 latency
//! model, for tests and `examples/bench_scan.rs`.
//!
//! Each request sleeps `per_request + bytes / bytes_per_second` (one
//! connection's throughput), plus an optional random jitter, then returns
//! a copy of the bytes, as a network would. Objects are shared
//! (`Arc<Vec<u8>>`), so a thousand keys can point at a handful of fixture
//! files without copies. It counts requests and bytes, can refuse or fail
//! chosen keys, and, when it watches a [`MemoryBudget`], records every
//! request that was not covered by permits held at the time, and any
//! moment the budget's holdings exceeded it.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_sdk_s3::primitives::{AggregatedBytes, ByteStream};

use super::budget::MemoryBudget;
use super::fetch::{FetchError, ObjectReader};

/// How long a simulated request takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Latency {
    /// Fixed cost per request (time to first byte).
    pub per_request: Duration,
    /// One connection's throughput; 0 for unlimited.
    pub bytes_per_second: u64,
    /// Up to this much more, chosen at random per request.
    pub jitter: Duration,
}

impl Latency {
    /// No delay at all.
    pub const NONE: Self = Self {
        per_request: Duration::ZERO,
        bytes_per_second: 0,
        jitter: Duration::ZERO,
    };

    fn of(self, bytes: u64, random: u64) -> Duration {
        let transfer = if self.bytes_per_second == 0 {
            Duration::ZERO
        } else {
            let micros = u128::from(bytes) * 1_000_000 / u128::from(self.bytes_per_second);
            Duration::from_micros(u64::try_from(micros).unwrap_or(u64::MAX))
        };
        let jitter_micros = u64::try_from(self.jitter.as_micros()).unwrap_or(0);
        let jitter = if jitter_micros == 0 {
            Duration::ZERO
        } else {
            Duration::from_micros(random % jitter_micros)
        };
        self.per_request + transfer + jitter
    }
}

#[derive(Debug, Default)]
struct Objects {
    data: HashMap<String, Arc<Vec<u8>>>,
    denied: HashSet<String>,
    failing: HashSet<String>,
}

#[derive(Debug)]
struct Inner {
    objects: Mutex<Objects>,
    latency: Mutex<Latency>,
    watched: Mutex<Option<Arc<MemoryBudget>>>,
    requests: AtomicU64,
    bytes: AtomicU64,
    unpermitted: AtomicU64,
    over_budget: AtomicU64,
    seed: AtomicU64,
}

/// An in-memory object store; see this module's doc. Clones share it.
#[derive(Debug, Clone)]
pub struct SimStore {
    inner: Arc<Inner>,
}

impl Default for SimStore {
    fn default() -> Self {
        Self::new(Latency::NONE)
    }
}

impl SimStore {
    /// An empty store answering with `latency`.
    #[must_use]
    pub fn new(latency: Latency) -> Self {
        Self {
            inner: Arc::new(Inner {
                objects: Mutex::new(Objects::default()),
                latency: Mutex::new(latency),
                watched: Mutex::new(None),
                requests: AtomicU64::new(0),
                bytes: AtomicU64::new(0),
                unpermitted: AtomicU64::new(0),
                over_budget: AtomicU64::new(0),
                seed: AtomicU64::new(0x5eed),
            }),
        }
    }

    /// Stores `data` at `key`, shared, not copied.
    pub fn insert(&self, key: &str, data: Arc<Vec<u8>>) {
        if let Ok(mut objects) = self.inner.objects.lock() {
            objects.data.insert(key.to_owned(), data);
        }
    }

    /// Stores `body` at `key`; for chaining in tests.
    #[must_use]
    pub fn with(self, key: &str, body: Vec<u8>) -> Self {
        self.insert(key, Arc::new(body));
        self
    }

    /// Refuses every read of `key` (access denied).
    pub fn deny(&self, key: &str) {
        if let Ok(mut objects) = self.inner.objects.lock() {
            objects.denied.insert(key.to_owned());
        }
    }

    /// Fails every read of `key`, as a request still failing after the
    /// SDK's retries would.
    pub fn fail(&self, key: &str) {
        if let Ok(mut objects) = self.inner.objects.lock() {
            objects.failing.insert(key.to_owned());
        }
    }

    /// Changes the latency model, and the jitter's random seed.
    pub fn set_latency(&self, latency: Latency, seed: u64) {
        if let Ok(mut current) = self.inner.latency.lock() {
            *current = latency;
        }
        self.inner.seed.store(seed, Ordering::SeqCst);
    }

    /// Checks every request against `budget` (see this module's doc).
    pub fn watch(&self, budget: &Arc<MemoryBudget>) {
        if let Ok(mut watched) = self.inner.watched.lock() {
            *watched = Some(Arc::clone(budget));
        }
    }

    /// Requests answered so far.
    #[must_use]
    pub fn requests(&self) -> u64 {
        self.inner.requests.load(Ordering::SeqCst)
    }

    /// Bytes returned so far.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.inner.bytes.load(Ordering::SeqCst)
    }

    /// Requests made while the watched budget held fewer bytes than they
    /// asked for: fetches without permits.
    #[must_use]
    pub fn unpermitted(&self) -> u64 {
        self.inner.unpermitted.load(Ordering::SeqCst)
    }

    /// Requests made while the watched budget held more than its total.
    #[must_use]
    pub fn over_budget(&self) -> u64 {
        self.inner.over_budget.load(Ordering::SeqCst)
    }

    /// Resets the counters.
    pub fn reset_counts(&self) {
        for counter in [
            &self.inner.requests,
            &self.inner.bytes,
            &self.inner.unpermitted,
            &self.inner.over_budget,
        ] {
            counter.store(0, Ordering::SeqCst);
        }
    }

    fn random(&self) -> u64 {
        // SplitMix64 over a shared counter.
        let mut z = self
            .inner
            .seed
            .fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::SeqCst)
            .wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

impl ObjectReader for SimStore {
    async fn read_range(
        &self,
        key: &str,
        start: u64,
        end: u64,
    ) -> Result<AggregatedBytes, FetchError> {
        self.inner.requests.fetch_add(1, Ordering::SeqCst);
        let wanted = end.saturating_sub(start);
        let watched = self.inner.watched.lock().ok().and_then(|w| w.clone());
        if let Some(budget) = watched {
            if budget.held() < wanted {
                self.inner.unpermitted.fetch_add(1, Ordering::SeqCst);
            }
            if budget.held() > budget.total() || budget.peak() > budget.total() {
                self.inner.over_budget.fetch_add(1, Ordering::SeqCst);
            }
        }
        let (data, denied, failing) = {
            let objects = self.inner.objects.lock().map_err(|_| FetchError::Failed)?;
            (
                objects.data.get(key).cloned(),
                objects.denied.contains(key),
                objects.failing.contains(key),
            )
        };
        let latency = self
            .inner
            .latency
            .lock()
            .map_or(Latency::NONE, |latency| *latency);
        let delay = latency.of(wanted, self.random());
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        if denied {
            return Err(FetchError::AccessDenied);
        }
        let data = data.filter(|_| !failing).ok_or(FetchError::Failed)?;
        let from = usize::try_from(start).map_err(|_| FetchError::Failed)?;
        let to = usize::try_from(end).map_err(|_| FetchError::Failed)?;
        let slice = data
            .get(from..to.min(data.len()))
            .ok_or(FetchError::Failed)?;
        self.inner.bytes.fetch_add(
            u64::try_from(slice.len()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
        ByteStream::from(slice.to_vec())
            .collect()
            .await
            .map_err(|_| FetchError::Failed)
    }
}
