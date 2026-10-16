//! Scan-speed benchmark for M9: `LakeScan`'s real scan code against an
//! in-memory store with a simulated S3 latency model (see
//! `docs/experiments/scan-speed.md`, where the results are written up).
//!
//! ```text
//! cargo run --release --example bench_scan -- \
//!     [--spike-dir spikes/parquet-pii/data2] [--files 1000]
//! ```
//!
//! Prints three Markdown tables: the small-file lake at several
//! `--concurrency` values, large files with and without coalescing (only
//! when `--spike-dir` holds the round-2 spike files), and listing alone.
//! The numbers are simulated: real-S3 measurement is still open.

use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use lakescan::cli::{ContentSettings, scan_with};
use lakescan::content::{DEFAULT_COALESCE_GAP, Latency, SimStore};
use lakescan::error::LakeScanError;
use lakescan::model::{ObjectMeta, StorageClass};
use lakescan::report::Format;
use lakescan::scanner::PageSource;

/// 30 ms per request, plus 100 MB/s per connection.
const MODEL: Latency = Latency {
    per_request: Duration::from_millis(30),
    bytes_per_second: 100_000_000,
    jitter: Duration::ZERO,
};

/// Listing: 100 ms per page of 1,000 keys.
const PAGE_DELAY: Duration = Duration::from_millis(100);
const PAGE_SIZE: usize = 1000;

/// The committed readable fixtures the small-file lake is made of.
const FIXTURES: [&str; 8] = [
    "pyarrow/customers.parquet",
    "polars/customers.parquet",
    "duckdb/customers.parquet",
    "spark/customers.parquet",
    "gzip/pyarrow/customers.parquet",
    "gzip/spark/customers.parquet",
    "brotli/pyarrow/customers.parquet",
    "escalation.parquet",
];

/// A listing of fixed objects, `PAGE_SIZE` per page, each page after
/// `delay`.
struct SimListing {
    objects: Vec<ObjectMeta>,
    next: usize,
    delay: Duration,
}

impl PageSource for SimListing {
    async fn fetch_page(
        &mut self,
        _continuation: Option<String>,
        out: &mut Vec<ObjectMeta>,
    ) -> Result<Option<String>, LakeScanError> {
        tokio::time::sleep(self.delay).await;
        let end = (self.next + PAGE_SIZE).min(self.objects.len());
        out.extend(
            self.objects
                .get(self.next..end)
                .unwrap_or_default()
                .iter()
                .cloned(),
        );
        self.next = end;
        Ok((end < self.objects.len()).then(|| end.to_string()))
    }
}

fn object(key: String, size: u64) -> ObjectMeta {
    ObjectMeta {
        etag: format!("etag-{key}"),
        key,
        size,
        last_modified: SystemTime::UNIX_EPOCH + Duration::from_hours(480_000),
        storage_class: StorageClass::Standard,
    }
}

/// One scan's measurements.
struct Measured {
    seconds: f64,
    requests: u64,
    bytes: u64,
    summary: String,
    findings: String,
}

/// Scans `objects` from `store` with `settings` (`None`: no `--pii`).
async fn measure(
    objects: Vec<ObjectMeta>,
    store: &SimStore,
    settings: Option<ContentSettings>,
    delay: Duration,
) -> Result<Measured, Box<dyn Error>> {
    store.reset_counts();
    let listing = SimListing {
        objects,
        next: 0,
        delay,
    };
    let (mut summary, mut findings) = (Vec::new(), Vec::new());
    let started = Instant::now();
    scan_with(
        listing,
        "bench",
        settings.map(|settings| (store.clone(), settings)),
        Format::Json,
        &mut summary,
        Some(&mut findings),
    )
    .await?;
    let seconds = started.elapsed().as_secs_f64();
    // The summary without its timing fields, to compare runs.
    let mut summary: serde_json::Value = serde_json::from_slice(&summary)?;
    if let Some(scan) = summary
        .get_mut("scan")
        .and_then(serde_json::Value::as_object_mut)
    {
        scan.remove("started_at");
        scan.remove("elapsed_ms");
    }
    Ok(Measured {
        seconds,
        requests: store.requests(),
        bytes: store.bytes(),
        summary: summary.to_string(),
        findings: String::from_utf8(findings)?,
    })
}

fn mb(bytes: u64) -> String {
    format!(
        "{:.1}",
        f64::from(u32::try_from(bytes / 100_000).unwrap_or(u32::MAX)) / 10.0
    )
}

async fn small_file_lake(fixtures: &Path, files: usize) -> Result<(), Box<dyn Error>> {
    let store = SimStore::new(MODEL);
    let mut bodies = Vec::new();
    for path in FIXTURES {
        bodies.push(Arc::new(std::fs::read(fixtures.join(path))?));
    }
    let mut objects = Vec::new();
    for i in 0..files {
        let which = i % bodies.len();
        let body = bodies.get(which).ok_or("no fixture")?;
        let key = format!("lake/t{which}/dt={i:05}/part-0.parquet");
        store.insert(&key, Arc::clone(body));
        objects.push(object(key, u64::try_from(body.len())?));
    }

    println!("### Small-file lake: {files} files, 1 page of listing per 1,000 keys\n");
    println!(
        "| --concurrency | --memory-budget | wall time (s) | files/s | speedup vs 1 | GET requests | MB read | outputs identical to 1 |"
    );
    println!("|---:|---:|---:|---:|---:|---:|---:|---|");
    let mut baseline: Option<Measured> = None;
    for (concurrency, budget) in [
        (1, 256_u64 << 20),
        (4, 256 << 20),
        (16, 256 << 20),
        (64, 256 << 20),
        (64, 1 << 30),
    ] {
        let settings = ContentSettings {
            concurrency,
            memory_budget: budget,
            ..ContentSettings::default()
        };
        let run = measure(objects.clone(), &store, Some(settings), PAGE_DELAY).await?;
        let (speedup, identical) = match &baseline {
            Some(first) => (
                first.seconds / run.seconds,
                first.summary == run.summary && first.findings == run.findings,
            ),
            None => (1.0, true),
        };
        let files_f = f64::from(u32::try_from(files).unwrap_or(u32::MAX));
        println!(
            "| {concurrency} | {} MiB | {:.2} | {:.0} | {speedup:.1}× | {} | {} | {} |",
            budget >> 20,
            run.seconds,
            files_f / run.seconds,
            run.requests,
            mb(run.bytes),
            if identical { "yes" } else { "NO" }
        );
        if baseline.is_none() {
            baseline = Some(run);
        }
    }
    println!();
    Ok(())
}

async fn large_files(spike_dir: Option<&Path>) -> Result<(), Box<dyn Error>> {
    println!("### Large files: --coalesce-gap 0 versus the default (1 MiB)\n");
    let Some(dir) = spike_dir.filter(|dir| dir.is_dir()) else {
        println!("Skipped: the round-2 spike files are not present (pass --spike-dir).\n");
        return Ok(());
    };
    let mut paths = Vec::new();
    for writer in ["pyarrow", "polars", "duckdb", "spark"] {
        for table in ["customers_1m", "tickets_1m", "events_2m"] {
            let path = dir.join(writer).join(format!("{table}.parquet"));
            if path.is_file() {
                paths.push((format!("{writer}/{table}"), path));
            }
        }
    }
    println!(
        "| file | MB | GETs, gap 0 | GETs, default | change | MB read, gap 0 | MB read, default | change | time (s), gap 0 | time (s), default | same findings |"
    );
    println!("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|");
    let (mut requests_apart, mut requests_merged, mut bytes_apart, mut bytes_merged) =
        (0_u64, 0_u64, 0_u64, 0_u64);
    for (name, path) in paths {
        let body = Arc::new(std::fs::read(&path)?);
        let size = u64::try_from(body.len())?;
        let store = SimStore::new(MODEL);
        let key = format!("big/{name}.parquet");
        store.insert(&key, body);
        let mut runs = Vec::new();
        for gap in [0, DEFAULT_COALESCE_GAP] {
            let settings = ContentSettings {
                concurrency: 1,
                coalesce_gap: gap,
                ..ContentSettings::default()
            };
            runs.push(
                measure(
                    vec![object(key.clone(), size)],
                    &store,
                    Some(settings),
                    Duration::ZERO,
                )
                .await?,
            );
        }
        let [apart, merged] = runs.as_slice() else {
            return Err("two runs expected".into());
        };
        let change = |before: u64, after: u64| {
            let (before, after) = (
                f64::from(u32::try_from(before).unwrap_or(u32::MAX)),
                f64::from(u32::try_from(after).unwrap_or(u32::MAX)),
            );
            format!("{:+.0}%", (after - before) / before * 100.0)
        };
        println!(
            "| {name} | {} | {} | {} | {} | {} | {} | {} | {:.2} | {:.2} | {} |",
            mb(size),
            apart.requests,
            merged.requests,
            change(apart.requests, merged.requests),
            mb(apart.bytes),
            mb(merged.bytes),
            change(apart.bytes / 1000, merged.bytes / 1000),
            apart.seconds,
            merged.seconds,
            if apart.findings == merged.findings {
                "yes"
            } else {
                "NO"
            }
        );
        requests_apart += apart.requests;
        requests_merged += merged.requests;
        bytes_apart += apart.bytes;
        bytes_merged += merged.bytes;
    }
    println!(
        "\nTotal: {requests_apart} → {requests_merged} GET requests, {} → {} MB read.\n",
        mb(bytes_apart),
        mb(bytes_merged)
    );
    Ok(())
}

async fn listing_alone() -> Result<(), Box<dyn Error>> {
    println!("### Listing alone: 1,000 keys per page, 100 ms per page, no --pii\n");
    println!("| keys | pages | wall time (s) | keys/s |");
    println!("|---:|---:|---:|---:|");
    let store = SimStore::new(MODEL);
    for keys in [10_000, 50_000] {
        let objects: Vec<ObjectMeta> = (0..keys)
            .map(|i| object(format!("logs/{i:07}.json"), 1000))
            .collect();
        let run = measure(objects, &store, None, PAGE_DELAY).await?;
        let keys_f = f64::from(u32::try_from(keys).unwrap_or(u32::MAX));
        println!(
            "| {keys} | {} | {:.2} | {:.0} |",
            keys / PAGE_SIZE,
            run.seconds,
            keys_f / run.seconds
        );
    }
    println!();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut spike_dir: Option<PathBuf> = None;
    let mut files = 1000;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--spike-dir" => spike_dir = args.next().map(PathBuf::from),
            "--files" => files = args.next().ok_or("--files needs a number")?.parse()?,
            other => return Err(format!("unknown argument {other:?}").into()),
        }
    }
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/parquet");
    println!(
        "Latency model: {} ms per request + {} MB/s per connection. Host: {} CPUs.\n",
        MODEL.per_request.as_millis(),
        MODEL.bytes_per_second / 1_000_000,
        std::thread::available_parallelism().map_or(0, std::num::NonZero::get)
    );
    small_file_lake(&fixtures, files).await?;
    large_files(spike_dir.as_deref()).await?;
    listing_alone().await?;
    let _ = io::Write::flush(&mut io::stdout());
    Ok(())
}
