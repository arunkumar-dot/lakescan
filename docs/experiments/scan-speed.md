# Scan speed (M9): concurrency and coalesced reads

**All numbers here are simulated.** They come from `examples/bench_scan.rs`
running LakeScan's real scan code (listing, reading, decoding, detection,
aggregation, reporting) against an in-memory object store with a latency
model, not against S3. Real-S3 measurement is still open: S3's actual
latency distribution, per-prefix request limits, throttling (503 SlowDown)
and connection reuse are not modelled.

## Targets (written before running)

1. **Concurrency.** On the small-file lake, `--concurrency 16` is at least
   **8×** faster (wall time) than `--concurrency 1`.
2. **Coalescing.** On large files, the default `--coalesce-gap` (1 MiB) cuts
   GET requests per file by at least **40%** versus `--coalesce-gap 0`,
   while adding at most **25%** more bytes read.

A missed target is reported as missed.

## Latency model

Every request sleeps `30 ms + bytes / 100 MB/s` (one connection's
throughput), then returns a copy of the bytes. Requests run concurrently
without a shared bandwidth cap, so the model is optimistic for very high
concurrency on one machine. Decoding is real work on the host's CPU, on
tokio's blocking pool.

## Workloads

- **Small-file lake.** 1,000 keys in 8 partitioned tables. Each key's bytes
  are one of the 8 committed readable fixtures (`tests/fixtures/parquet`:
  `customers.parquet` from 4 writers and 3 codecs, and `escalation.parquet`,
  1.2-2.1 MB each), shared in memory, not copied. All are under the 8 MiB
  whole-file maximum, so each is one whole read. Measured at `--concurrency`
  1, 4, 16 and 64, with the M9 default `--memory-budget` (256 MiB; the
  default is 512 MiB since M11.1).
- **Large files.** The round-2 spike files (`spikes/parquet-pii/data2`, 12
  files, 45-184 MB, pyarrow, Polars, DuckDB and Spark), when present (the
  benchmark's `--spike-dir`). Each is scanned alone, partially, with
  `--coalesce-gap 0` and with the default.
- **Listing alone.** Pages of 1,000 keys at 100 ms per page, no `--pii`: how
  fast listing feeds the pipeline, to compare with how fast content
  scanning consumes Parquet files.

## Results

Run on 2026-10-15, release build, macOS, 10 CPUs:
`cargo run --release --example bench_scan -- --spike-dir spikes/parquet-pii/data2`.

### Small-file lake: 1,000 files

| --concurrency | --memory-budget | wall time (s) | files/s | speedup vs 1 | GET requests | MB read | outputs identical to 1 |
|---:|---:|---:|---:|---:|---:|---:|---|
| 1 | 256 MiB | 63.34 | 16 | 1.0× | 1000 | 1419.0 | yes |
| 4 | 256 MiB | 15.95 | 63 | 4.0× | 1000 | 1419.0 | yes |
| 16 | 256 MiB | 4.38 | 228 | 14.4× | 1000 | 1419.0 | yes |
| 64 | 256 MiB | 4.10 | 244 | 15.4× | 1000 | 1419.0 | yes |
| 64 | 1024 MiB | 1.80 | 555 | 35.2× | 1000 | 1419.0 | yes |

"Outputs identical" compares the JSON summary (minus its timing fields)
and the findings stream with the `--concurrency 1` run.

### Large files: `--coalesce-gap 0` versus the default (1 MiB)

| file | MB | GETs, gap 0 | GETs, default | change | MB read, gap 0 | MB read, default | change | time (s), gap 0 | time (s), default | same findings |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| pyarrow/customers_1m | 148.8 | 19 | 18 | -5% | 6.7 | 7.0 | +5% | 0.27 | 0.28 | yes |
| pyarrow/tickets_1m | 73.6 | 13 | 13 | +0% | 2.5 | 2.5 | +0% | 0.18 | 0.18 | yes |
| pyarrow/events_2m | 181.4 | 14 | 12 | -14% | 4.7 | 5.4 | +14% | 0.19 | 0.20 | yes |
| polars/customers_1m | 91.2 | 11 | 4 | -64% | 3.6 | 5.7 | +60% | 0.16 | 0.18 | yes |
| polars/tickets_1m | 44.9 | 7 | 3 | -57% | 1.0 | 4.6 | +337% | 0.11 | 0.11 | yes |
| polars/events_2m | 117.6 | 9 | 4 | -56% | 3.5 | 4.4 | +26% | 0.12 | 0.12 | yes |
| duckdb/customers_1m | 148.2 | 20 | 10 | -50% | 17.5 | 20.0 | +14% | 0.36 | 0.37 | yes |
| duckdb/tickets_1m | 73.2 | 13 | 9 | -31% | 8.5 | 9.4 | +11% | 0.20 | 0.23 | yes |
| duckdb/events_2m | 182.2 | 15 | 9 | -40% | 11.2 | 11.7 | +4% | 0.24 | 0.24 | yes |
| spark/customers_1m | 150.8 | 11 | 10 | -9% | 2.4 | 2.7 | +13% | 0.15 | 0.16 | yes |
| spark/tickets_1m | 73.1 | 7 | 7 | +0% | 1.3 | 1.3 | +0% | 0.12 | 0.11 | yes |
| spark/events_2m | 183.7 | 9 | 7 | -22% | 1.8 | 2.9 | +59% | 0.11 | 0.13 | yes |

Total: 148 → 106 GET requests (-28%), 65.2 → 78.1 MB read (+20%).

### Listing alone: 1,000 keys per page, 100 ms per page

| keys | pages | wall time (s) | keys/s |
|---:|---:|---:|---:|
| 10000 | 10 | 1.03 | 9744 |
| 50000 | 50 | 5.12 | 9765 |

### M11.1: large files together, `--concurrency 16`

All 12 large spike files in one lake, scanned at `--concurrency 16`
(`cargo run --release --example bench_scan -- --spike-dir
spikes/parquet-pii/data2 --large-together-only`), three runs each, same
latency model and host (10 CPUs). "Before" is the code at v0.1.0's M11
commit, whose default budget was 256 MiB; "after" releases the overflow
lane as soon as a file is back within its share, and defaults to 512 MiB.

| code | --memory-budget | wall time (s), 3 runs | GET requests | MB read |
|---|---:|---:|---:|---:|
| before | 256 MiB (default) | 0.48, 0.49, 0.50 | 106 | 78.1 |
| after | 256 MiB | 0.42, 0.42, 0.42 | 106 | 78.1 |
| after | 512 MiB (default) | 0.36, 0.36, 0.36 | 106 | 78.1 |

The early release alone cuts the time by about 15% at the same budget;
with the larger default, by about 27%. Requests and bytes are unchanged:
only how long files wait for the lane changes. Simulated, like the rest.

## Verdict against the targets

1. **Concurrency: met.** `--concurrency 16` is **14.4×** faster than
   `--concurrency 1` (target: 8×), with identical outputs. At 1 the scan is
   latency-bound (63 ms per file: one 30 ms request, ~17 ms of transfer,
   and decoding); at 16 it is near the host's decoding throughput.
2. **Coalescing: missed on requests, met on bytes.** Requests fell **28%**
   in total, not 40%; only 4 of 12 files reached -40% (Polars' three and
   DuckDB's events). Bytes rose **20%** in total, within the 25% allowance,
   though one small Polars file read 4.6 MB instead of 1.0 MB (+337%).

## What the numbers say

- **Coalescing helps files with small row groups, not large ones.** It
  merges the first pages of different columns in one row group. Polars
  (125,000-row row groups) and DuckDB (122,880) write row groups of 15-30
  MB, so many columns' first pages sit within 1 MiB of the next one's;
  Polars files drop to 3-4 requests. pyarrow and Spark write one or two
  row groups of 0.9-1.5 million rows (125-242 MB each), which puts a whole
  column chunk, often tens of MB, between consecutive first pages, far
  past the 1 MiB gap, so almost nothing merges. (Layouts checked with
  pyarrow's metadata reader.) Reading
  those gaps would cost far more bytes than it saves in requests. A target
  of -40% per large file was optimistic for these writers.
- **Coalescing barely changes time.** Each file's ranges are already
  fetched four at a time, so fewer requests mostly saves request cost
  (S3 bills per GET), not wall time: under this model the default and
  `--coalesce-gap 0` take the same time on every large file.
- **The remaining requests are structural.** pyarrow and DuckDB write no
  offset index by default, so each column takes two reads: a 64 KiB window
  to find the page headers, then the page itself (Polars and Spark write
  one, and their files need one read per column). A larger first window would cut
  that, at a byte cost; it is a read-plan change, not coalescing, and was
  left out of M9 rather than tuned after seeing these numbers.
- **The memory budget caps concurrency for small files.** At
  `--concurrency 64` with the default 256 MiB budget, each in-flight file's
  free share is (256 MiB - 101 MiB) / 63 ≈ 2.5 MiB, less than a 2 MB file
  plus its decode permits, so most files take turns in the overflow lane
  and the speedup stalls at 15×. With 1 GiB it reaches 35×. Memory, not
  `--concurrency`, is the real limit above 16 at the default budget.
- **Listing is the next bottleneck for metadata-only scans.** One
  ListObjectsV2 stream yields ~9,800 keys/s under this model (100 ms per
  page), about 35 million keys an hour. Content scanning at
  `--concurrency 16` consumes ~230 Parquet files/s, so listing outruns it
  unless fewer than ~2% of keys are Parquet; without `--pii`, listing is
  all there is. Parallel listing (by prefix) is the next step for very
  large buckets, and is out of M9's scope.

## Still open

Real S3: latency tails, throttling (503 SlowDown) at high concurrency
(adaptive retry is on, but untested at scale), per-prefix request rate
limits, and whether one host's network sustains 16-64 connections at the
modelled throughput. None of that is measured here.
