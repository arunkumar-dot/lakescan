# First real-S3 test

**These are real-S3 numbers from one laptop, over a residential internet link,
to a bucket in ap-south-1.** They test whether LakeScan behaves on real S3
as it does on moto. They do not measure LakeScan's speed inside AWS: almost
all of the wall time below is spent moving bytes over a slow, unstable link,
not in S3 or in LakeScan.

Run on 2026-10-17 with `lakescan 0.1.0` (release build, commit 5408222),
macOS, against `motoserver/moto:5.2.3` for the baseline.

## Setup

| | |
|---|---|
| Bucket | `lakescan-real-test-ircbqe` (deleted after the test) |
| Region | ap-south-1 |
| Access | Block Public Access on (all four settings); bucket-owner-enforced ownership (the S3 default for new buckets). An anonymous `ListObjectsV2` returned `403 AccessDenied` before any upload. |
| Encryption | Default SSE-S3 (`AES256`); `HeadObject` on an uploaded object returned `ServerSideEncryption: AES256`. |
| Objects | 18 objects, 15,430,299 bytes (14.7 MiB) |
| Moto baseline | The same 18 keys and bytes in a moto bucket of the same name |

Layout:

- `lake/`: every file under `tests/fixtures/parquet/`, folder structure kept:
  11 `.parquet` files (8 readable `customers.parquet` and `escalation.parquet`,
  plus `bad/not_parquet.parquet`, `bad/truncated.parquet` and
  `skipped/too_large.parquet`) and 4 non-Parquet files (`README.md`,
  `generate.py`, `spark_write.py`, `requirements.txt`).
- `lake/extensionless/`: 3 of the same files with `.parquet` stripped from
  the key: `pyarrow/customers`, `spark/customers`, `escalation`.

The test IAM user could create the bucket and write its public-access and
encryption settings, but not read them back (`GetBucketPublicAccessBlock`,
`GetEncryptionConfiguration` and the other `Get*` bucket calls were denied),
or set ownership controls. Privacy was therefore confirmed by the anonymous
403 and by successful (exit 0) `Put*` calls, not by reading the settings back.

## Results

Wall time is LakeScan's own `scan.elapsed_ms`. Timed scans ran 3 times (the
concurrency pair 5 times, interleaved); the median is shown, with the range.
"Matches moto" compares the JSON summary and the findings stream with the
same run against moto, excluding timing fields (`started_at`, `elapsed_ms`)
and object timestamps (`last_modified`, and the inventory's
`oldest_file`/`newest_file`, which are upload times and so differ between
the two stores).

| scan | mode | exit | wall time, median (range) | GETs | bytes read | matches moto |
|---|---|---:|---|---:|---:|---|
| a | metadata only, `s3://bucket` | 0 | 0.74 s (0.30-1.44) | 0 | 0 | yes |
| b | `--pii` on `lake/` | 6 | 28.1 s (24.3-30.7) | 17 | 15,411,232 | yes |
| c | `--pii --pii-whole-file-max 0` | 6 | 27.4 s (17.0-28.5) | 46 | 9,687,850 | yes |
| d1 | `--pii --concurrency 1` | 6 | 16.1 s (12.0-149.0) | 17 | 15,411,232 | yes |
| d16 | `--pii --concurrency 16` | 6 | 29.5 s (25.5-31.9) | 17 | 15,411,232 | yes |
| e | `--pii` on `does-not-exist/` | 0 | 0.47 s | 0 | 0 | yes |
| f | `--pii`, bad credentials | 3 | 0.37 s | 0 | 0 | no: moto accepts any credentials (exit 6 there) |
| x | `--pii` on `lake/extensionless/` | 1 | 24.6 s (20.5-25.3) | 6 | 3,803,425 | yes |

Every content scan returned 95 findings (21 for `x`), the same findings as
moto. Exit 6 in b, c and d is expected: the three `bad/` and `skipped/`
fixtures cannot be scanned (`not-parquet=1, unreadable=1,
no-column-examined=1`), on moto too. The 4 non-Parquet files are out of
scope, on both.

- **d, concurrency 1 vs 16.** All 25 pairings of the 5 + 5 runs gave an
  identical summary (apart from `settings.concurrency` and timing) and a
  byte-identical findings stream, in the same order.
- **e, nonexistent prefix.** Exit 0, no message on stderr. The summary says
  `objects: 0` and `no findings`, the same as moto.
- **f, bad credentials.** Exit 3, `lakescan: auth: InvalidAccessKeyId: The
  AWS Access Key Id you provided does not exist in our records.` The listing
  fails, so nothing is read.

## Timing compared with the simulated model

`docs/experiments/scan-speed.md` models every request as
`30 ms + bytes / 100 MB/s`, with no shared bandwidth cap. Applied to this lake
(17 GETs, 15.4 MB), it predicts about 0.8 s at `--concurrency 1` (0.5 s
of request latency, 0.15 s of transfer, 0.14 s of local work) and about
0.1 s at 16. Scan-speed.md measured 63 ms per file at concurrency 1.

| scan | model | real (median) | real ÷ model |
|---|---:|---:|---:|
| d1, 14 files | ~0.8 s (63 ms/file) | 16.1 s (1.15 s/file) | ~20× |
| d16 | ~0.1 s | 29.5 s | ~300× |

GET latency estimate, as asked: (median wall time - local time) ÷ GETs,
using the moto run's wall time as the local decode and listing time.

| scan | median wall | moto (local) | GETs | per GET |
|---|---:|---:|---:|---:|
| b | 28.11 s | 0.06 s | 17 | 1.65 s |
| c | 27.38 s | 0.09 s | 46 | 0.59 s |
| d1 | 16.14 s | 0.14 s | 17 | 0.94 s |
| d16 | 29.50 s | 0.06 s | 17 | 1.73 s |
| x | 24.55 s | 0.03 s | 6 | 4.09 s |

These are not request latencies. Most GETs here download a whole 1-2 MB
file, and at concurrency above 1 they overlap, so the division mostly
measures this link's throughput. Measured directly with `curl`:

- **Request latency.** Time to first byte was 0.23-0.32 s for whole-object
  GETs, and 0.35-0.71 s for an 8-byte range GET on a new connection (the
  TLS handshake to `s3.ap-south-1.amazonaws.com` alone took 0.23 s). That is
  8-20× the model's 30 ms, as expected from a laptop rather than inside the
  region.
- **Throughput.** It varied widely, from minute to minute and object to
  object. The same 1.9 MB object downloaded in 0.97 s and then in 12.1 s
  (2.0 MB/s, then 0.16 MB/s). `aws s3api get-object` took 20.6 s for it,
  the same as LakeScan's single-file scan of it (20.7 s). The model assumes
  100 MB/s per connection.
- **Serial vs parallel, raw.** Downloading the scanned objects with `curl`
  one at a time took 92.6 s and 110.6 s in two rounds; 16 at a time, 19.4 s
  and 26.2 s.

So on this link LakeScan is as fast as the network: its single-file scan
matched the AWS CLI, and `--concurrency 16` (25.5-31.9 s) matched curl at
16 parallel downloads (19.4-26.2 s). `--concurrency 16` was the stable
setting; `--concurrency 1` was faster in 4 of 5 runs and much slower in
one (149 s), following the link's swings. The concurrency speedup in
scan-speed.md (14.4×) cannot be checked from here. That, and S3's real
latency, need a run from EC2 in the bucket's region. Running on an EC2
instance in the same region as the bucket removes internet latency; the 14x
concurrency speedup from the simulated model should hold there.

## Extensionless sniffing

`lakescan scan s3://<bucket>/lake/extensionless/ --pii`:

- **Sniffed:** 3 objects (one 8-byte range GET each).
- **Identified as Parquet:** 3 of 3 (`sniffed_not_parquet: 0`), then each
  downloaded whole: 6 GETs in all, 3,803,425 bytes (3 × 8 sniff bytes plus
  the 3 files).
- **Findings:** 21, identical to scanning the same three files under their
  `.parquet` keys (10 + 10 + 1), once the key is mapped back to the
  `.parquet` name. The same on moto.

The `lake/` scans (b, c, d) also sniffed these 3 objects and found them
Parquet. The 4 non-Parquet files were not sniffed: their extensions are on
the known non-Parquet list.

## Surprises and differences from moto

1. **The network, not S3 or LakeScan, set the wall time.** The bucket was
   20-300× slower than the simulated model, with throughput that changed
   10× from one download to the next. The model's "100 MB/s per connection,
   no shared cap" holds inside AWS, not over a residential link. PRODUCT.md's
   claim that scans "stay fast ... even outside AWS" holds for bytes read
   (and so for cost), not for wall time on a slow link.
2. **More concurrency was not faster here.** On a bandwidth-limited link,
   `--concurrency 16` was steadier than 1 but not faster in most runs.
   Outputs were identical at both, as designed.
3. **A nonexistent prefix exits 0, silently.** `s3://bucket/does-not-exist/`
   exits 0 with `objects: 0` and nothing on stderr, on real S3 and moto
   alike. A mistyped prefix in CI therefore passed green. **Fixed in
   M12.1:** an empty listing now prints `lakescan: no objects found under
   s3://<bucket>/<prefix>; check that the prefix is correct` to stderr; the
   exit code is still 0.
4. **Wrong region: real S3 redirects; moto does not.** With
   `AWS_REGION=us-east-1`, real S3 answered `PermanentRedirect`, and LakeScan
   exited 2: `lakescan: usage: PermanentRedirect: The bucket you are
   attempting to access must be addressed using the specified endpoint. ...
   (the bucket is in a different region; set AWS_REGION to match it)`.
   Correct and helpful, but moto accepted the wrong region and exited 0, so
   this path cannot be covered by the moto e2e tests. **Fixed in M12.1:**
   the message now names the bucket's region from the redirect's
   `x-amz-bucket-region` header (`bucket is in eu-west-1; rerun with
   --region eu-west-1`), which the SDK exposes on the raw response. Real S3
   sends that header with the 301 (checked with an anonymous request to a
   public bucket); the end-to-end path was not rerun against real S3.
5. **Bad credentials: exit 3 on real S3, a normal scan on moto.** Moto
   ignores credentials, so it ran the scan and exited 6. Expected, but the
   auth path (exit 3) is only testable against real S3.
6. **Nonexistent bucket: the same on both.** Exit 2, `NoSuchBucket ...
   (check the bucket name and that it exists)`.
7. **No throttling, failed reads or redirects during scans.** Across 22
   real content scans, no read failed (no `fetch-failed` or `access-denied`), and the
   GET and byte counts matched moto exactly. Whether the SDK retried
   anything silently cannot be told: LakeScan logs nothing about retries.
   A debug or verbose mode that counts retries and throttles would have
   answered this.
8. **A mid-body network failure is not retried.** Not observed, but the
   link made it plausible. In `src/content/fetch.rs`, `body.collect()` runs
   after `send()` returns, outside the SDK's retry loop, so a connection
   reset during the body becomes `FetchError::Failed`, that file becomes
   `content-not-scanned`, and the run exits 6. On a flaky link one dropped
   connection fails the coverage gate.

## Cleanup

Run with the test account's credentials in the environment (not shown here):

```sh
aws s3 rm s3://lakescan-real-test-ircbqe --recursive --region ap-south-1
aws s3api delete-bucket --bucket lakescan-real-test-ircbqe --region ap-south-1
aws s3api head-bucket --bucket lakescan-real-test-ircbqe --region ap-south-1   # expect 404 Not Found
docker stop lakescan-realtest-moto
```
