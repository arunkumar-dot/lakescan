# Changelog

All notable changes to LakeScan. Versions follow
[Semantic Versioning](https://semver.org/); the public contracts are the
exit codes, the rule codes and the JSON summary's `schema_version`.

## [Unreleased]

## [0.1.1] - 2026-10-18

### Preflight checks (M14)

Before the first listing, `lakescan scan` calls `sts:GetCallerIdentity` and
`s3:HeadBucket`. Unusable credentials or a denied bucket exit 3; a missing
bucket or one in another region exits 2, naming the `--region` to use. With
`--pii` (and not `--quiet`) stderr gets a one-line hint about `s3:GetObject`
and `kms:Decrypt`. `LAKESCAN_DEBUG=1` logs the caller's ARN. Scans now need
`sts:GetCallerIdentity` too (README, Permissions).

Detection fixes from real public datasets (M12; see
[docs/experiments/real-data.md](docs/experiments/real-data.md)). Exit
codes and rule codes are unchanged; the JSON summary gains fields and one
table status, all additive, so `schema_version` stays 1.

### Detection

- Person-name hints: whole-name parts (`FIRST`, `LAST`, `MIDDLE`, `MAIDEN`,
  `family`, `given`) and name words (`surname`, `forename`, `fname`,
  `lname`) are strong; `name` counts only when a name part or a person
  noun qualifies it (`nameFirst`, `customer_display_name`). A bare `name`
  and names of things (`Short Name`, `Indicator Name`, `drug_name`,
  `organization_name`) no longer hint anything.
- Date-of-birth hints: `bdate`, `bday`, `birth_dt` and `date_birth` are
  strong; a count, rate or flag of births (`multipleBirthInteger`,
  `birth_rate`, `births`) no longer hints.
- Phones: North American numbers (`(201) 555-0123`), UK and EU national
  numbers with a trunk `0`, and `00`-prefixed international numbers, when
  written with separators. A phone column whose name isn't about a person
  is `confirmed` only at a 95% match rate, else `likely`: organisations
  have phone numbers too. A bare digit run (no `+`, no separators, and
  every integer column) counts as a phone only under a name with a phone
  or contact word (`phone`, `mobile`, `cell`, `tel`, `contact`, `msisdn`):
  identifiers such as US NPI numbers look like Indian mobiles. An unnamed
  column of bare mobile numbers is therefore no longer reported.
- Repeated (list and map) columns are read, and named for their hints by
  the field behind the wrapper (`telecom.list.element.value` is `value`).
  A repeated page may declare at most 131,072 values; one file now needs
  at most ~108 MiB of the memory budget (was ~103 MiB).
- Cleaning drops emails at `example.com`, `example.org`, `example.net` and
  `.test` (test accounts), masked values (`****1234`) and the sentinel
  dates `1900-01-01` and `1970-01-01`. A column with no value left after
  cleaning, or a date column whose statistics say it is all null, is never
  reported, even on its name.

### Coverage honesty

- Columns that could hold personal data but were not examined (a string or
  integer column skipped for any reason, or a float, decimal or time
  column named like PII) are recorded per table and in COVERAGE, in text,
  HTML, JSON and CSV. A table with no PII found and such columns has the
  new status `columns_not_examined`, never `no_pii_in_scanned_files`. They
  are reported only: the exit code is unchanged.

### Real-S3 fixes (M12.1)

From the first real-S3 test
([docs/experiments/real-s3.md](docs/experiments/real-s3.md)). Exit codes
are unchanged.

- A scan whose listing returns no objects (an empty or mistyped prefix)
  prints `lakescan: no objects found under s3://<bucket>/<prefix>; check
  that the prefix is correct` to stderr, `--quiet` or not, and still
  exits 0.
- When S3 redirects a listing to the bucket's region (`PermanentRedirect`,
  exit 2), the error names that region from the `x-amz-bucket-region`
  header: `bucket is in eu-west-1; rerun with --region eu-west-1`. Without
  the header, the message is unchanged.

### Fixtures

- The committed fixtures' emails moved to the reserved `.example`
  top-level domain, which LakeScan keeps; every other value is unchanged.

## [0.1.0]

The first release: an S3 bucket audit from the object listing, and, with
`--pii`, a scan of Parquet files for personal data, run in your own account
with read-only access. A discovery aid, not a compliance assessment: no
finding does not prove there is no personal data.

### Bucket audit (no object contents read)

- `lakescan scan s3://bucket/prefix` pages through the listing with fixed
  memory, however large the bucket.
- Six rules: secret-looking keys (`sensitive-key`), deprecated
  `REDUCED_REDUNDANCY` storage, stale `STANDARD` data, small objects in cold
  tiers, empty objects, and unrecognized storage classes.
- A summary as text or JSON: inventory by storage class, findings by rule
  and severity, examples, the largest objects, size and age histograms, and
  an estimate of duplicated content.
- `--findings`: one JSON line per finding as it is found, keys untruncated.
- Frozen exit codes for CI: 0 clean, 1 findings at or above
  `--fail-on`, and distinct codes for usage, credential, network, report
  and coverage failures.
- Suppressions (`--config`): accept a finding by key or prefix, with a
  reason and an optional expiry date. Expired and unused entries are
  reported.
- Hostile key names (terminal escapes, right-to-left overrides) are escaped
  in text output and round-trip exactly in JSON.

### PII scanning of Parquet files (`--pii`)

- Finds emails, phone numbers (E.164 and Indian mobiles), Indian PAN and
  Aadhaar numbers, card numbers and IP addresses from the values, and
  people's names and dates of birth from column names.
- Reads only what reveals a column's contents: the footer, the first data
  page of up to three row groups, and dictionary pages. Small files are
  read whole, in one request. On large files that is 0.8-8.1% of the data
  in tests.
- Messy data is cleaned first (nulls, blanks, placeholders, padding,
  dominant default values), and every verdict comes with a confidence:
  confirmed, likely or possible.
- Snappy, ZSTD, LZ4, GZIP and Brotli pages. GZIP and Brotli are decoded by
  LakeScan within each page's declared size, so a hostile file cannot
  exhaust memory.
- Never reports a value: only the column, the rule, and how many sampled
  values matched.
- A per-table PII inventory: partitioned and Iceberg-style keys are
  grouped into tables, with each table's PII columns and whether each is
  documented by a suppression. Also as CSV (`--inventory`).
- Coverage fails closed: a Parquet file that could not be scanned
  (unreadable, encrypted, access denied, too wide, and so on) fails the run
  with exit code 6 until a suppression documents it.
- Parquet files without an extension (as Athena CTAS and Trino write them)
  are found by sniffing: one 8-byte ranged GET per object with no
  extension, or one not known to be another format, checks the `PAR1`
  magic (`--pii-sniff unknown`, the default; `none` turns it off).
- Every output says what it could not say: inspection is sampled in every
  mode (a whole-file download is still sampled); objects out of scope are
  counted by extension, with sniffed non-Parquet objects and empty ones; a
  table with nothing found reads "No structured PII detected in sampled
  data from N files"; and a truncated inventory is flagged in the text, the
  HTML report, on stderr and in JSON.
- Column-name hints for people's names and dates of birth no longer fire
  on `product_name`, `file_name`, `birth_place` and the like.
- Each table shows the date range of its files; a documented location
  shows when its suppression expires; the undocumented count is split by
  confidence.
- Concurrent scanning (`--concurrency`) within a memory budget
  (`--memory-budget`, 512 MiB by default, at most 64 GiB), with nearby page
  reads coalesced into one request (`--coalesce-gap`). Output is identical
  at any concurrency. A file that waits more than 10 minutes for memory is
  `content-not-scanned` with reason `budget-timeout`.

### Reports and release

- `--html`: a self-contained, offline HTML report with every name escaped
  and no personal-data values.
- Every report records the scan's settings, and a `--config` file by its
  SHA-256 and entry count, never its path.
- Output files are written to a temporary file and renamed into place only
  when the run completes, so a failed run never leaves a partial report.
- JSON `schema_version` 1 is now **stable**, under an additive-only
  compatibility policy. The last breaking change before the freeze:
  `largest_objects` entries no longer carry `severity`, which was always
  `null`.
- Release binaries for macOS (Apple silicon and Intel) and Linux (x86_64
  and arm64, glibc 2.17 or newer, so Amazon Linux 2023 and Ubuntu 22.04 and
  later), each with a SHA256SUMS entry.
- Licensed under FSL-1.1-ALv2: free to use, modify and run inside your own
  organization; each version becomes Apache-2.0 two years after its
  release.
