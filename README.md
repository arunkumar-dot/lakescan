# LakeScan

LakeScan audits an S3 bucket from its object listing. It pages through
`ListObjectsV2`, checks every object against a small set of rules (secret-looking
keys, deprecated or wasteful storage classes, stale data, empty objects), sets
aside findings you have explicitly accepted, and writes a summary as text or
JSON. It exits with a code your CI can act on.

With `--pii`, it also looks inside Parquet files for personal data (emails,
phone numbers, Indian PAN and Aadhaar numbers, card numbers, IP addresses,
and, by column name, people's names and dates of birth). It reads a small part
of each file, not the whole of it, and reports which columns hold what. It
never reports the values themselves. See
[PII content scanning](#pii-content-scanning).

Where the product is headed, and why, is in [docs/PRODUCT.md](docs/PRODUCT.md).

Memory use does not grow with the bucket. Every stage has a fixed budget: one
listing page in flight, fixed-size summaries, and a streaming writer. Scanning
ten objects or ten billion uses the same memory.

## Install

LakeScan is not published yet. Build it from source with Rust 1.94.1 or newer:

```sh
git clone https://github.com/arunkumar-dot/lakescan.git
cd lakescan
cargo build --release
./target/release/lakescan --version
```

## Quickstart: the local demo

The repository includes a seeder that fills a local S3 fake with a demo bucket.
That bucket has 2,413 objects across three listing pages, a few planted
problems, and some hostile key names. This needs Docker and no AWS account.

```sh
# 1. Start moto, an in-memory S3 fake that accepts any credentials.
#    On macOS, AirPlay Receiver already listens on port 5000, so map 5001.
docker run --rm -d --name lakescan-moto -p 5001:5000 motoserver/moto:5.2.3

# 2. Any credentials work against moto.
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1

# 3. Create and fill the lakescan-demo bucket.
cargo run --example seed_local -- http://localhost:5001

# 4. Scan it.
cargo run --release -- scan s3://lakescan-demo --endpoint-url http://localhost:5001
echo "exit code: $?"    # 1: the bucket has High findings

# 5. Write the same results as a self-contained HTML report, then open
#    report.html in a browser (it loads nothing from the network).
cargo run --release -- scan s3://lakescan-demo --endpoint-url http://localhost:5001 \
  --html report.html --quiet > /dev/null
open report.html        # macOS; xdg-open on Linux, start on Windows

docker stop lakescan-moto
```

On Linux, or with AirPlay Receiver turned off, you can use `-p 5000:5000` and
`http://localhost:5000` instead.

## Usage

```text
lakescan scan <TARGET> [OPTIONS]
lakescan rules
lakescan --help | --version
```

`lakescan rules` prints every rule's code and title, one per line.

`lakescan scan` lists `<TARGET>`, which must be `s3://bucket` or
`s3://bucket/prefix`. An empty prefix (`s3://bucket/`) scans the whole bucket.
AWS credentials and the region come from the standard AWS configuration chain:
environment variables, shared config and credentials files, then
container or instance credentials.

| Flag | Default | Meaning |
|---|---|---|
| `--format text\|json` | `text` | Summary format. |
| `--output <PATH>` | stdout | Write the summary to `PATH`. `-` means stdout. |
| `--findings <PATH>` | off | Also stream every unsuppressed finding to `PATH` as JSON Lines, one record per finding, as it is found. `-` means stdout, which then requires `--output` to name a file. |
| `--fail-on <LEVEL>` | `high` | Exit 1 when the worst unsuppressed finding is at or above `LEVEL`: `info`, `low`, `medium`, `high`, `critical`, or `none` (never fail on findings). |
| `--region <REGION>` | from config | Overrides the configured AWS region. |
| `--endpoint-url <URL>` | AWS | An S3-compatible endpoint (`http://` or `https://`). Implies path-style addressing. |
| `--config <PATH>` | none | A suppression file (see [Suppressions](#suppressions)). Only used when given; never discovered automatically. |
| `--quiet` | off | No progress line and no suppression warnings on stderr. |
| `--pii` | off | Also scan Parquet files (keys ending in `.parquet` or `.parq`, any case) for personal data. Reads object contents; see [PII content scanning](#pii-content-scanning). Without it, no object is read. |
| `--pii-whole-file-max <BYTES>` | `8388608` (8 MiB) | With `--pii`: Parquet files of at most `BYTES` are read whole, in one request. Larger ones are read partially. `0` to `67108864` (64 MiB). Requires `--pii`. |
| `--concurrency <N>` | `16` | With `--pii`: Parquet files scanned at once, `1` to `256`. Output is identical for any value. Requires `--pii`. See [Speed and memory](#speed-and-memory). |
| `--memory-budget <BYTES>` | `268435456` (256 MiB) | With `--pii`: the most bytes in-flight file scans hold at once. Must cover the most one file can need (~103 MiB at the default `--pii-whole-file-max`, ~132 MiB at 64 MiB); less is a usage error. Requires `--pii`. |
| `--coalesce-gap <BYTES>` | `1048576` (1 MiB) | With `--pii`: page ranges of one file at most `BYTES` apart are read as one request (merged reads stay within 8 MiB). `0` reads each range alone. Requires `--pii`. |
| `--html <PATH>` | off | Also write a self-contained [HTML report](#html-report) to `PATH`. `-` means stdout, which then requires every other output to go to a file. Works with or without `--pii`. |
| `--inventory <PATH>` | off | With `--pii`: also write the [PII inventory](#pii-inventory-and-coverage) as CSV to `PATH`, one row per table, column and rule. `-` means stdout, which then requires `--output` to name a file, and `--findings` not to be `-`. Requires `--pii`. |

A progress line (`scanned N objects, M findings`) is shown on stderr only when
stderr is a terminal. Errors print one line to stderr, `lakescan: <error>`.

## Exit codes

The numbers are a stable contract. CI can branch on them.

| Code | Name | Meaning |
|---|---|---|
| 0 | `Ok` | The scan completed and no unsuppressed finding reached `--fail-on`. |
| 1 | `FindingsExceedThreshold` | The scan completed, but an unsuppressed finding reached `--fail-on`. |
| 2 | `Usage` | Bad arguments, an invalid target or config file, a nonexistent bucket, or a region mismatch. |
| 3 | `Auth` | Credentials are missing, expired, or rejected. |
| 4 | `Transport` | The network or S3 failed (DNS, TLS, timeouts, 5xx, an unparseable response). Often worth retrying. |
| 5 | `Report` | The summary or findings stream could not be written (full disk, bad path, permissions). |
| 6 | `ContentNotScanned` | `--pii` was given and at least one Parquet file could not be content-scanned (unreadable, encrypted, refused, a read that kept failing, not Parquet, or with every readable column skipped) without a `content-not-scanned` suppression documenting it. Coverage fails closed: one such file among thousands of readable ones is enough. The summary is still written, and stderr gives the counts by reason. Takes precedence over 1. |

A closed pipe (`lakescan ... | head`) is not an error.

Exit status 101 is outside this contract. It means an internal error: a bug
in LakeScan itself, which panicked. stderr then names the source location
(never the message, which could quote scanned data). Please report it, with
that line and the command you ran. A panic inside the Parquet parser while
reading one file is not this: it is contained, and that file becomes
`content-not-scanned`.

## Rules

Rules see only what a listing reports for each object: key, size,
last-modified time, ETag, and storage class.

| Code | Severities | Flags | Why |
|---|---|---|---|
| `sensitive-key` | high, medium | High: a key whose name is a secret file on its own (`.env`, `.env.*` except `.env.example`, `.env.sample` and `.env.template`, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.htpasswd`, `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`), ends in `.tfstate`, `.tfstate.backup`, `.ppk`, `.kdbx`, or is `.aws/credentials` (a file named `credentials` directly inside a `.aws` directory, at any depth). Medium: a name ending in `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.keystore`, or any key with a `.git` or `.ssh` path segment (anything under a `.git/` or `.ssh/` directory). Matching is case-insensitive. | Credentials in a data lake get copied, shared and exposed far more easily than credentials in a secrets manager. |
| `reduced-redundancy` | medium | Objects in `REDUCED_REDUNDANCY`. | The class is deprecated: it gives up durability and is no longer cheaper than `STANDARD`. |
| `stale-standard` | low, medium | `STANDARD` objects unmodified for more than 90 days. Low at 128 KiB or more, medium at 1 GiB or more. Smaller objects are never flagged. | They are candidates for a cheaper class or a lifecycle rule. Below 128 KiB, IA classes bill a minimum size and Intelligent-Tiering won't tier the object, so moving it would cost more. |
| `small-object-cold-tier` | low | Objects under 128 KiB in `STANDARD_IA`, `ONEZONE_IA`, `GLACIER_IR`, `GLACIER` or `DEEP_ARCHIVE`. | These classes bill a minimum object size (and Glacier adds per-object overhead), so small objects cost more there than in `STANDARD`. |
| `zero-byte-object` | info | Empty objects whose key does not end in `/`. | These are usually failed uploads or leftover scaffolding. Empty `folder/` markers are what consoles create, and they are not flagged. |
| `unknown-storage-class` | info | A storage class this build of LakeScan does not recognize. | This is a newer class than this build knows about. The other rules cannot judge such an object, so LakeScan says so instead of guessing. |

No v1 rule raises `critical`: a listing alone cannot prove an object is
exposed.

With `--pii`, these content rules also apply to Parquet files. Each finding
names one column, and its severity follows from its confidence (see
[Confidence and severity](#confidence-and-severity)):

| Code | Flags |
|---|---|
| `pii-email` | A column of email addresses. |
| `pii-phone` | A column of phone numbers: E.164 (`+14155550123`), or Indian mobile numbers with an optional `+91`, `91` or `0`. Spaces, dashes, dots and parentheses are ignored. |
| `pii-in-pan` | A column of Indian PAN numbers (`ABCPE1234F`, in either case). |
| `pii-in-aadhaar` | A column of Aadhaar numbers: 12 digits, the first 2–9, with a valid Verhoeff check digit. |
| `pii-card-number` | A column of payment card numbers: 13 to 19 digits with a valid Luhn check digit. |
| `pii-ip-address` | A column of IPv4 or IPv6 addresses. |
| `pii-person-name` | A column whose name says it holds people's names (`full_name`, `lastName`, …). Detected by name only. |
| `pii-date-of-birth` | A column whose name says it holds dates of birth (`dob`, `birth_date`, …). Detected by name only. |
| `content-not-scanned` | `info`: a Parquet file that could not be scanned, with a reason: `not-parquet`, `unreadable`, `access-denied`, `encrypted`, `footer-too-large`, `no-column-examined` (it has string or integer columns, but every one was skipped, so no value was examined), `fetch-failed` (a `GetObject` still failed after the SDK's retries: throttling, timeouts, 5xx, an object deleted mid-scan), or `too-many-columns` (the schema has more than 16,384 leaf columns). It never stops the scan, but unless suppressed it fails the run with exit code 6 (see [Coverage](#coverage-fails-closed)). |

## PII content scanning

`--pii` reads the contents of every object whose key ends in `.parquet` or
`.parq` (in any case), up to `--concurrency` files at once (see [Speed and
memory](#speed-and-memory)).

**What is read.** A file of at most `--pii-whole-file-max` bytes (8 MiB by
default) is read whole, in one request. For a larger file, LakeScan reads:

- the footer, with one 64 KiB tail read (plus a second read if the footer is
  longer than that), and the offset indexes, if the writer wrote them: free
  when they are in the tail, else one read for all of them;
- for each candidate column, its dictionary page, if any, and the first data
  page of row group 0. With an offset index, that is one exact range.
  Without one, the range is found by reading page headers. A row group's
  ranges are coalesced (see [Speed and memory](#speed-and-memory)).

A column whose sample is too small or too ambiguous after row group 0 is
sampled again in the middle row group, then the last: never more than 3 row
groups per column. This catches junk or nulls clustered at the start of a
file. Candidate columns are string, binary, INT32 and INT64 columns, plus
DATE and TIMESTAMP columns for the date-of-birth name check. Struct fields
count; repeated (list and map) columns are skipped and counted. At most
2,000 values per column per row group are evaluated.

A candidate column is skipped, and counted by reason, when its first pages
are over the page cap (`page-too-large`), can't be decoded (`unreadable`),
or use a codec LakeScan doesn't decode (`unsupported-codec`: LZO). Every
other codec is read: uncompressed, Snappy, GZIP, LZ4, LZ4_RAW, ZSTD and
BROTLI. A file whose string and integer columns were *all* skipped is not
counted as scanned: it is `content-not-scanned` with reason
`no-column-examined`, so a lake LakeScan couldn't actually read can't pass
silently. Findings that rest on a column's name alone, such as a date of
birth, are still reported for such a file. A file with no string or integer
columns at all (only doubles, say) has nothing to examine and counts as
scanned.

Each file's `PAR1` magic bytes are checked first. A file without them is not
Parquet and is skipped (`content-not-scanned`, `not-parquet`), not an error.

**Cleaning.** Before anything is counted, values are trimmed. Nulls, empty
strings, values made of one repeated character (`0000000000`, `----`) and
the placeholders `n/a`, `na`, `null`, `none`, `nil`, `unknown`, `undefined`,
`unk`, `tbd`, `test`, `sample`, `dummy`, `-`, `?` and `.` (in any case) are
dropped. So is a value that makes up more than half of a column's sample,
such as a default address, unless it is the column's only value.

### Confidence and severity

| Confidence | When | Severity |
|---|---|---|
| `confirmed` | At least 80% of at least 30 cleaned values match. | `high` |
| `likely` | 50–80% of at least 30 cleaned values match; or at least 80% match but there are fewer than 30; or the column's name suggests the type and at least one value matches; or, for names and dates of birth, a clear name hint on a column of fitting type. | `medium` |
| `possible` | The column's name suggests the type, but there is no value evidence. | `info` |

Each finding says what it rests on: `evidence=values matched=X/Y` (in
JSON, `"evidence": "values"` with `matched` and `sampled`) when sampled values
validated, or `evidence=column-name` (`"evidence": "column-name"`, no counts)
when only the column's name and type support it. Names and dates of birth are
always `column-name`.

Values override names. A column with at least 30 cleaned values, none of
which match, is never reported for that type, whatever it is called. So a
column of hashes named `email_sha256` is not an email finding. A `pan` column
name is only an Indian PAN finding if a value matches, so a card's "primary
account number" column isn't mistaken for a tax ID. When values match more
than one type, the most confident wins, then the stricter validator
(checksums before patterns). Each column gets at most one finding.

With the default `--fail-on high`, a confirmed PII column fails the run
(exit code 1).

### Hostile files

Anyone who can upload to a scanned bucket chooses the bytes of every Parquet
file in it, so LakeScan treats every file as hostile. One crafted file must
never crash the scan or exhaust memory:

- **Every page header is checked before any allocation for the page.** That
  covers dictionary and data pages, on both the whole-file and partial
  paths. A page declaring more than 8 MiB compressed or uncompressed, or a
  dictionary declaring more than 1,048,576 values, skips its column as
  `page-too-large`. Nothing is allocated for it.
- **Decompression stops at the declared size.** Snappy, ZSTD, LZ4 and
  LZ4_RAW pages are decompressed by the Parquet parser into a buffer of the
  declared size (LZ4's unbounded frame fallback is off). The parser's GZIP
  and BROTLI decoders would write as much as the stream produces, so
  LakeScan decompresses those pages itself. It reads at most the declared
  size plus one byte, and a page whose output doesn't exactly match its
  declared size is `unreadable`, however much more the stream holds. Brotli
  streams asking for a window over 16 MiB ("large window" Brotli) are
  refused before decoding, because the decoder would allocate the whole
  window up front.
- **LakeScan's own page-header reader is fuzzed.** A test feeds it 100,000
  random and mutated headers and checks it always returns a result or an
  error, without panicking.
- **A parser panic costs one file.** The Parquet parser is third-party code,
  so a panic inside it becomes `content-not-scanned` (reason `unreadable`)
  for that file, and the scan continues. Its message is never printed,
  because it could quote file contents.

### No values in the output

LakeScan never writes a sampled value anywhere: not in the text or JSON
summary, the `--findings` stream, warnings, or error messages. A finding
carries the file, the column path (at most 256 bytes), the confidence, and
two counts, `matched` and `sampled`. A test seeds known values into Parquet
files and checks that none appears in any output.

### Permissions and cost

Content scanning needs `s3:GetObject` on the objects it reads. For objects
encrypted with SSE-KMS it also needs `kms:Decrypt` on their key. A refused
read is a `content-not-scanned` finding with reason `access-denied`, and
fails the run with exit code 6 unless documented (see
[Coverage](#coverage-fails-closed)). If most undocumented files were
refused, stderr also names the missing permissions.

The cost is S3 `GET` requests: one for a small file, and for a large one
one for the footer, one for the offset indexes if they aren't in it, and
one or two per sampled column and row group, fewer when coalescing merges
them (see below). Add data transfer for the bytes read when you run
outside the bucket's AWS region. The `CONTENT` section (`content` in JSON)
reports `bytes_read` and `get_requests`, so you can see what a scan cost.

### Speed and memory

Content scanning runs up to `--concurrency` files at once (16 by
default). Results are applied in listing order, so the summary, the
findings stream and the inventory are identical for any `--concurrency`.
Decoding runs on a separate thread pool, so it doesn't stall reads.
`GetObject` uses the SDK's adaptive retry mode, which slows down when S3
throttles (503 `SlowDown`); a read that still fails becomes
`content-not-scanned` with reason `fetch-failed`, which fails the run (exit
code 6) unless documented.

**Memory is bounded by `--memory-budget`** (256 MiB by default). Every read
and every decode takes permits for its bytes (the bytes fetched, or the
page sizes a header declares) before it starts, and gives them back when
its buffers are freed. One file never needs more than ~103 MiB under
LakeScan's caps (~132 MiB with `--pii-whole-file-max 64MiB`), and a budget
below that is a usage error, since that file could never start. Files
share the budget so that none can wait forever: each in-flight file may
hold an equal share freely, and one file at a time may go beyond it. On
top of the budget, each in-flight file holds a few kilobytes of state and
up to ~0.8 MiB of page locations. A bigger budget lets more files run at
full speed at high `--concurrency`: with 256 MiB, going past 16 adds
little for typical files.

**Coalescing trades bytes for requests.** Within a partially read file,
each round's page reads (the first pages of every column in row group 0,
then of the columns that need more) are sorted and merged when they are at
most `--coalesce-gap` apart (1 MiB by default; merged reads stay within 8
MiB), and up to 4 are fetched at once. The bytes between merged ranges are
read too. That pays off for files with small row groups, and does little
for files with a few large ones. S3 bills per request, and egress per byte
outside its region: where egress costs more than requests and time, set
`--coalesce-gap 0`. Simulated measurements, and their limits, are in
[docs/experiments/scan-speed.md](docs/experiments/scan-speed.md).

### PII inventory and coverage

With `--pii`, the summary ends its content sections with COVERAGE and PII
INVENTORY: where personal data lives, by table and column, and whether each
location is documented. It is the report a privacy team hands to an
auditor, a customer or a regulator.

```text
COVERAGE
  parquet files:  11
  scanned:        8 (72.7%)
  not scanned:    2 documented, 1 undocumented

PII INVENTORY
  4 tables with PII, 31 PII columns: 30 undocumented (action needed), 1 documented. 2 tables not fully scanned.
  bad  files: 0 scanned, 2 not scanned (not-parquet=1 documented, unreadable=1 documented)
    not scanned: PII unknown
  lake/customers  files: 4 scanned, 0 not scanned
    example: lake/customers/dt=2026-01-01/part-0.parquet
    aadhaar_no  pii-in-aadhaar  confirmed  evidence=values  4 files confirmed  UNDOCUMENTED
    full_name  pii-person-name  likely  evidence=column-name  4 files likely  UNDOCUMENTED
    pan  pii-in-pan  confirmed  evidence=values  4 files confirmed  UNDOCUMENTED
    email  pii-email  confirmed  evidence=values  4 files, documented: Consented marketing contacts, DPA-12
```

(Trimmed: the real output lists every table and row.)

The headline counts the action items: undocumented PII locations, and
tables with files that weren't scanned. A table never claims more than was
read: one with no file scanned says `not scanned: PII unknown`, and one
where nothing was found says `no PII found in N scanned files`, adding
`; M not scanned` when some weren't (JSON: each table's `status`,
`pii_found`, `no_pii_in_scanned_files` or `not_scanned`, and
`pii_inventory.summary` for the headline).

**Tables.** A listing knows nothing about catalogs, so each Parquet file is
put in a table by its key, a heuristic: take the directory (everything up
to the last `/`), drop trailing Hive-style partition segments
(`name=value`, such as `dt=2026-01-01` and `region=in`), then drop one
trailing `data` segment (Iceberg keeps data files under `<table>/data/`).
So `lake/customers/dt=2026-01-01/region=in/part-0.parquet`,
`lake/customers/data/part-0.parquet` and a Delta table's
`lake/customers/part-0.parquet` are all table `lake/customers`. Files at the
bucket root are table `(bucket root)` (`""` in JSON and CSV). A directory
named `data` that isn't Iceberg's is folded into its parent all the same.

**Entries.** Each table lists one line per column and PII rule,
undocumented ones first, then documented, each by column: the highest
confidence any file reached, what the findings rest on (`values` if any
file's did), and a status. An `UNDOCUMENTED` line gives its non-zero file
counts (`3 files confirmed, 1 likely`; suppressed files too, if only some
were); it is undocumented if any file's finding was not suppressed. A
documented line gives all its files and the reason of the first `--config`
entry (in file order) that suppressed them: `4 files, documented: <reason>`.
JSON and CSV keep every count. Each table
also gives its files scanned and not scanned, the unscanned ones by reason,
documented or not, and an example key: the smallest key in the table with a
PII finding. No sampled value appears, in any format.

**Documenting a location.** To record that a column is meant to hold
personal data, suppress its rule for that column under the table's prefix,
with the reason (see [Suppressions](#suppressions)):

```toml
[[suppress]]
rule = "pii-email"
prefix = "lake/customers/"
column = "email"
reason = "Consented marketing contacts, DPA-12"
expires = 2027-06-30
```

The finding then stops counting toward the verdict and the findings stream,
but stays in the inventory, as documented, with that reason.

**CSV export.** `--inventory <PATH>` writes the same inventory as CSV, one
row per table, column and rule, under a header row: `table`, `column`,
`rule`, `highest_confidence`, `evidence`, `files_confirmed`,
`files_likely`, `files_possible`, `files_suppressed`, `status`
(`UNDOCUMENTED` or `documented`), `reason`, and `example_key` (the table's).
It follows RFC 4180 (CRLF line ends; a field with a comma or quote is
quoted, with quotes doubled). The CSV is a human-facing report, and table
names, column paths, keys and reasons are attacker-controlled, so it is
escaped like the text summary: control characters (ESC, newline, tab...)
and the bidi controls U+202A-U+202E and U+2066-U+2069 are written as
`\u{XXXX}`, so `--inventory -` can't drive your terminal and a name can't
display as a different one. Then a cell that starts with `=`, `+`, `-` or
`@` is prefixed with `'`, which stops spreadsheets from running it as a
formula. Read such a cell without its leading `'`. The JSON summary and the
`--findings` stream are the exact-data channels: they carry every name
byte for byte (JSON-escaped).

**Caps.** At most 4,096 tables and 16,384 entries (table, column, rule) are
kept, so the inventory's memory stays bounded (~16.5 MiB at the caps). Over
a cap, the lexicographically smallest tables and entries are kept, the
same whatever order files arrive in, with every kept count exact. What is
left out is counted (files and findings) and reported in a `truncated:`
line, `left_out` in JSON. Scan a narrower prefix to see the rest.

### HTML report

`--html report.html` writes the same results as one file to open in a
browser, print, or send: the scan's target, version, timing and exit code
with its meaning; an **Action needed** banner listing what to do
(undocumented PII columns, undocumented unscanned files, findings at the
failing threshold), or **No action needed**; headline cards; the PII
inventory by table, ordered as in the text summary, with status badges and
documented reasons, and filters (All, Undocumented, Documented); the files
not scanned, by table and reason; and the metadata findings per rule.
Without `--pii` it has the metadata sections only.

- **Offline.** All CSS and JavaScript are inline, fonts are the system's,
  and a Content-Security-Policy (`default-src 'none'`) stops the page from
  loading anything: opening it makes no network request.
- **No values.** Like every other output, it holds no sampled personal
  data: keys, table and column names, counts, and your documented reasons.
- **Escaped names.** Keys, table and column names and reasons are
  attacker-controlled. Each is escaped like the text summary (control and
  bidi characters as `\u{XXXX}`, backslashes doubled), then HTML-escaped,
  so a name like `<script>…</script>` shows as text. The small script reads
  its data from a JSON block in which `<` is written `\u003c`, and only sets
  text, never HTML.
- **Works without JavaScript**: every row is shown and the filters are
  hidden. Printing shows every row, without the filters.
- **Deterministic**: the same for any `--concurrency`, apart from its start
  time and duration.

### Coverage fails closed

COVERAGE counts the eligible Parquet files, those scanned (with the
percentage, rounded down, so it never reads 100% unless every file was
scanned), and those not scanned, split into **documented** (their
`content-not-scanned` finding was suppressed) and **undocumented**.

Any undocumented file fails the run with exit code 6, even among thousands
of readable ones, and even when exit 1 would otherwise apply: an inventory
is only evidence if the files it skipped are accounted for. stderr says how
many, by reason. To accept a file that can't be scanned (a known-corrupt
export, a blob table with no personal data), document it:

```toml
[[suppress]]
rule = "content-not-scanned"
prefix = "lake/raw_blobs/"
reason = "Binary payloads, no personal data; reviewed 2026-10-01"
expires = 2027-04-01
```

## Suppressions

Some findings are expected, such as a public example key in your docs or a
scratch prefix full of placeholders. List them in a TOML file and pass it with
`--config`:

```toml
version = 1

# One exact key, for one bucket, until a date.
[[suppress]]
rule = "sensitive-key"
key = "docs/examples/id_rsa"
reason = "Public example key used in our docs"
expires = 2027-01-31       # quoted "2027-01-31" works too
bucket = "my-bucket"       # only applies when scanning my-bucket

# Everything under a prefix.
[[suppress]]
rule = "zero-byte-object"
prefix = "tmp/"
reason = "Scratch space for the nightly job"

# An empty prefix suppresses a rule for the whole bucket.
[[suppress]]
rule = "stale-standard"
prefix = ""
reason = "Archive bucket: everything here is stale by design"

# One column of every Parquet file under a prefix.
[[suppress]]
rule = "pii-email"
prefix = "crm/contacts/"
column = "billing.email"
reason = "Consented billing contacts, covered by our DPA"
```

Each `[[suppress]]` entry has:

| Field | Required | Meaning |
|---|---|---|
| `rule` | yes | A rule code from the table above. |
| `key` / `prefix` | exactly one | `key` matches one key exactly. `prefix` matches every key that starts with it, and `""` matches all keys. |
| `reason` | yes | Why the finding is acceptable. Must not be blank. |
| `expires` | no | The last day (UTC) the entry applies. The day after, it stops suppressing and is reported as expired. |
| `bucket` | no | The entry applies only when scanning this bucket. For any other bucket it is ignored completely, and never reported as unused or expired. |
| `column` | no | The entry applies only to findings on this exact column path, such as `billing.email` (PII findings). Listing findings never match it. At most 256 bytes. |

When several entries match a finding, the first one in the file wins.

A suppressed finding still counts, but only as suppressed. It does not appear
in the findings matrix, does not affect the verdict or exit code, and is not
written to the `--findings` stream. A suppressed PII finding stays in the
[PII inventory](#pii-inventory-and-coverage), marked documented with the
entry's reason, and a suppressed `content-not-scanned` finding no longer
fails the run with exit code 6: suppressions are how PII locations and
unscannable files are documented. The summary shows each rule's suppressed
count. Its SUPPRESSIONS section (and `suppressions` in JSON) lists entries that
have **expired** and active entries that were **unused**, meaning they
suppressed nothing in this scan. Unless `--quiet` is given, each of those also
gets a one-line warning on stderr.

LakeScan refuses to start (exit code 2) on a config file it cannot fully
understand. The error message names the file and the offending entry. That
covers:

- `version` other than 1
- an unknown field (a typo like `reson` fails rather than being ignored)
- an unknown rule
- a blank reason
- both or neither of `key`/`prefix`
- a malformed date
- more than 10,000 entries
- a key or prefix over 1 KiB, a reason over 1 KiB, a bucket name over 63 bytes,
  or a column that is empty or over 256 bytes
- a missing or unreadable file

## JSON output

`--format json` writes one JSON object. The full schema is documented in
[`src/report/mod.rs`](src/report/mod.rs). Its top-level fields:

- `schema_version`: currently `1`
- `tool`: `name` and `version`
- `scan`: `bucket`, `prefix` (or `null`), `started_at` (RFC 3339, UTC) and
  `elapsed_ms`
- `verdict`: `worst_severity`, or `null`
- `inventory`: `object_count` and `total_bytes`; `by_storage_class`, one
  entry per known class with objects, with `storage_class`, `count` and
  `bytes`; `unrecognized_storage_classes` (their names, at most the 8
  smallest) and `unrecognized_storage_class_totals` (`count` and `bytes`
  of every such object)
- `findings`: per rule, its `rule` code and `title`; `counts` and `bytes`,
  each keyed by severity (`critical`, `high`, `medium`, `low`, `info`);
  and `suppressed` `{count, bytes}`. For `content-not-scanned`, `bytes` is
  the size of the file. For PII rules, both byte totals are always `0`, as
  not applicable: their findings are about columns, and a file's size
  would be counted once per column. The text summary shows `-` for them.
- `content`: with `--pii`, Parquet files found (`files_eligible`),
  `scanned_whole`, `scanned_partially`, and `not_scanned` by reason (every
  reason code, `0` when none); `columns_examined`, and `columns_skipped` by
  reason (`repeated`, `unsupported_type`, `page_too_large`, `unreadable`,
  `unsupported_codec`); `bytes_read` and `get_requests`. `null` without
  `--pii`.
- `coverage`: with `--pii`, `files_eligible`, `files_scanned`,
  `not_scanned_suppressed`, `not_scanned_unsuppressed`, and `percent`
  (rounded down to one decimal; `null` with no eligible file). `null`
  without `--pii`.
- `pii_inventory`: with `--pii`, `tables` (sorted by name), each with
  `table`, `status` (`pii_found`, `no_pii_in_scanned_files` or
  `not_scanned`), `files_eligible`, `files_scanned`, `files_not_scanned`,
  `not_scanned` (per reason with any, its `suppressed` and `unsuppressed`
  file counts),
  `example_key` (or `null`) and `columns` (sorted by column, then rule), each
  with `column`, `rule`, `highest_confidence`, `evidence`,
  `files_confirmed`, `files_likely`, `files_possible`, `files_suppressed`,
  `status` (`UNDOCUMENTED` or `documented`) and `reason` (or `null`); plus
  `summary` (`tables_with_pii`, `pii_columns`, `undocumented`, `documented`,
  `tables_not_fully_scanned`, and `tables_not_fully_scanned_documented`:
  of those, the tables whose every unscanned file is documented),
  `left_out` (`files`, `findings`) and `caps` (`tables`, `entries`). `null`
  without `--pii`.
- `suppressions`: `expired` and `unused` entries, each with `rule`, `key`
  or `prefix`, `reason`, `expires` (`YYYY-MM-DD`, or `null`), and `column`
  when the entry has one
- `samples`: up to 10 example findings per rule, keyed by rule code. Each
  has `key`, `key_truncated`, `severity`, `size`, `storage_class` and
  `last_modified`. A PII sample also has `column`, `confidence` and
  `evidence` (`values` or `column-name`), plus `matched` and `sampled` when
  the evidence is `values`. A `content-not-scanned` sample has `reason`
- `largest_objects`: the 20 largest objects, shaped like a sample, with
  `severity` always `null`
- `size_histogram`: non-empty buckets, ascending, each with `lower` and
  `upper` bounds in bytes (`upper` is `null` for the open-ended top
  bucket), `count` and `bytes`; `age_histogram` likewise, with its bounds
  as `lower_seconds` and `upper_seconds`
- `distinct_content`: an ETag-based `estimate` of distinct content, a
  `duplicate_lower_bound`, and `duplicates_significant` (whether the
  duplicates exceed estimator error)

`--findings` writes one JSON object per line:
`{"key", "rule", "severity", "size", "storage_class", "last_modified"}`, plus
`column`, `confidence`, `evidence` (and `matched` and `sampled` for value
evidence) on a PII finding, and `reason` on a `content-not-scanned` one. Keys are written in full and JSON-escaped, so
any key round-trips exactly.

**Compatibility policy.** `schema_version` stays the same as long as changes are
additive: new fields, new sections, new list entries. Consumers should ignore
fields they don't recognize. Removing or renaming a field, changing its type, or
changing what it means bumps `schema_version`.

## Limitations

- **Listing data, plus Parquet contents with `--pii`.** LakeScan never reads
  bucket policies, ACLs, Block Public Access settings, or encryption
  configuration. It cannot tell you whether an object is public or
  encrypted. Without `--pii` it never reads object contents either.
- **Content scanning covers Parquet only.** CSV, JSON, Avro and ORC files are
  not read.
- **Structured columns only.** Personal data embedded in free text (an email
  in a notes column) is not detected. Neither are names or dates of birth
  under a column name that doesn't say so.
- **Repeated columns are skipped.** List and map columns are counted but not
  read.
- **It samples rather than reads everything.** A column is judged from the
  first data page of up to three row groups (at most 2,000 values each). A
  column whose personal data appears only in other pages can be missed.
- **One listing stream.** Listing is sequential (one `ListObjectsV2` page
  at a time), so for very large buckets, and for scans without `--pii`, it
  becomes the bottleneck. Scan big buckets by prefix, in parallel runs.
- **Speed is measured on a simulated S3 only.** See
  [docs/experiments/scan-speed.md](docs/experiments/scan-speed.md).
- **Tables are guessed from keys.** The inventory groups files by directory,
  minus Hive partitions and an Iceberg `data/` directory. It does not read
  Glue, Hive, Iceberg or Delta metadata, so a table laid out differently is
  split or merged.
- **Inventory caps.** Past 4,096 tables or 16,384 table/column/rule entries,
  the largest names are left out and counted. Scan by prefix for bigger
  lakes.
- **Encryption.** Files using Parquet modular encryption with an encrypted
  footer are reported as `encrypted`. Files that encrypt only some columns,
  with a plaintext footer, are reported as `unreadable` or have those
  columns skipped. S3 server-side encryption is transparent, given
  `kms:Decrypt`.
- **Page caps.** A page whose header declares over 8 MiB, compressed or
  decompressed, skips that column (see [Hostile files](#hostile-files)).
- **LZO columns are not read.** They're skipped as `unsupported-codec`.
- **`stale-standard` measures last modification, not last access.** A listing
  has no access time, so an object read every day but written two years ago
  is still flagged as stale.
- **Duplicate detection is a lower bound.** Duplicates are estimated from
  `(ETag, size)` pairs with a HyperLogLog sketch (about 1% error). The same
  content uploaded with a different multipart chunking, or encrypted with
  SSE-KMS or SSE-C, gets a different ETag and is not detected. Differences
  under about 2% of the object count are within the estimator's error and are
  reported as "no duplicates detected".
- **Keys are matched as listed.** Suppression keys and prefixes are compared
  byte for byte with the decoded S3 key. No glob or case folding is applied.

## Development

The five gates CI runs, in order:

```sh
cargo fmt --all -- --check                                   # 1. formatting
cargo clippy --all-targets --all-features -- -D warnings     # 2. lints
cargo check --all-targets --all-features                     # 3. check
cargo test --all-features                                    # 4. tests
cargo build --release && ./target/release/lakescan --version # 5. release build + smoke
```

The minimum supported Rust version is **1.94.1**, which CI also checks.
`rust-toolchain.toml` pins stable, so name the toolchain explicitly:

```sh
rustup toolchain install 1.94.1
cargo +1.94.1 check --all-targets
```

The end-to-end tests run the built binary against a seeded moto server. They
are `#[ignore]`d by default:

```sh
docker run --rm -d --name lakescan-moto -p 5001:5000 motoserver/moto:5.2.3
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1
export LAKESCAN_E2E_ENDPOINT=http://localhost:5001
cargo run --example seed_local -- "$LAKESCAN_E2E_ENDPOINT"
cargo test --test e2e --test e2e_pii -- --ignored
docker stop lakescan-moto
```

The seeder fills two buckets: `lakescan-demo` for the listing rules, and
`lakescan-pii` with the Parquet fixtures in
[`tests/fixtures/parquet`](tests/fixtures/parquet/README.md), written by
pyarrow, polars, DuckDB and Spark, uploaded under partitioned keys (Hive
`dt=`/`region=` and Iceberg `data/`) so the inventory has tables to group.
That README lists each fixture's ground truth and how to regenerate it.

## License

LakeScan is source-available under the Functional Source License, Version 1.1,
ALv2 Future License (FSL-1.1-ALv2). In plain words:

- You are free to use, modify and run LakeScan inside your own organization.
- You may not offer it, or something built from it, as a competing commercial
  product or service.
- Each version becomes available under the Apache License, Version 2.0, two
  years after its release.

The full terms are in [LICENSE](LICENSE).
