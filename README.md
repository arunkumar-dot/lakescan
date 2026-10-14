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
| 6 | `ContentNotScanned` | `--pii` was given and at least one Parquet file was found, but none could be content-scanned (all unreadable, encrypted, refused, not Parquet, or with every readable column skipped). The summary is still written, and stderr gives the reasons. Takes precedence over 1. |

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
| `sensitive-key` | high, medium | High: a key whose name is a secret file on its own (`.env`, `.env.*` except `.example`/`.sample`/`.template`, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.htpasswd`, `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`) or ends in `.tfstate`, `.tfstate.backup`, `.ppk`, `.kdbx`. Medium: a name ending in `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.keystore`, or any key under a `.git/` or `.ssh/` directory. Matching is case-insensitive. | Credentials in a data lake get copied, shared and exposed far more easily than credentials in a secrets manager. |
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
| `content-not-scanned` | `info`: a Parquet file that could not be scanned, with a reason: `not-parquet`, `unreadable`, `access-denied`, `encrypted`, `footer-too-large`, or `no-column-examined` (it has string or integer columns, but every one was skipped, so no value was examined). It never stops the scan. |

## PII content scanning

`--pii` reads the contents of every object whose key ends in `.parquet` or
`.parq` (in any case), one file at a time.

**What is read.** A file of at most `--pii-whole-file-max` bytes (8 MiB by
default) is read whole, in one request. For a larger file, LakeScan reads:

- the footer, with one 64 KiB tail read (plus a second read if the footer is
  longer than that);
- for each candidate column, its dictionary page, if any, and the first data
  page of row group 0. With an offset index, that is one exact range.
  Without one, the range is found by reading page headers.

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
read is a `content-not-scanned` finding with reason `access-denied`. If most
files were refused and none could be scanned, LakeScan exits with code 6 and
names the missing permissions on stderr.

The cost is S3 `GET` requests: one for a small file, and for a large one
about one for the footer plus one or two per sampled column and row group.
On the test fixtures (15 columns), that was 14–16 requests per file. Add
data transfer for the bytes read when you run outside the bucket's AWS
region. The
`CONTENT` section (`content` in JSON) reports `bytes_read` and
`get_requests`, so you can see what a scan cost.

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
written to the `--findings` stream. The summary shows each rule's suppressed
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
- `tool`: name and version
- `scan`: bucket, prefix, start time (RFC 3339, UTC) and elapsed milliseconds
- `verdict`: `worst_severity`, or `null`
- `inventory`: object and byte totals, overall and per storage class
- `findings`: per rule, counts and bytes per severity plus `suppressed`
  `{count, bytes}`. For a content rule, `bytes` is the size of the file the
  finding is in, once per finding.
- `content`: with `--pii`, Parquet files found, scanned whole or partially,
  and not scanned by reason; columns examined and skipped by reason
  (`repeated`, `unsupported_type`, `page_too_large`, `unreadable`,
  `unsupported_codec`); bytes read and `GET` requests. `null` without
  `--pii`.
- `suppressions`: `expired` and `unused` entries
- `samples`: up to 10 example findings per rule. A PII sample also has
  `column`, `confidence` and `evidence` (`values` or `column-name`), plus
  `matched` and `sampled` when the evidence is `values`. A
  `content-not-scanned` sample has `reason`
- `largest_objects`: the 20 largest objects
- `size_histogram`, `age_histogram`
- `distinct_content`: an ETag-based estimate of distinct content, plus
  `duplicates_significant` (whether the duplicates exceed estimator error)

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
- **Sequential.** Files are read one at a time, so a lake of many small files
  takes one round trip per file, or more.
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
pyarrow, polars, DuckDB and Spark. That README lists each fixture's ground
truth and how to regenerate it.

## License

Licensed under the [Functional Source License, Version 1.1, ALv2 Future License](LICENSE)
(FSL-1.1-ALv2).
