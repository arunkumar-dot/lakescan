# LakeScan, hands on

This tutorial runs LakeScan against a local fake of S3 and explains
everything it prints. You need Docker and a Rust toolchain, and no AWS
account. Start the guided demo from the repository root:

```sh
scripts/demo.sh            # pauses before each step; press Enter to go on
scripts/demo.sh --no-pause # runs straight through
```

Every output below is real. It was captured from `scripts/demo.sh --no-pause`
on 2026-10-16 (plus a few extra runs, marked as such) and trimmed where
marked with `...`. Timestamps and `elapsed` times will differ on your
machine. Everything else should match.

## What LakeScan does

LakeScan looks through an Amazon S3 bucket and tells you what is risky or
wasteful in it. From the bucket's listing alone (names, sizes, dates,
storage classes) it spots things like secret keys left in the lake and
data in deprecated or overpriced storage. With `--pii` it also opens
Parquet files, the format most data lakes store tables in, and reports
which columns hold personal data: emails, phone numbers, Indian PAN and
Aadhaar numbers, card numbers, IP addresses, names and dates of birth. It
reads only a small part of each large file, so it costs far less than
Amazon Macie. It never copies or prints the personal data it finds. It
reports which file, which column, how sure it is, and how many values it
checked. The output is a per-table inventory of personal data that you
can hand to an auditor, plus exit codes your CI can act on.

## The pipeline

Every run is one pass through six stages. Each stage has a fixed memory
budget, so scanning ten objects or ten billion uses the same memory. The
diagram at the top of [`src/lib.rs`](../src/lib.rs) shows them together.
[`src/cli/driver.rs`](../src/cli/driver.rs) wires them up for one run.

**Scanner** ([`src/scanner/`](../src/scanner/)). Pages through
`ListObjectsV2` one page (up to 1,000 keys) at a time and turns every entry
into an `ObjectMeta`: key, size, last-modified time, ETag, storage class.
It decides what exists, never whether anything is wrong with it. Only one
page is in memory at once.

**Metadata rules** ([`src/rules/`](../src/rules/)). Six stateless rules,
one file each, look at one `ObjectMeta` at a time and raise `Finding`s:
`sensitive-key`, `reduced-redundancy`, `stale-standard`,
`small-object-cold-tier`, `zero-byte-object`, `unknown-storage-class`. A
rule never looks across objects and never touches the network.

**PII content scanner** ([`src/content/`](../src/content/)). Only with
`--pii`. Keys ending in `.parquet` or `.parq` are eligible, and so are
extensionless objects (and objects whose extension is not a known
non-Parquet format) after one 8-byte sniff for the `PAR1` magic. It
downloads a small file whole in one request, or reads a large file's footer
and the first pages of each candidate column, and samples either way. It then cleans the sampled values
(`clean.rs`), validates them (`detect.rs`), checks column names
(`names.rs`) and decides a confidence per column (`classify.rs`). Up to
`--concurrency` files are scanned at once, under one `--memory-budget`
(`budget.rs`). A file it cannot read becomes a `content-not-scanned`
finding, not an error.

**Suppressions** ([`src/suppress/`](../src/suppress/)). Reads the optional
`--config` TOML file and checks every finding against its entries. A
matching finding is suppressed, which means *documented*: it no longer
counts toward the exit code or the findings stream, but it is counted and
stays in the PII inventory with its reason.

**Aggregate** ([`src/aggregate/`](../src/aggregate/)). Folds findings and
objects into bounded summaries: totals per storage class, the findings
matrix, samples, the largest objects, histograms, a HyperLogLog
distinct-content estimate, content-scan counters, and the PII inventory
(`pii.rs`), which groups files into tables by their keys. Only this stage
keeps state across objects, and each of its summaries has a compile-time
size limit.

**Report** ([`src/report/`](../src/report/)). Writes what the aggregates
hold, without recomputing anything: the text or JSON summary (`text.rs`,
`json.rs`), the live JSON Lines findings stream (`findings.rs`), the
inventory CSV (`csv.rs`) and the HTML report (`html.rs`). Every key and
column name is attacker-controlled, so it is escaped first (`escape.rs`).

## The life of one file

Follow `lake/customers/dt=2026-01-01/part-0.parquet` from the
`lakescan-pii` bucket. It is the pyarrow fixture
`tests/fixtures/parquet/pyarrow/customers.parquet`: 12,000 synthetic
customers in 3 row groups. Its ground truth is in
[`tests/fixtures/parquet/README.md`](../tests/fixtures/parquet/README.md).

**1. Listed.** The scanner sees one entry in a listing page and makes an
`ObjectMeta` of it. In step d's summary it shows up among the largest
objects:

```text
LARGEST OBJECTS
  lake/customers/dt=2026-01-01/part-0.parquet  size=1909661 (1.8 MiB) class=STANDARD modified=2026-10-16T05:01:48Z
```

**2. Metadata rules.** Nothing fires. The key isn't secret-looking, the
object is `STANDARD`, it is not empty, and it is younger than 90 days.

**3. Read.** The key ends in `.parquet` and `--pii` is on, so the content
scanner takes it. At 1,909,661 bytes it is under the 8 MiB
`--pii-whole-file-max`, so it is downloaded whole, in one `GET`. An extra run,
scoped to this file's prefix, shows that:

```text
$ lakescan scan s3://lakescan-pii/lake/customers/dt=2026-01-01/ --endpoint-url http://localhost:5001 --pii --quiet
...
CONTENT
  parquet files:      1
    downloaded whole:  1
    read partially:    0
    not scanned:       0
  columns examined:   16
  columns skipped:    1 (repeated=0, unsupported-type=1, page-too-large=0, unreadable=0, unsupported-codec=0)
  bytes read:         1914681 (1.8 MiB)
  GET requests:       1
  sniffed:            0 (objects without a Parquet extension; one 8-byte GET each)
```

The file has 17 leaf columns (the struct `billing` holds two: `email` and
`city`). `tags` is a list of strings: its elements are read like any other
column (`tags.list.element`). `amount` is a double, so it is skipped as
`unsupported-type`; its name hints nothing personal, so it is not a column
*not examined*. The other 16 are examined.

The real lake's big files take the partial path. To see it on this
small file, set `--pii-whole-file-max 0` (another extra run). LakeScan
then reads the 64 KiB tail for the footer, then the dictionary and first
data page of each candidate column, coalescing nearby ranges into fewer
requests:

```text
$ lakescan scan s3://lakescan-pii/lake/customers/dt=2026-01-01/ --endpoint-url http://localhost:5001 --pii --quiet --pii-whole-file-max 0
...
    read partially:    1
...
  bytes read:         974316 (951.4 KiB)
  GET requests:       4
  sniffed:            0 (objects without a Parquet extension; one 8-byte GET each)
```

With `--coalesce-gap 0` as well, it reads each range on its own: `bytes
read: 685930 (669.8 KiB)` in `GET requests: 15`. Fewer bytes, more
requests. Both partial runs produce exactly the same findings as the whole
read. On this file a partial read takes about half the bytes. On large
lake files, where row groups are big, it is under 10%.

**4. Clean, detect, classify.** For the `email` column, LakeScan decodes
values from row group 0, drops nulls, blanks, placeholders like `N/A` and
`-`, and repeated-character junk, and keeps up to 2,000 cleaned values. It
got the full 2,000 here. 1,943 of them are valid emails. The other 57 are
the fixture's planted malformed values and placeholders that aren't on
LakeScan's list (`NOT PROVIDED`, `999`). 1,943 of 2,000 is at least 80% of
at least 30 values, so the confidence is **confirmed**, which is severity
**high**. Its finding, from step g's stream:

```json
{"key":"lake/customers/dt=2026-01-01/part-0.parquet","rule":"pii-email","severity":"high","size":1909661,"storage_class":"STANDARD","last_modified":"2026-10-16T05:01:48Z","column":"email","confidence":"confirmed","evidence":"values","matched":1943,"sampled":2000}
```

`full_name` is judged by its name alone (names have no validator), so it
is **likely** (medium) with `evidence: column-name`. `email_sha256`
is a decoy: its name says email, but none of its values is one, and
values override names, so it gets no finding. In all, this file yields
10 findings, one per PII column.

**5. Suppress.** Without `--config`, every finding passes through. With
step f's `demo.toml`, the entry `rule = "pii-email"`, `prefix =
"lake/customers/"`, `column = "email"` matches this finding. It is set
aside as documented. `billing.email` is a different column path, so it
stays undocumented.

**6. Aggregate.** The PII inventory puts the file in a table by its key:
take the directory `lake/customers/dt=2026-01-01`, drop the Hive partition
segment `dt=2026-01-01`, and the table is `lake/customers`. The three other
`lake/customers/...` files land there too, so their findings merge into
one entry per (table, column, rule). This file is also the table's
`example_key`, the smallest key in the table with a PII finding.

**7. Report.** The finding ends as one inventory row. Undocumented, from
step e's CSV:

```text
lake/customers,email,pii-email,confirmed,values,4,0,0,0,UNDOCUMENTED,,lake/customers/dt=2026-01-01/part-0.parquet,2026-10-16T16:52:42Z,2026-10-16T16:52:42Z,
```

Documented, from step f2's CSV (all 4 files now counted as suppressed,
with the reason and the expiry):

```text
lake/customers,email,pii-email,confirmed,values,0,0,0,4,documented,"Consented marketing contacts, DPA-12",lake/customers/dt=2026-01-01/part-0.parquet,2026-10-16T16:52:42Z,2026-10-16T16:52:42Z,2027-06-30
```

## The demo, step by step

### Step 0: setup

```text
$ docker run --rm -d --name lakescan-demo-moto -p 5001:5000 motoserver/moto:5.2.3
-> moto is up on http://localhost:5001 (on macOS, AirPlay Receiver owns port 5000, hence 5001; set MOTO_PORT to use another)
$ export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1
$ cargo build --release
    Finished `release` profile [optimized] target(s) in 0.24s
$ cargo run --release --example seed_local -- http://localhost:5001
wrote 2413 objects to s3://lakescan-demo at http://localhost:5001
wrote 11 objects to s3://lakescan-pii at http://localhost:5001
```

What to notice:

- moto is an in-memory S3 that accepts any credentials, so the
  credentials are dummies.
- The seeder fills two buckets. `lakescan-demo` holds 2,413 tiny objects
  across three listing pages, with planted problems. `lakescan-pii` holds
  the 11 Parquet fixtures under lake-like keys.
- The script stops moto when it exits, even on Ctrl-C.
- `MOTO_PORT` (default `5001`) is the host port. On macOS, AirPlay Receiver already owns 5000.
- The script exports the dummy credentials for its own process tree only. Do not leave `AWS_ENDPOINT_URL` exported afterwards: a later scan of a real bucket would be sent to that endpoint. `--endpoint-url` on the command is the flag for an S3-compatible service.
- Everything it writes goes to `target/demo/`, which git ignores.

In the steps below, `lakescan` means `target/release/lakescan`.

### Step a: `lakescan rules`

```text
$ lakescan rules
sensitive-key           Key looks like a credential or secret file
reduced-redundancy      Object uses the deprecated REDUCED_REDUNDANCY storage class
stale-standard          Large STANDARD object has gone unmodified for a long time
small-object-cold-tier  Small object sits in a cold storage tier that bills a size minimum
zero-byte-object        Zero-byte object that is not a folder marker
unknown-storage-class   Object reports a storage class this build of LakeScan does not recognize
pii-email               Parquet column holds email addresses
pii-phone               Parquet column holds phone numbers
pii-in-pan              Parquet column holds Indian PAN numbers
pii-in-aadhaar          Parquet column holds Aadhaar numbers
pii-card-number         Parquet column holds payment card numbers
pii-ip-address          Parquet column holds IP addresses
pii-person-name         Parquet column holds people's names
pii-date-of-birth       Parquet column holds dates of birth
content-not-scanned     Parquet file could not be content-scanned
exit code: 0
```

What to notice:

- The first six rules need only the listing.
- The last nine apply only with `--pii`.
- These codes are what you write in a `--config` file's `rule =` field.

### Step b: a metadata-only scan

```text
$ lakescan scan s3://lakescan-demo --endpoint-url http://localhost:5001
lakescan 0.1.0
s3://lakescan-demo
settings: pii=off fail-on=high prefix=(none) config=(none)
started:  2026-10-16T16:52:42Z
elapsed:  0.195s

VERDICT
  worst severity: high

INVENTORY
  objects:     2413
  total bytes: 112471 (109.8 KiB)
  by storage class:
    STANDARD                 count=2410       bytes=111416 (108.8 KiB)
    REDUCED_REDUNDANCY       count=1          bytes=42 (42 B)
    STANDARD_IA              count=1          bytes=13 (13 B)
    GLACIER                  count=1          bytes=1000 (1000 B)

FINDINGS
  sensitive-key - Key looks like a credential or secret file
    high: 3 (125 B)
    medium: 2 (91 B)
  reduced-redundancy - Object uses the deprecated REDUCED_REDUNDANCY storage class
    medium: 1 (42 B)
  small-object-cold-tier - Small object sits in a cold storage tier that bills a size minimum
    low: 2 (1013 B)
  zero-byte-object - Zero-byte object that is not a folder marker
    info: 4 (0 B)

SAMPLES
  [sensitive-key]
    id_rsa  severity=high size=42 (42 B) class=STANDARD modified=2026-10-16T05:01:48Z
    infra/terraform.tfstate  severity=high size=42 (42 B) class=STANDARD modified=2026-10-16T05:01:48Z
    .env.production  severity=high size=41 (41 B) class=STANDARD modified=2026-10-16T05:01:48Z
    certs/server.pem  severity=medium size=46 (46 B) class=STANDARD modified=2026-10-16T05:01:48Z
    app/.git/config  severity=medium size=45 (45 B) class=STANDARD modified=2026-10-16T05:01:48Z
...
  [zero-byte-object]
    hostile/\u{001b}[31mred-alert.txt  severity=info size=0 (0 B) class=STANDARD modified=2026-10-16T05:01:48Z
    hostile/\u{202e}txt.exe  severity=info size=0 (0 B) class=STANDARD modified=2026-10-16T05:01:48Z
    placeholder/empty.txt  severity=info size=0 (0 B) class=STANDARD modified=2026-10-16T05:01:48Z
    plus+and%percent space.txt  severity=info size=0 (0 B) class=STANDARD modified=2026-10-16T05:01:48Z
...
DISTINCT CONTENT
  ~2413 distinct (etag, size) values across 2413 objects; no duplicates detected (differences under ~2% are within estimator error)
  (re-uploaded or re-encrypted content gets a new ETag and is not detected)
exit code: 1
```

What to notice:

- No object was read. All of this comes from listing pages.
- The two `hostile/` keys contain an ANSI escape and a right-to-left
  override. They are printed as `\u{001b}` and `\u{202e}`, so a key can't
  recolor your terminal or display as a different name.
- `id_rsa`, `terraform.tfstate` and `.env.production` are `high`.
- **Exit code 1**: the worst finding is `high`, and the default
  `--fail-on` is `high`.

### Step c: the same scan as JSON

```text
$ lakescan scan s3://lakescan-demo --endpoint-url http://localhost:5001 --format json --quiet > summary.json
$ pretty-print summary.json | head -45
{
  "schema_version": 1,
  "tool": {
    "name": "lakescan",
    "version": "0.1.0"
  },
  "scan": {
    "bucket": "lakescan-demo",
    "prefix": null,
    "started_at": "2026-10-16T16:52:43Z",
    "elapsed_ms": 175,
    "settings": {
      "pii": false,
      "pii_whole_file_max": null,
      "pii_sniff": null,
      "coalesce_gap": null,
      "concurrency": null,
      "memory_budget": null,
      "fail_on": "high",
      "prefix": null,
      "config": null
    }
  },
  "verdict": {
    "worst_severity": "high"
  },
  "inventory": {
    "object_count": 2413,
    "total_bytes": 112471,
...
exit code: 1
```

What to notice:

- The JSON is the same data as the text summary, for scripts and
  dashboards.
- `schema_version` only changes on a breaking change, so consumers should
  ignore fields they don't know.
- The pretty-printing uses `jq`, or Python's `json.tool` if `jq` isn't
  installed.
- **Exit code 1** again: the format changes nothing else.

### Step d: a PII scan

```text
$ lakescan scan s3://lakescan-pii --endpoint-url http://localhost:5001 --pii > pii-summary.txt
lakescan: 3 of 11 eligible Parquet files could not be content-scanned and are not documented (not-parquet=1, unreadable=1, no-column-examined=1)
lakescan: to accept a file that cannot be scanned, document it in --config with a content-not-scanned suppression: rule, key or prefix, reason, and optionally expires
VERDICT
  worst severity: high

FINDINGS
  pii-email - Parquet column holds email addresses
    high: 15 (-)
  pii-phone - Parquet column holds phone numbers
    high: 14 (-)
  pii-in-pan - Parquet column holds Indian PAN numbers
    high: 7 (-)
...
  pii-person-name - Parquet column holds people's names
    medium: 7 (-)
  pii-date-of-birth - Parquet column holds dates of birth
    medium: 7 (-)
  content-not-scanned - Parquet file could not be content-scanned
    info: 3 (1.2 MiB)

CONTENT
  parquet files:      11
    downloaded whole:  8
    read partially:    0
    not scanned:       3 (not-parquet=1, unreadable=1, no-column-examined=1)
  columns examined:   114
  columns skipped:    10 (repeated=0, unsupported-type=9, page-too-large=1, unreadable=0, unsupported-codec=0)
  bytes read:         11607807 (11.0 MiB)
  GET requests:       11
  sniffed:            0 (objects without a Parquet extension; one 8-byte GET each)

COVERAGE
  parquet files:  11
  scanned:        8 (72.7%)
  not scanned:    0 documented, 3 undocumented
  inspection:     sampled: the dictionary and first data page of each column in up to 3 row groups, at most 2,000 values per column per row group; files read whole are downloaded whole but sampled the same way
  columns not examined: 0 in 0 files of 0 tables
  Not in scope for --pii: none by extension
  sniffed, not Parquet: 0
  empty objects and folder markers: 0

PII INVENTORY
  4 tables with PII, 31 PII columns: 31 undocumented (25 confirmed, 6 likely, 0 possible), 0 documented. Action needed on the undocumented. 2 tables with files not scanned (0 documented), 0 with columns not examined.
  Tables are inferred from object paths. Documented means your team recorded a reason: an operational exception, not a compliance approval.
  bad  files: 0 scanned, 2 not scanned (not-parquet=1 undocumented, unreadable=1 undocumented); files dated 2026-10-16 to 2026-10-16
    not scanned: PII unknown
  lake/customers  files: 4 scanned, 0 not scanned; files dated 2026-10-16 to 2026-10-16
    example: lake/customers/dt=2026-01-01/part-0.parquet
    aadhaar_no  pii-in-aadhaar  confirmed  evidence=values  4 files confirmed  UNDOCUMENTED
    billing.email  pii-email  confirmed  evidence=values  4 files confirmed  UNDOCUMENTED
...
    dob  pii-date-of-birth  likely  evidence=column-name  4 files likely  UNDOCUMENTED
    email  pii-email  confirmed  evidence=values  4 files confirmed  UNDOCUMENTED
    full_name  pii-person-name  likely  evidence=column-name  4 files likely  UNDOCUMENTED
...
  lake/events  files: 1 scanned, 0 not scanned; files dated 2026-10-16 to 2026-10-16
    example: lake/events/data/dt=2026-01-01/part-0.parquet
    contact_email  pii-email  confirmed  evidence=values  1 file confirmed  UNDOCUMENTED
  skipped  files: 0 scanned, 1 not scanned (no-column-examined=1 undocumented); files dated 2026-10-16 to 2026-10-16
    not scanned: PII unknown
exit code: 6
```

What to notice:

- **Readers.** The same columns are found in files written by pyarrow,
  polars, DuckDB and Spark, compressed with Snappy, GZIP or Brotli.
- **Escalation.** `lake/events` is `escalation.parquet`. Its
  `contact_email` is pure junk in row group 0, so LakeScan sampled later
  row groups and still confirmed it.
- **Tables.** Files are grouped into tables from their keys: Hive
  partitions (`dt=`, `region=`) and Iceberg's `data/` are dropped.
- **Unscannable files.** The three files that could not be scanned are
  `bad/not_parquet.parquet` (a CSV), `bad/truncated.parquet` (cut off at
  60%) and `skipped/too_large.parquet` (its only string column has a
  9.5 MB page, over the 8 MiB cap). Their tables say `PII unknown`, never
  "no PII".
- **Exit code 6, not 1.** Confirmed PII is `high`, which alone would give
  1. But three files went unscanned and nothing documents why, so the
  inventory is incomplete. Coverage fails closed, and 6 takes precedence
  over 1. stderr says which reasons, and how to document them.

### Step e: the inventory as CSV

```text
$ lakescan scan s3://lakescan-pii --endpoint-url http://localhost:5001 --pii --inventory inventory.csv --quiet > /dev/null
lakescan: 3 of 11 eligible Parquet files could not be content-scanned and are not documented (not-parquet=1, unreadable=1, no-column-examined=1)
...
$ head -6 inventory.csv
table,column,rule,highest_confidence,evidence,files_confirmed,files_likely,files_possible,files_suppressed,status,reason,example_key,oldest_file,newest_file,expires,not_examined_reason
lake/customers,aadhaar_no,pii-in-aadhaar,confirmed,values,4,0,0,0,UNDOCUMENTED,,lake/customers/dt=2026-01-01/part-0.parquet,2026-10-16T16:52:42Z,2026-10-16T16:52:42Z,
lake/customers,billing.email,pii-email,confirmed,values,4,0,0,0,UNDOCUMENTED,,lake/customers/dt=2026-01-01/part-0.parquet,2026-10-16T16:52:42Z,2026-10-16T16:52:42Z,
lake/customers,card_number,pii-card-number,confirmed,values,4,0,0,0,UNDOCUMENTED,,lake/customers/dt=2026-01-01/part-0.parquet,2026-10-16T16:52:42Z,2026-10-16T16:52:42Z,
lake/customers,contact,pii-phone,confirmed,values,4,0,0,0,UNDOCUMENTED,,lake/customers/dt=2026-01-01/part-0.parquet,2026-10-16T16:52:42Z,2026-10-16T16:52:42Z,
lake/customers,dob,pii-date-of-birth,likely,column-name,0,4,0,0,UNDOCUMENTED,,lake/customers/dt=2026-01-01/part-0.parquet,2026-10-16T16:52:42Z,2026-10-16T16:52:42Z,
  ... (31 rows; full file: .../target/demo/inventory.csv)
exit code: 6
```

What to notice:

- There is one row per (table, column, rule), the same 31 entries as the
  text inventory.
- Cells are escaped against terminal tricks and spreadsheet formulas.
- **Exit code 6** again: the CSV is an extra output, and the same three
  files are still undocumented.

### Step f: documenting, and fail-closed coverage

**f1.** A config that documents one PII column and one unscannable file:

```toml
version = 1

# Document a PII location: the email column of the customers table.
[[suppress]]
rule = "pii-email"
prefix = "lake/customers/"
column = "email"
reason = "Consented marketing contacts, DPA-12"
expires = 2027-06-30

# Document one file that cannot be scanned.
[[suppress]]
rule = "content-not-scanned"
key = "bad/not_parquet.parquet"
reason = "A CSV export misnamed .parquet; no personal data, reviewed 2026-10-16"
```

```text
$ lakescan scan s3://lakescan-pii --endpoint-url http://localhost:5001 --pii --config demo.toml > documented-1.txt
lakescan: 2 of 11 eligible Parquet files could not be content-scanned and are not documented (unreadable=1, no-column-examined=1)
...
COVERAGE
  parquet files:  11
  scanned:        8 (72.7%)
  not scanned:    1 documented, 2 undocumented
  inspection:     sampled: the dictionary and first data page of each column in up to 3 row groups, at most 2,000 values per column per row group; files read whole are downloaded whole but sampled the same way
  columns not examined: 0 in 0 files of 0 tables
  Not in scope for --pii: none by extension
  sniffed, not Parquet: 0
  empty objects and folder markers: 0

PII INVENTORY
  4 tables with PII, 31 PII columns: 30 undocumented (24 confirmed, 6 likely, 0 possible), 1 documented. Action needed on the undocumented. 2 tables with files not scanned (0 documented), 0 with columns not examined.
  Tables are inferred from object paths. Documented means your team recorded a reason: an operational exception, not a compliance approval.
  bad  files: 0 scanned, 2 not scanned (not-parquet=1 documented, unreadable=1 undocumented); files dated 2026-10-16 to 2026-10-16
    not scanned: PII unknown
  lake/customers  files: 4 scanned, 0 not scanned; files dated 2026-10-16 to 2026-10-16
    example: lake/customers/dt=2026-01-01/part-0.parquet
    aadhaar_no  pii-in-aadhaar  confirmed  evidence=values  4 files confirmed  UNDOCUMENTED
    billing.email  pii-email  confirmed  evidence=values  4 files confirmed  UNDOCUMENTED
...
    pan  pii-in-pan  confirmed  evidence=values  4 files confirmed  UNDOCUMENTED
    email  pii-email  confirmed  evidence=values  4 files, documented until 2027-06-30: Consented marketing contacts, DPA-12
exit code: 6
```

What to notice:

- `email` moved to the end of its table as documented, with its reason and the date it applies until (`documented until 2027-06-30`).
  Undocumented entries are listed first.
- `billing.email` is a different column path, so it is still
  undocumented. The same is true of `email` in the `_gzip` and `_brotli`
  tables, which the prefix does not cover.
- `not-parquet` is now documented.
- **Exit code still 6**: one undocumented unscannable file is enough to
  fail the run, and two remain. That is what fail-closed means.

**f2.** Document the other two unscannable files and rerun:

```toml
[[suppress]]
rule = "content-not-scanned"
key = "bad/truncated.parquet"
reason = "Known-corrupt partial upload, kept for the incident record"

[[suppress]]
rule = "content-not-scanned"
prefix = "skipped/"
reason = "Oversized test pages; reviewed, no production data"
```

```text
$ lakescan scan s3://lakescan-pii --endpoint-url http://localhost:5001 --pii --config demo.toml --inventory documented.csv > documented-2.txt
COVERAGE
  parquet files:  11
  scanned:        8 (72.7%)
  not scanned:    3 documented, 0 undocumented
  inspection:     sampled: the dictionary and first data page of each column in up to 3 row groups, at most 2,000 values per column per row group; files read whole are downloaded whole but sampled the same way
  columns not examined: 0 in 0 files of 0 tables
  Not in scope for --pii: none by extension
  sniffed, not Parquet: 0
  empty objects and folder markers: 0

PII INVENTORY
  4 tables with PII, 31 PII columns: 30 undocumented (24 confirmed, 6 likely, 0 possible), 1 documented. Action needed on the undocumented. 2 tables with files not scanned (2 documented), 0 with columns not examined.
  Tables are inferred from object paths. Documented means your team recorded a reason: an operational exception, not a compliance approval.
  bad  files: 0 scanned, 2 not scanned (not-parquet=1 documented, unreadable=1 documented); files dated 2026-10-16 to 2026-10-16
    not scanned: PII unknown
$ grep ',documented,' documented.csv
lake/customers,email,pii-email,confirmed,values,0,0,0,4,documented,"Consented marketing contacts, DPA-12",lake/customers/dt=2026-01-01/part-0.parquet,2026-10-16T16:52:42Z,2026-10-16T16:52:42Z,2027-06-30
exit code: 1
```

What to notice:

- No stderr warning this time, and coverage is fully accounted for.
- Scanned is still 72.7%: documenting a file doesn't pretend it was read.
- **Exit code 6 → 1**: with coverage accounted for, the exit code comes
  from the findings, and 30 confirmed or likely PII columns are still
  undocumented.
- To reach 0 you would document every one of them, or change `--fail-on`
  (step i).

### Step g: the findings stream

```text
$ lakescan scan s3://lakescan-pii --endpoint-url http://localhost:5001 --pii --findings findings.jsonl --quiet > /dev/null
...
74 findings; two PII ones:
$ grep '"rule":"pii-' findings.jsonl | head -2
{"key":"lake/customers/dt=2026-01-01/part-0.parquet","rule":"pii-person-name","severity":"medium","size":1909661,"storage_class":"STANDARD","last_modified":"2026-10-16T05:01:48Z","column":"full_name","confidence":"likely","evidence":"column-name"}
{"key":"lake/customers/dt=2026-01-01/part-0.parquet","rule":"pii-email","severity":"high","size":1909661,"storage_class":"STANDARD","last_modified":"2026-10-16T05:01:48Z","column":"email","confidence":"confirmed","evidence":"values","matched":1943,"sampled":2000}
$ grep -c @ findings.jsonl
0
exit code: 6
```

What to notice:

- **No values.** A finding carries the file, the column, the confidence
  and two counts, never a value. The stream has 15 `pii-email` findings
  and not one `@`, so no email address left the scanner.
- **Live.** The stream is written as findings are made, for `jq`, a SIEM
  or a ticketing hook.
- Suppressed findings are left out of it.
- The file starts with the three `content-not-scanned` findings, which
  is why the demo picks out PII lines with `grep`.
- **Exit code 6**: this run has no `--config`.

### Step h: the HTML report

```text
$ lakescan scan s3://lakescan-pii --endpoint-url http://localhost:5001 --pii --config demo.toml --html report.html --quiet > /dev/null
$ open report.html
exit code: 1
```

What to notice:

- `--html` writes an interactive dashboard. Open the file in any browser;
  it works offline and makes no network requests. CSS and script are
  inline, and a Content-Security-Policy of `default-src 'none'` stops the
  page from loading anything.
- The header shows the bucket, when the scan ran, how long it took, and
  the exit code with its meaning.
- **PII inventory**: filter All, Undocumented and Documented, and click a
  rule or a table to narrow the rows. Documented rows show the reason and
  expiry. **Document ›** copies a suppression snippet for an undocumented
  column.
- **Files not scanned**, with the reason and whether it is documented.
- **Coverage detail** and **Metadata findings** are collapsed at the
  bottom; open them for the file counts and the six metadata rules.
- **Exit code 1**, as in f2. The page states that code and its meaning.

### Step i: `--fail-on none`

```text
$ lakescan scan s3://lakescan-pii --endpoint-url http://localhost:5001 --pii --config demo.toml --fail-on none --quiet > /dev/null
exit code: 0

$ lakescan scan s3://lakescan-pii --endpoint-url http://localhost:5001 --pii --fail-on none --quiet > /dev/null
lakescan: 3 of 11 eligible Parquet files could not be content-scanned and are not documented (not-parquet=1, unreadable=1, no-column-examined=1)
...
exit code: 6
```

What to notice:

- `--fail-on` sets the lowest severity that fails a run, and `none`
  means findings never fail it. With `demo.toml` that gives **0**: the
  same findings as f2, reported but not failing.
- Without `demo.toml` it is **6** even with `--fail-on none`: `--fail-on`
  governs findings, never coverage. The only way past 6 is to document
  the files that can't be scanned.

### Step j: `--concurrency 1` versus the default

```text
$ lakescan scan s3://lakescan-pii --endpoint-url http://localhost:5001 --pii --quiet --concurrency 1 --findings findings-c1.jsonl --inventory inventory-c1.csv > summary-c1.txt
...
$ lakescan scan s3://lakescan-pii --endpoint-url http://localhost:5001 --pii --quiet --findings findings-c16.jsonl --inventory inventory-c16.csv > summary-c16.txt
...
exit codes: 6 (--concurrency 1) and 6 (default)
$ diff <(grep -v -E "^(started|elapsed|settings):" summary-c1.txt) <(grep -v -E "^(started|elapsed|settings):" summary-c16.txt)
$ diff findings-c1.jsonl findings-c16.jsonl
$ diff inventory-c1.csv inventory-c16.csv
-> No diff output: the summary, the findings stream and the inventory are identical.
```

What to notice:

- With 16 files in flight, they finish in any order. The driver still
  applies results in listing order, so every output is identical, byte
  for byte.
- The only differences are the `started:`, `elapsed:` and `settings:`
  lines (`settings` records concurrency), which are left out of the
  comparison.
- That determinism is what makes reports diffable between runs.

## Exit codes

The numbers are a frozen contract ([`src/error.rs`](../src/error.rs)).
The run's code is decided in `decide` in
[`src/cli/driver.rs`](../src/cli/driver.rs): coverage first, then the
verdict.

| Code | Name | Meaning | Seen in |
|---|---|---|---|
| 0 | `Ok` | The scan completed and no unsuppressed finding reached `--fail-on`. | a, i |
| 1 | `FindingsExceedThreshold` | The scan completed, but an unsuppressed finding reached `--fail-on`. | b, c, f2, h |
| 2 | `Usage` | Bad arguments, target or config file, a missing bucket, or a region mismatch. | below |
| 3 | `Auth` | Credentials are missing, expired or rejected. | (moto accepts any) |
| 4 | `Transport` | The network or S3 failed; often worth retrying. | below |
| 5 | `Report` | An output could not be written (bad path, full disk, permissions). | below |
| 6 | `ContentNotScanned` | With `--pii`, a Parquet file could not be scanned and is not documented. Wins over 1. | d, e, f1, g, i, j |
| 101 | (outside the contract) | LakeScan itself panicked: a bug, please report it. | |

Codes 2, 4 and 5 are not in the demo. These are real runs of them:

```text
$ lakescan scan lakescan-demo
lakescan: usage: invalid target "lakescan-demo": expected s3://bucket or s3://bucket/prefix
exit 2
$ lakescan scan s3://lakescan-demo --endpoint-url http://localhost:5999   # nothing listening
lakescan: transport: io error
exit 4
$ lakescan scan s3://lakescan-demo --endpoint-url http://localhost:5001 --output /nonexistent/summary.txt
lakescan: report: cannot open /nonexistent/summary.txt: No such file or directory (os error 2)
exit 5
```

## Read the code in this order

1. [`src/lib.rs`](../src/lib.rs): the pipeline diagram, each stage's memory
   budget, and the hostile-input threat model. Read it first.
2. [`src/model.rs`](../src/model.rs): the shared vocabulary.
   `ObjectMeta`, `Finding`, `Severity`, `RuleId`, `PiiType`,
   `Confidence`, `NotScannedReason`. Every other module speaks it.
3. [`src/error.rs`](../src/error.rs): how every failure maps to exactly one
   frozen exit code.
4. [`src/scanner/page_source.rs`](../src/scanner/page_source.rs), then
   [`s3_source.rs`](../src/scanner/s3_source.rs): the pagination seam
   that makes the scanner testable without a network, and why listings
   use URL-encoded keys.
5. [`src/rules/mod.rs`](../src/rules/mod.rs) and
   [`sensitive_key.rs`](../src/rules/sensitive_key.rs): a stateless rule
   that allocates nothing per object, and why no v1 rule is `critical`.
   The other rule files follow the same pattern.
6. [`src/suppress/config.rs`](../src/suppress/config.rs), then
   [`mod.rs`](../src/suppress/mod.rs): a strict config parser (an unknown
   field is an error), and entries as inactive, expired, active or unused.
7. [`src/content/mod.rs`](../src/content/mod.rs): the map of content
   scanning. Then, in the order a file goes through them:
   - [`fetch.rs`](../src/content/fetch.rs): the read seam.
   - [`read.rs`](../src/content/read.rs): the whole or partial read plan,
     escalation to more row groups, and `coalesce`.
   - [`header.rs`](../src/content/header.rs): checking page headers before
     anything is allocated.
   - [`clean.rs`](../src/content/clean.rs), [`detect.rs`](../src/content/detect.rs)
     (Luhn, Verhoeff, PAN and more), [`names.rs`](../src/content/names.rs)
     and [`classify.rs`](../src/content/classify.rs): from raw values to
     one confidence per column.
   - [`budget.rs`](../src/content/budget.rs): the memory semaphore, and
     how it avoids deadlock.
8. [`src/aggregate/mod.rs`](../src/aggregate/mod.rs): mergeable,
   order-independent summaries with compile-time size limits. Then
   [`pii.rs`](../src/aggregate/pii.rs): `table_of`, the inventory's
   caps, and documented versus undocumented.
9. [`src/report/text.rs`](../src/report/text.rs) and
   [`escape.rs`](../src/report/escape.rs): rendering without
   recomputing, and defusing hostile names. Then
   [`json.rs`](../src/report/json.rs), [`findings.rs`](../src/report/findings.rs),
   [`csv.rs`](../src/report/csv.rs) and [`html.rs`](../src/report/html.rs).
10. [`src/cli/driver.rs`](../src/cli/driver.rs): everything wired
    together. The concurrent, in-order window of content scans, and
    `decide`, which picks the exit code. Its tests run whole scans in
    memory.
11. Tests: [`tests/pipeline.rs`](../tests/pipeline.rs) (the stages through
    the public API only), then [`tests/e2e_pii.rs`](../tests/e2e_pii.rs)
    (the built binary against moto, which is what this demo does by
    hand).

## Glossary

**Parquet.** A columnar file format for tables: values of one column are
stored together, compressed, so a reader can fetch one column without the
others. A Parquet file starts and ends with the magic bytes `PAR1`.

**Row group.** A horizontal slice of a Parquet file's rows (the fixtures
use 4,000 rows each). Each row group holds one *column chunk* per column.
LakeScan samples row group 0 first, then the middle and last ones if it
needs more evidence (at most 3).

**Page.** The unit a column chunk is stored in, each with its own header
(type, sizes, codec). LakeScan reads the first data page of a column
chunk, and refuses pages whose header declares more than 8 MiB.

**Footer.** The metadata at the end of a Parquet file: the schema, and
where every row group and column chunk starts. For a file too big to read
whole, LakeScan reads it first, with one 64 KiB tail read, to plan the
other reads.

**Dictionary encoding.** A writer stores each distinct value once, in a
dictionary page at the start of the column chunk, and data pages hold
small indexes into it. When a writer uses one, LakeScan reads it too.
Some writers don't, for example Spark for these PII columns.

**Suppression.** A `[[suppress]]` entry in the `--config` file: a rule,
an exact `key` or a `prefix`, optionally a `column`, a required `reason`,
and an optional `expires` date. A suppressed finding is *documented*. It
no longer affects the exit code or the findings stream, but it is counted
and stays in the inventory with its reason.

**Confidence levels.** How sure LakeScan is that a column holds a PII
type. They set the severity:

- `confirmed` (high): at least 80% of at least 30 cleaned values validate.
- `likely` (medium): 50–80% of at least 30 validate; or at least 80% of
  fewer than 30; or the column's name suggests the type and at least one
  value validates; or, for names and dates of birth (judged by name
  only), a clear name hint on a column of fitting type.
- `possible` (info): a name hint with no value evidence.

**Coverage.** How many of the eligible Parquet files were actually
scanned, and of the rest, how many are documented. It also says the
inspection was sampled (never exhaustive), and counts objects that were
not in scope for `--pii` by extension. It is shown as the COVERAGE
section, and `coverage` in JSON.

**Fail-closed.** When LakeScan can't check something, it fails instead of
passing. One undocumented unscanned file among thousands makes the exit
code 6, and a table with no file scanned says `PII unknown`, never "no
PII".

**Memory budget.** The `--memory-budget` limit (512 MiB by default) on
the bytes in-flight content scans may hold. Every fetch and decode takes
permits for its size before it starts. One file needs at most ~108 MiB,
so a smaller budget is a usage error. The bucket's size never changes
memory use.
