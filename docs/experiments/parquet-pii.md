# Experiment: finding PII from Parquet footers, dictionaries and first pages

This answers the open question in [docs/PRODUCT.md](../PRODUCT.md): what share of
PII columns can be found by reading only a Parquet file's footer, its min/max
statistics, its dictionary pages and a few data pages, and what fraction of the
file's bytes that takes. The code is throwaway and lives in
[`spikes/parquet-pii/`](../../spikes/parquet-pii/). It is not part of LakeScan.

**Verdict:** under the pre-registered criteria, **not viable as specified**.
Every writer fails on the 1M-row customers file at 80% value recall. The cause
is the same single column every time: free text in which about 5% of rows
contain an email address. Every other value-detectable PII column was found,
with 100% precision, by every writer and strategy from S1 upward. Those reads
used at most 7.3% of uncompressed bytes, and usually far less. Details and
caveats follow.

## Setup

Run on 2026-10-13 on an Apple M5 running macOS 27.0.1, reading local files.

**Writers**, each at its default settings:

- pyarrow 25.0.1 (`pq.write_table`, snappy)
- polars 1.44.2 (`DataFrame.write_parquet`, zstd)
- duckdb 1.5.6 (`COPY ... (FORMAT PARQUET)`, snappy)

The generator ran on Python 3.14.6 with numpy 2.5.3. The measurement program
uses the Rust `parquet` crate 60.0.0 (built with rustc 1.99.0), with only its
`snap` and `zstd` features. Every Python package and every crate in the spike's
lockfile is a release at least 14 days old (cutoff 2026-09-29).

**Data.** Synthetic and seeded; generating all nine files takes 13 seconds and
852 MB.

`customers` has 12 columns:

| Column | Ground truth | Name |
|---|---|---|
| `customer_id` | none | |
| `full_name` | PERSON_NAME | honest |
| `email` | EMAIL, unique per row | honest |
| `contact` | PHONE: `+91 98765 43210`, `+919876543210`, 10-digit, and US E.164 | obfuscated |
| `dob` | DATE_OF_BIRTH (`date`) | honest |
| `pan` | IN_PAN | honest |
| `c9` | IN_AADHAAR: 12 digits, Verhoeff-valid, unique | obfuscated |
| `city` | none | |
| `plan` | none, 5 values | |
| `email_sha256` | none: a decoy, hex digests of the email | |
| `signup_ts` | none | |
| `notes` | EMAIL_EMBEDDED: free text, 4.96% of rows embed an email | not revealing |

`events` has 9 columns:

| Column | Ground truth | Name |
|---|---|---|
| `event_id` | none: uuid strings | |
| `customer_email` | EMAIL, 1,000,000 distinct values over 2M rows | honest |
| `src` | IP_ADDRESS: 80% IPv4, 20% IPv6 | obfuscated |
| `card` | CARD_NUMBER: Luhn-valid Visa, Mastercard and Amex, 25% space-grouped | honest |
| `order_ref` | none: a decoy, 12-digit Aadhaar look-alikes that fail Verhoeff | |
| `amount`, `status`, `user_agent`, `country` | none | |

The manifest at `data/manifest.json` records every file and column's true type
and whether its name is honest.

| File | Writer | Rows | Row groups | File size | Uncompressed (column chunks) |
|---|---|---:|---:|---:|---:|
| `pyarrow/customers_1m.parquet` | pyarrow | 1,000,000 | 1 | 146.4 MB | 237.3 MB |
| `polars/customers_1m.parquet` | polars | 1,000,000 | 8 | 85.5 MB | 239.2 MB |
| `duckdb/customers_1m.parquet` | duckdb | 1,000,000 | 9 | 147.4 MB | 239.5 MB |
| `pyarrow/events_2m.parquet` | pyarrow | 2,000,000 | 2 | 193.6 MB | 271.1 MB |
| `polars/events_2m.parquet` | polars | 2,000,000 | 16 | 121.4 MB | 281.9 MB |
| `duckdb/events_2m.parquet` | duckdb | 2,000,000 | 17 | 194.6 MB | 273.0 MB |
| `pyarrow/customers_10k.parquet` | pyarrow | 10,000 | 1 | 1.7 MB | 2.6 MB |
| `polars/customers_10k.parquet` | polars | 10,000 | 1 | 920.5 KB | 2.5 MB |
| `duckdb/customers_10k.parquet` | duckdb | 10,000 | 1 | 1.5 MB | 2.5 MB |

"Uncompressed" is the sum of every column chunk's `total_uncompressed_size`,
the basis Macie bills on.

**Reading.** All file access goes through a counting reader. One "range read"
is one contiguous fetch, the unit an object store bills and the main driver of
latency.

- Page headers, whose length is unknown until parsed, are fetched in 1 KiB
  probes, and each probe counts as a range.
- Page bodies are fetched as exact ranges.
- No strategy reads a whole file.

The strategies are cumulative:

- **S0**: the footer only (2 ranges: the 8-byte tail, then the footer). Uses
  column names.
- **S1**: S0 plus the min/max statistics values from every row group. These
  are already in the footer, so they cost no extra bytes.
- **S2**: S1 plus the dictionary page of every dictionary-encoded column in
  row group 0, read as exactly the range
  `[dictionary_page_offset, data_page_offset)`.
- **S3**: S2 plus the first data page of every column with no dictionary page
  in row group 0. That page is decoded with the crate's column reader, behind
  a wrapper that never fetches a second page.

**Detectors.**

| Type | Validator |
|---|---|
| EMAIL | anchored regex |
| EMAIL_EMBEDDED | an email found inside a value that is not itself an email |
| PHONE | E.164, or an Indian mobile with optional `+91`/`91`/`0`, after stripping spaces, dashes, dots and parentheses |
| IN_PAN | `^[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]$` |
| IN_AADHAAR | 12 digits, first digit 2–9, Verhoeff checksum |
| CARD_NUMBER | 13–19 digits, Luhn checksum |
| IP_ADDRESS | parses as IPv4 or IPv6 |

PERSON_NAME and DATE_OF_BIRTH are recognized by column name only. Name hints
come from tokens in the column name, e.g. `email`, `phone`, `dob`, `pan`,
`aadhaar`, `card`, `ip`, `name`.

**Column rule (pre-registered).** A column is flagged as type T when at least
80% of its non-null sampled values validate as T. When several types qualify,
the strictest wins: checksums, then parsers, then structured regexes, then
loose regexes.

**Metrics.**

- *Value recall* is over value-detectable PII columns: 5 in customers
  (`email`, `contact`, `pan`, `c9`, `notes`) and 3 in events.
- *Recall incl. names* is over all PII columns. A column counts as found if its
  value flag, or (when there is no value flag) its name hint, gives the true
  type.
- *Precision* is the share of flagged columns whose flag is the true type.

## Encoding of PII columns (first row group)

This directly answers the question of how often high-cardinality PII columns
fall back to plain encoding.

| Dataset | Column | PII type | pyarrow | polars | duckdb |
|---|---|---|---|---|---|
| customers (1,000,000) | `full_name` | PERSON_NAME | dictionary (151 KB dict) | dictionary (103 KB dict; page stats absent) | dictionary (151 KB dict; page stats absent) |
| customers (1,000,000) | `email` | EMAIL | dictionary, then PLAIN fallback (444 KB dict) | plain (no dictionary) | plain (no dictionary) |
| customers (1,000,000) | `contact` | PHONE | dictionary, then PLAIN fallback (646 KB dict) | plain (no dictionary) | plain (no dictionary) |
| customers (1,000,000) | `dob` | DATE_OF_BIRTH | dictionary (83 KB dict) | dictionary (55 KB dict; page stats absent) | dictionary (83 KB dict; page stats absent) |
| customers (1,000,000) | `pan` | IN_PAN | dictionary, then PLAIN fallback (825 KB dict) | plain (no dictionary) | plain (no dictionary) |
| customers (1,000,000) | `c9` | IN_AADHAAR | dictionary, then PLAIN fallback (668 KB dict) | plain (no dictionary) | plain (no dictionary) |
| customers (1,000,000) | `notes` | EMAIL_EMBEDDED | dictionary, then PLAIN fallback (288 KB dict) | plain (no dictionary) | plain (no dictionary) |
| events (2,000,000) | `customer_email` | EMAIL | dictionary, then PLAIN fallback (531 KB dict) | plain (no dictionary) | plain (no dictionary) |
| events (2,000,000) | `src` | IP_ADDRESS | dictionary, then PLAIN fallback (715 KB dict) | plain (no dictionary) | plain (no dictionary) |
| events (2,000,000) | `card` | CARD_NUMBER | dictionary, then PLAIN fallback (774 KB dict) | plain (no dictionary) | plain (no dictionary) |

In the 10,000-row file, pyarrow dictionary-encodes all seven PII columns
without fallback, while polars and duckdb dictionary-encode none of them, not
even `full_name` and `dob`.

**Reading the table.** The concern in PRODUCT.md is real, and worse than it
assumed.

- **polars and duckdb** never dictionary-encode a high-cardinality PII column:
  they write it plain from the first page.
- **pyarrow** always starts a dictionary and falls back to PLAIN once it
  passes its size limit. The dictionary then holds only the first few tens of
  thousands of distinct values.
- **Consequence for dictionary-only reads:** for polars and duckdb, the only
  dictionary-encoded PII columns are the two that can only be found by name.
  So reading dictionaries alone would find **none** of the value-detectable
  PII columns from those writers. In the cumulative S2 results below, all of
  that recall comes from the S1 statistics.

## Results

### S0: footer only

| File | Writer | Value recall | Value precision | Recall incl. names | Precision incl. names | Read | % of file | % of uncompressed | Ranges | Wall ms |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| customers 1,000,000 | pyarrow | 0% (0/5) | n/a | 57% (4/7) | 80% | 2.8 KB | 0.002% | 0.001% | 2 | 0.0 |
| customers 1,000,000 | polars | 0% (0/5) | n/a | 57% (4/7) | 80% | 11.5 KB | 0.013% | 0.005% | 2 | 0.0 |
| customers 1,000,000 | duckdb | 0% (0/5) | n/a | 57% (4/7) | 80% | 15.2 KB | 0.010% | 0.006% | 2 | 0.0 |
| events 2,000,000 | pyarrow | 0% (0/3) | n/a | 67% (2/3) | 100% | 3.4 KB | 0.002% | 0.001% | 2 | 0.0 |
| events 2,000,000 | polars | 0% (0/3) | n/a | 67% (2/3) | 100% | 16.5 KB | 0.014% | 0.006% | 2 | 0.0 |
| events 2,000,000 | duckdb | 0% (0/3) | n/a | 67% (2/3) | 100% | 21.4 KB | 0.011% | 0.008% | 2 | 0.0 |
| customers 10,000 | pyarrow | 0% (0/5) | n/a | 57% (4/7) | 80% | 2.7 KB | 0.163% | 0.104% | 2 | 0.0 |
| customers 10,000 | polars | 0% (0/5) | n/a | 57% (4/7) | 80% | 2.4 KB | 0.259% | 0.095% | 2 | 0.0 |
| customers 10,000 | duckdb | 0% (0/5) | n/a | 57% (4/7) | 80% | 1.9 KB | 0.123% | 0.075% | 2 | 0.0 |

### S1: footer plus min/max statistics

| File | Writer | Value recall | Value precision | Recall incl. names | Precision incl. names | Read | % of file | % of uncompressed | Ranges | Wall ms |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| customers 1,000,000 | pyarrow | 80% (4/5) | 100% | 86% (6/7) | 86% | 2.8 KB | 0.002% | 0.001% | 2 | 0.0 |
| customers 1,000,000 | polars | 80% (4/5) | 100% | 86% (6/7) | 86% | 11.5 KB | 0.013% | 0.005% | 2 | 0.0 |
| customers 1,000,000 | duckdb | 80% (4/5) | 100% | 86% (6/7) | 86% | 15.2 KB | 0.010% | 0.006% | 2 | 0.0 |
| events 2,000,000 | pyarrow | 100% (3/3) | 100% | 100% (3/3) | 100% | 3.4 KB | 0.002% | 0.001% | 2 | 0.0 |
| events 2,000,000 | polars | 100% (3/3) | 100% | 100% (3/3) | 100% | 16.5 KB | 0.014% | 0.006% | 2 | 0.0 |
| events 2,000,000 | duckdb | 100% (3/3) | 100% | 100% (3/3) | 100% | 21.4 KB | 0.011% | 0.008% | 2 | 0.0 |
| customers 10,000 | pyarrow | 80% (4/5) | 100% | 86% (6/7) | 86% | 2.7 KB | 0.163% | 0.104% | 2 | 0.0 |
| customers 10,000 | polars | 80% (4/5) | 100% | 86% (6/7) | 86% | 2.4 KB | 0.259% | 0.095% | 2 | 0.0 |
| customers 10,000 | duckdb | 80% (4/5) | 100% | 86% (6/7) | 86% | 1.9 KB | 0.123% | 0.075% | 2 | 0.0 |

### S2: plus dictionary pages of row group 0

| File | Writer | Value recall | Value precision | Recall incl. names | Precision incl. names | Read | % of file | % of uncompressed | Ranges | Wall ms |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| customers 1,000,000 | pyarrow | 80% (4/5) | 100% | 86% (6/7) | 86% | 5.7 MB | 3.927% | 2.422% | 14 | 37.0 |
| customers 1,000,000 | polars | 80% (4/5) | 100% | 86% (6/7) | 86% | 169.7 KB | 0.199% | 0.071% | 6 | 1.5 |
| customers 1,000,000 | duckdb | 80% (4/5) | 100% | 86% (6/7) | 86% | 249.4 KB | 0.169% | 0.104% | 6 | 2.9 |
| events 2,000,000 | pyarrow | 100% (3/3) | 100% | 100% (3/3) | 100% | 3.9 MB | 2.007% | 1.433% | 11 | 13.1 |
| events 2,000,000 | polars | 100% (3/3) | 100% | 100% (3/3) | 100% | 17.1 KB | 0.014% | 0.006% | 5 | 0.5 |
| events 2,000,000 | duckdb | 100% (3/3) | 100% | 100% (3/3) | 100% | 130.3 KB | 0.067% | 0.048% | 6 | 3.2 |
| customers 10,000 | pyarrow | 80% (4/5) | 100% | 86% (6/7) | 86% | 1.5 MB | 88.939% | 56.482% | 14 | 5.4 |
| customers 10,000 | polars | 80% (4/5) | 100% | 86% (6/7) | 86% | 2.8 KB | 0.300% | 0.111% | 4 | 0.2 |
| customers 10,000 | duckdb | 80% (4/5) | 100% | 86% (6/7) | 86% | 2.4 KB | 0.153% | 0.094% | 4 | 0.2 |

### S3: plus the first data page of every column without a dictionary

| File | Writer | Value recall | Value precision | Recall incl. names | Precision incl. names | Read | % of file | % of uncompressed | Ranges | Wall ms |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| customers 1,000,000 | pyarrow | 80% (4/5) | 100% | 86% (6/7) | 86% | 5.7 MB | 3.927% | 2.422% | 14 | 12.4 |
| customers 1,000,000 | polars | 80% (4/5) | 100% | 86% (6/7) | 86% | 2.9 MB | 3.406% | 1.217% | 22 | 15.8 |
| customers 1,000,000 | duckdb | 80% (4/5) | 100% | 86% (6/7) | 86% | 17.4 MB | 11.823% | 7.279% | 22 | 41.7 |
| events 2,000,000 | pyarrow | 100% (3/3) | 100% | 100% (3/3) | 100% | 3.9 MB | 2.007% | 1.433% | 11 | 9.0 |
| events 2,000,000 | polars | 100% (3/3) | 100% | 100% (3/3) | 100% | 2.2 MB | 1.848% | 0.796% | 17 | 14.9 |
| events 2,000,000 | duckdb | 100% (3/3) | 100% | 100% (3/3) | 100% | 11.5 MB | 5.931% | 4.228% | 16 | 30.3 |
| customers 10,000 | pyarrow | 80% (4/5) | 100% | 86% (6/7) | 86% | 1.5 MB | 88.939% | 56.482% | 14 | 2.6 |
| customers 10,000 | polars | 80% (4/5) | 100% | 86% (6/7) | 86% | 917.8 KB | 99.709% | 36.684% | 24 | 6.1 |
| customers 10,000 | duckdb | 80% (4/5) | 100% | 86% (6/7) | 86% | 1.5 MB | 99.889% | 61.304% | 24 | 4.1 |

### What the numbers show

- **Which columns are missed.** At S1 and above, the only value-detectable
  column ever missed is `notes`, in every customers file, for every writer.
  With about 5% of values carrying an email, it cannot reach the 80% rule.
  The only PII column missed even with name hints is also `notes`; `full_name`
  and `dob` are found by name, as designed.
- **Decoys and precision.** No value flag was wrong, in any file or strategy.
  Neither decoy (`email_sha256`, `order_ref`) was ever flagged from values. The
  86% "precision incl. names" in customers is entirely the `email_sha256` name
  hint, which wrongly suggests EMAIL. Name hints, unlike value flags, produced
  a false positive.
- **Statistics do most of the work.** S1 reaches the same recall as S2 and S3,
  from between 2 (pyarrow customers) and 34 (duckdb events) min/max values per
  column, at zero bytes beyond the footer. In these synthetic columns every
  value has the PII shape, so the extremes do too (see Limitations).
- **Cost of S2 and S3 by writer.** pyarrow's fallback dictionaries make its S2
  the most expensive read: 5.7 MB, 2.4% of uncompressed. DuckDB writes one
  data page per column per row group (about 123k rows), so its S3 "first page"
  is a whole row-group chunk: 17.4 MB, 7.3% of uncompressed. That is still
  within budget, but only because the file has 9 row groups. A DuckDB file
  with one row group would cost close to the full column.
- **Small files.** On the 10,000-row file, dictionaries and first pages *are*
  the data: S2 and S3 read 37–61% of uncompressed bytes. The pass criteria
  apply only to the 1M- and 2M-row files, and in absolute terms the reads are
  at most 1.5 MB.
- **Wall times** come from local files with a warm page cache. They are not a
  proxy for object-store latency; the range count is. S3 needs 11–22 ranges
  per file.

## Verdict against the pre-registered criteria

**Criterion:** the approach is viable if, for every writer, S2 or S3 reaches at
least 90% recall on value-detectable PII columns, with at least 95% precision,
on the 1M- and 2M-row files, while reading at most 10% of uncompressed bytes.

| Writer | File | Best of S2/S3 meeting all three thresholds | Value recall | Value precision | % of uncompressed |
|---|---|---|---:|---:|---:|
| pyarrow | customers 1,000,000 | **fails** (shown: S3) | 80% | 100% | 2.42% |
| pyarrow | events 2,000,000 | **S2 passes** | 100% | 100% | 1.43% |
| polars | customers 1,000,000 | **fails** (shown: S3) | 80% | 100% | 1.22% |
| polars | events 2,000,000 | **S2 passes** | 100% | 100% | 0.01% |
| duckdb | customers 1,000,000 | **fails** (shown: S3) | 80% | 100% | 7.28% |
| duckdb | events 2,000,000 | **S2 passes** | 100% | 100% | 0.05% |

**Not viable as specified.** All three writers fail on customers. Precision
(100%) and bytes (at most 7.3%) pass everywhere; recall fails on one column:
the sparse embedded email in free text. The 80%-of-values rule cannot flag a
column where only a few percent of rows hold PII, however many bytes are read.
This is a limit of the rule, not of the reads.

**Supplementary analysis (not part of the verdict).** This rule was written
into the measurement code before the first run, not chosen after seeing
results: flag EMAIL_EMBEDDED when no pre-registered type qualifies and at
least 1% of sampled values contain an embedded email.

| File | Writer | S2 value recall | S3 value recall | S3 value precision |
|---|---|---:|---:|---:|
| customers 1,000,000 | pyarrow | 100% | 100% | 100% |
| customers 1,000,000 | polars | 80% | 100% | 100% |
| customers 1,000,000 | duckdb | 80% | 100% | 100% |
| events 2,000,000 | pyarrow | 100% | 100% | 100% |
| events 2,000,000 | polars | 100% | 100% | 100% |
| events 2,000,000 | duckdb | 100% | 100% | 100% |

With that rule, S3 meets all three thresholds for every writer on both large
files. Sparse PII in free text needs its own rule; a single threshold for all
types does not work.

## Limitations

- **Synthetic, homogeneous data.** Every value in a PII column has the PII
  shape, with no nulls, junk, mixed content or legacy formats. That is exactly
  the condition under which min/max statistics are representative. In a real
  column a single malformed extreme (`""`, `"N/A"`, `"0"`) turns one of the
  2–34 statistics values against the 80% rule, so the S1 result here is an
  upper bound. Real lakes also contain PII this data lacks: names in free
  text, addresses, national IDs from other countries.
- **Statistics can be absent or truncated.** Writers can disable statistics.
  polars truncates string min/max to 64 bytes: its `notes` statistics are
  exactly 64 bytes, against 65–66 for pyarrow and duckdb. Every email here is
  shorter than that, but a longer value would be cut and could then fail its
  validator. Without statistics, polars and duckdb files fall straight to S3.
- **First-row-group sampling bias.** S2 and S3 sample only row group 0. Data
  sorted or partitioned by time, region or tenant can make the first row group
  unrepresentative, for example when PII appears only in later rows. S1 uses
  every row group's statistics, which partly offsets this.
- **Name-only types.** PERSON_NAME and DATE_OF_BIRTH are found only when the
  column name is honest. In this data both names were honest; with obfuscated
  names, value recall is unchanged but "recall incl. names" drops. Name hints
  also cost precision (`email_sha256`).
- **One configuration per writer.** These are defaults only. Writer settings
  such as the dictionary size limit, page size, row-group size and statistics
  options change both recall and bytes.
- **Not measured:** nested and repeated columns, encrypted Parquet, data page
  v2 specifics, other compression codecs, real object-store latency, and a
  single run's variance. Wall times are from a warm local page cache.
- **Header probes.** Fetching page headers in 1 KiB probes is a choice. polars
  writes an offset index by default (pyarrow and duckdb do not). Using it would
  make the first-page reads exact, at the cost of one more range to fetch the
  index, and remove a few over-read kilobytes.

## Reproduce

From the repository root, with Python 3 and Rust installed:

```sh
cd spikes/parquet-pii
python3 -m venv gen/.venv
gen/.venv/bin/pip install --only-binary=:all: -r gen/requirements.txt
gen/.venv/bin/python gen/generate.py data      # ~15 s, ~850 MB, seeded
cargo run --release --locked -- data           # writes results/results.json
for s in setup encodings encodings_small S0 S1 S2 S3 supplementary verdict; do
  python3 report.py results/results.json $s
done
```

`data/`, `results/`, `target/` and the venv are git-ignored by
`spikes/parquet-pii/.gitignore`.

---

# Round 2: messy values, Spark, free text and small files

Round 1 left three questions: whether the results survive messy real-world
values (where junk lands in min/max statistics), whether they hold for Spark,
and whether free-text PII can be found at a known cost. Round 2 tests these
with new data, a fourth writer and a rule for each confidence level. Round 1's
results above are unchanged.

**Verdict:** both pre-registered criteria **pass** for all four writers. At S3,
every structured PII column was CONFIRMED with no false CONFIRMED flags, while
reading at most 8.1% of uncompressed bytes (DuckDB customers). At S4, embedded
emails were found at every rate down to 0.01% with no false flags. Two results
change the picture from round 1:

- **Statistics no longer do the work.** On messy data, S1 confirms nothing:
  75–83% of the statistics values are junk that cleaning removes, and too few
  are left to reach CONFIRMED. All CONFIRMED recall comes from the S3 pages.
- **Free text and small files cost far more.** S4 read 15–40% of uncompressed
  bytes, mostly on hashes and UUIDs that the 40-byte length rule counts as
  free text. In a lake of 10,000-row files, S3 read 89–100% of each file's
  bytes.

## Round 2 setup

Run on 2026-10-13 on the same machine as round 1.

**Writers**, each at its default settings:

- pyarrow 25.0.1, polars 1.44.2 and duckdb 1.5.6, as in round 1.
- **Spark 4.2.0** (parquet-java 1.17.0), in the official image
  `apache/spark:4.2.0-python3`, pinned by digest
  `sha256:fc64959c04bd87b0ac686be9aaa9008b69cdb1afc695400528279c8b01f43d89`
  (pushed 2026-07-16). It runs in `local[*]` mode with `--driver-memory 4g`.
  `gen/spark_write.py` reads a pyarrow copy of each table and writes it with
  `df.coalesce(1).write.parquet(...)`, so every output is a single file. No
  Parquet or Spark SQL option is changed. Timestamps came through as
  `TIMESTAMP_NTZ` (INT64 micros), not INT96, because the source column has no
  time zone.

The generator (`gen/generate_r2.py`, seeded) takes 18 seconds, and Spark's
writes take 41 seconds. The round-2 data takes 1.9 GB, and the Spark image
2.1 GB on disk. Round 1's data directory was deleted to stay within about
4 GB; it is seeded and can be regenerated.

**Data.**

- `customers` (1M rows) and `events` (2M rows) have round 1's columns and
  ground truth, with messy values. Full names now combine 3,000 first,
  1,000 middle (60% of rows) and 3,000 last names, so they are almost
  unique.
- `tickets` (1M rows) is the free-text sweep. Four columns embed an email in
  exactly 5% (`agent_notes`), 1% (`customer_reply`), 0.1%
  (`internal_comment`) and 0.01% (`resolution`) of rows. Emails sit at the
  start, middle or end of a note, and one in five is upper-case. `summary` is
  a free-text decoy with no emails, but with `@mentions`, "acme dot com" and
  "price @ 499".
- The **small-file lake** is `customers` split into 100 files of 10,000 rows
  per writer: 400 files in all.

Mess applied, as a share of all rows:

| Dataset | Column | Null | Empty | Whitespace-only | Placeholder | Malformed | Padded |
|---|---|---:|---:|---:|---:|---:|---:|
| customers | `full_name` | 12.0% | 1.5% | 1.0% | 2.0% | 0.0% | 4.2% |
| customers | `email` | 10.0% | 1.5% | 1.0% | 2.0% | 2.0% | 4.2% |
| customers | `contact` | 20.0% | 1.5% | 1.0% | 2.0% | 2.0% | 3.7% |
| customers | `pan` | 29.9% | 1.5% | 1.0% | 2.0% | 2.0% | 3.2% |
| customers | `c9` | 25.0% | 1.5% | 1.0% | 2.0% | 2.0% | 3.4% |
| customers | `notes` | 15.0% | 1.5% | 1.0% | 2.0% | 0.0% | 4.1% |
| customers | `dob` | 15.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| events | `customer_email` | 10.0% | 1.5% | 1.0% | 2.0% | 2.0% | 4.2% |
| events | `src` | 20.0% | 1.5% | 1.0% | 2.0% | 2.0% | 3.6% |
| events | `card` | 30.0% | 1.5% | 1.0% | 2.0% | 2.0% | 3.2% |
| tickets | `agent_notes` | 10.0% | 1.5% | 1.0% | 2.0% | 0.0% | 4.3% |
| tickets | `customer_reply` | 10.0% | 1.5% | 1.0% | 2.0% | 0.0% | 4.3% |
| tickets | `internal_comment` | 10.0% | 1.5% | 1.0% | 2.0% | 0.0% | 4.3% |
| tickets | `resolution` | 10.0% | 1.5% | 1.0% | 2.0% | 0.0% | 4.3% |
| tickets | `summary` | 10.0% | 1.5% | 1.0% | 2.0% | 0.0% | 4.3% |

- *Placeholders* are `N/A`, `unknown`, `-`, `0000000000` and `test@test.com`.
- *Malformed* values are:
  - an email with its `@` removed;
  - a phone cut to 5–8 digits;
  - PAN or Aadhaar missing its last character;
  - a card cut to 11–12 digits;
  - an IPv4 address with three octets, or an IPv6 address with a bad hextet.
- *Padded* values have leading or trailing spaces or tabs.
- *Mixed case:*
  - 10% of emails are upper-case or capitalized;
  - 10% of names are upper- or lower-case;
  - 5% of PANs are lower-case, which the round 1 PAN validator rejects;
  - 10% of IPs are upper-case, which only affects IPv6 hex.
- `customers.notes` embeds an email in 3.82% of rows after the mess (5%
  before it). The manifest records the exact count for every column and lake
  file.

**Junk in the statistics.** Empty strings sort first and `unknown` sorts after
digits and upper-case letters. So almost every row group's min or max, and
often both, is junk:

| File | Writer | Statistics values (structured PII columns) | Removed by cleaning | Invalid after cleaning |
|---|---|---:|---:|---:|
| customers 1,000,000 | pyarrow | 8 | 6 | 1 |
| customers 1,000,000 | polars | 64 | 48 | 8 |
| customers 1,000,000 | duckdb | 72 | 54 | 9 |
| customers 1,000,000 | spark | 16 | 12 | 2 |
| events 2,000,000 | pyarrow | 12 | 10 | 1 |
| events 2,000,000 | polars | 96 | 80 | 1 |
| events 2,000,000 | duckdb | 102 | 85 | 1 |
| events 2,000,000 | spark | 12 | 10 | 1 |

"Invalid after cleaning" values are malformed or lower-case values that
survived cleaning and fail the validator.

**Detection rules, declared in `src/round2.rs` before the first run:**

- **Cleaning.** Before any share is computed, trim whitespace, and drop nulls,
  empty and whitespace-only values, and the five placeholders (ignoring ASCII
  case).
- **Structured types:** EMAIL, PHONE, IN_PAN, IN_AADHAAR, CARD_NUMBER,
  IP_ADDRESS, with round 1's validators and strictness order. The value rule
  passes when at least 80% of cleaned values validate.
  - **CONFIRMED**: the value rule passes on at least 30 cleaned values.
  - **LIKELY**: the value rule passes on fewer than 30, or a name hint plus at
    least one validating value.
  - **POSSIBLE**: a name hint only.
- **Free text:** a BYTE_ARRAY column whose summed `total_uncompressed_size`
  divided by summed `num_values` exceeds 40 bytes.
  - It is flagged EMAIL_EMBEDDED when at least one cleaned sampled value
    contains an email (round 1's unanchored regex).
  - Round 1's 80% rule no longer applies to EMAIL_EMBEDDED.

**Strategies**, cumulative:

- **S1**: footer plus min/max statistics of every row group.
- **S3**: S1 plus row group 0's dictionary pages, plus the first data page of
  each column without a dictionary (round 1's S3).
- **S4**: S3 plus every page of every row group of the free-text columns.
  - Each column chunk is fetched as one range.
  - For those columns this replaces the S3 reads, so no byte is counted
    twice.
  - This is why S4 sometimes needs *fewer* ranges than S3: one chunk read
    replaces 1 KiB header probes.

**Metrics** are round 1's, plus recall and precision at each confidence
level.

- *Recall at level L*: the share of structured value-detectable PII columns
  (4 in customers: `email`, `contact`, `pan`, `c9`; 3 in events) flagged with
  their true type at L or stronger.
- *Precision at L*: the share of all flags at L or stronger, including
  name-only PERSON_NAME and DATE_OF_BIRTH hints, whose type is the true type.
- Round 1's "value recall" corresponds most closely to ≥LIKELY, and "recall
  incl. names" to ≥POSSIBLE.

Files:

| File | Writer | Rows | Row groups | File size | Uncompressed (column chunks) |
|---|---|---:|---:|---:|---:|
| `pyarrow/customers_1m.parquet` | pyarrow | 1,000,000 | 1 | 148.8 MB | 221.2 MB |
| `polars/customers_1m.parquet` | polars | 1,000,000 | 8 | 91.3 MB | 223.3 MB |
| `duckdb/customers_1m.parquet` | duckdb | 1,000,000 | 9 | 148.2 MB | 220.6 MB |
| `spark/customers_1m.parquet` | spark | 1,000,000 | 2 | 150.8 MB | 221.9 MB |
| `pyarrow/events_2m.parquet` | pyarrow | 2,000,000 | 2 | 181.4 MB | 238.4 MB |
| `polars/events_2m.parquet` | polars | 2,000,000 | 16 | 117.6 MB | 252.3 MB |
| `duckdb/events_2m.parquet` | duckdb | 2,000,000 | 17 | 182.2 MB | 240.4 MB |
| `spark/events_2m.parquet` | spark | 2,000,000 | 2 | 183.8 MB | 237.7 MB |
| `pyarrow/tickets_1m.parquet` | pyarrow | 1,000,000 | 1 | 73.7 MB | 242.4 MB |
| `polars/tickets_1m.parquet` | polars | 1,000,000 | 8 | 45.0 MB | 244.0 MB |
| `duckdb/tickets_1m.parquet` | duckdb | 1,000,000 | 9 | 73.2 MB | 244.1 MB |
| `spark/tickets_1m.parquet` | spark | 1,000,000 | 1 | 73.2 MB | 241.7 MB |

## Round 2 encodings (first row group)

| Dataset | Column | Ground truth | pyarrow | polars | duckdb | spark |
|---|---|---|---|---|---|---|
| customers (1,000,000) | `full_name` | PERSON_NAME | dictionary, then PLAIN (763 KB dict) | plain | plain | plain |
| customers (1,000,000) | `email` | EMAIL | dictionary, then PLAIN (608 KB dict) | plain | plain | plain |
| customers (1,000,000) | `contact` | PHONE | dictionary, then PLAIN (665 KB dict) | plain | plain | plain |
| customers (1,000,000) | `dob` | DATE_OF_BIRTH | dictionary (83 KB dict) | dictionary (55 KB dict; page stats absent) | dictionary (83 KB dict; page stats absent) | plain |
| customers (1,000,000) | `pan` | IN_PAN | dictionary, then PLAIN (850 KB dict) | dictionary (608 KB dict; page stats absent) | plain | plain |
| customers (1,000,000) | `c9` | IN_AADHAAR | dictionary, then PLAIN (686 KB dict) | dictionary (561 KB dict; page stats absent) | plain | plain |
| customers (1,000,000) | `notes` | EMAIL_EMBEDDED | dictionary, then PLAIN (290 KB dict) | plain | plain | plain |
| events (2,000,000) | `customer_email` | EMAIL | dictionary, then PLAIN (662 KB dict) | plain | plain | plain |
| events (2,000,000) | `src` | IP_ADDRESS | dictionary, then PLAIN (720 KB dict) | dictionary (908 KB dict; page stats absent) | plain | plain |
| events (2,000,000) | `card` | CARD_NUMBER | dictionary, then PLAIN (784 KB dict) | dictionary (760 KB dict; page stats absent) | plain | plain |
| tickets (1,000,000) | `agent_notes` | EMAIL_EMBEDDED | dictionary, then PLAIN (289 KB dict) | plain | plain | plain |
| tickets (1,000,000) | `customer_reply` | EMAIL_EMBEDDED | dictionary, then PLAIN (280 KB dict) | plain | plain | plain |
| tickets (1,000,000) | `internal_comment` | EMAIL_EMBEDDED | dictionary, then PLAIN (275 KB dict) | plain | plain | plain |
| tickets (1,000,000) | `resolution` | EMAIL_EMBEDDED | dictionary, then PLAIN (274 KB dict) | plain | plain | plain |
| lake file 000 (10,000) | `full_name` | PERSON_NAME | dictionary (118 KB dict) | plain | plain | plain |
| lake file 000 (10,000) | `email` | EMAIL | dictionary (154 KB dict) | plain | plain | plain |
| lake file 000 (10,000) | `contact` | PHONE | dictionary (81 KB dict) | plain | plain | plain |
| lake file 000 (10,000) | `dob` | DATE_OF_BIRTH | dictionary (28 KB dict) | dictionary (18 KB dict; page stats absent) | plain | plain |
| lake file 000 (10,000) | `pan` | IN_PAN | dictionary (75 KB dict) | dictionary (49 KB dict; page stats absent) | plain | plain |
| lake file 000 (10,000) | `c9` | IN_AADHAAR | dictionary (74 KB dict) | dictionary (44 KB dict; page stats absent) | plain | plain |
| lake file 000 (10,000) | `notes` | EMAIL_EMBEDDED | dictionary (145 KB dict) | plain | plain | plain |

- **Spark** writes no dictionary page for any high-cardinality column, and
  none for `dob` either; only `city`, `plan` and the low-cardinality event
  columns get one. Its pages hold at most 20,000 rows by default, so its S3
  first pages are small.
- **polars** chose dictionaries for `pan`, `c9`, `src` and `card` this time,
  though in round 1 it wrote all four plain. Its choice depends on the data.
- **DuckDB** again writes one page per column per row group (about 123k
  rows), which makes its S3 the most expensive.
- **pyarrow** behaves as in round 1. With high-cardinality names, `full_name`
  now also falls back to PLAIN.

## Round 2 results: structured PII

### S1: footer plus min/max statistics (report only)

| File | Writer | CONFIRMED recall | CONFIRMED precision | ≥LIKELY recall | ≥LIKELY precision | ≥POSSIBLE recall | ≥POSSIBLE precision | Read | % of file | % of uncompressed | Ranges | Wall ms |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| customers 1,000,000 | pyarrow | 0% (0/4) | n/a (0 flags) | 25% (1/4) | 100% (1/1) | 50% (2/4) | 80% (4/5) | 2.8 KB | 0.002% | 0.001% | 2 | 0.0 |
| customers 1,000,000 | polars | 0% (0/4) | n/a (0 flags) | 25% (1/4) | 100% (1/1) | 50% (2/4) | 80% (4/5) | 10.6 KB | 0.012% | 0.005% | 2 | 0.0 |
| customers 1,000,000 | duckdb | 0% (0/4) | n/a (0 flags) | 25% (1/4) | 100% (1/1) | 50% (2/4) | 80% (4/5) | 13.1 KB | 0.009% | 0.006% | 2 | 0.0 |
| customers 1,000,000 | spark | 0% (0/4) | n/a (0 flags) | 25% (1/4) | 100% (1/1) | 50% (2/4) | 80% (4/5) | 4.2 KB | 0.003% | 0.002% | 2 | 0.0 |
| events 2,000,000 | pyarrow | 0% (0/3) | n/a (0 flags) | 33% (1/3) | 100% (1/1) | 67% (2/3) | 100% (2/2) | 3.3 KB | 0.002% | 0.001% | 2 | 0.0 |
| events 2,000,000 | polars | 0% (0/3) | n/a (0 flags) | 33% (1/3) | 100% (1/1) | 67% (2/3) | 100% (2/2) | 15.5 KB | 0.013% | 0.006% | 2 | 0.1 |
| events 2,000,000 | duckdb | 0% (0/3) | n/a (0 flags) | 33% (1/3) | 100% (1/1) | 67% (2/3) | 100% (2/2) | 19.1 KB | 0.010% | 0.008% | 2 | 0.0 |
| events 2,000,000 | spark | 0% (0/3) | n/a (0 flags) | 33% (1/3) | 100% (1/1) | 67% (2/3) | 100% (2/2) | 3.3 KB | 0.002% | 0.001% | 2 | 0.0 |

S1 reads under 20 KB per file but confirms nothing.

- The one LIKELY hit is `email`/`customer_email`, from the few statistics
  values that survive cleaning. Every other structured column's surviving
  values are too few, malformed, or lower-case PAN.
- ≥POSSIBLE recall comes from the honest names (`email`, `pan`, `card`).
- The decoy `email_sha256` is the one false flag, from its name.
- Round 1's limitation is confirmed: the statistics were an upper bound,
  and with junk in the data they find almost nothing.

### S3: plus dictionary pages and first data pages

| File | Writer | CONFIRMED recall | CONFIRMED precision | ≥LIKELY recall | ≥LIKELY precision | ≥POSSIBLE recall | ≥POSSIBLE precision | Read | % of file | % of uncompressed | Ranges | Wall ms |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| customers 1,000,000 | pyarrow | 100% (4/4) | 100% (4/4) | 100% (4/4) | 100% (4/4) | 100% (4/4) | 86% (6/7) | 6.6 MB | 4.439% | 2.985% | 14 | 33.4 |
| customers 1,000,000 | polars | 100% (4/4) | 100% (4/4) | 100% (4/4) | 100% (4/4) | 100% (4/4) | 86% (6/7) | 3.8 MB | 4.214% | 1.722% | 21 | 16.1 |
| customers 1,000,000 | duckdb | 100% (4/4) | 100% (4/4) | 100% (4/4) | 100% (4/4) | 100% (4/4) | 86% (6/7) | 17.9 MB | 12.060% | 8.101% | 23 | 36.3 |
| customers 1,000,000 | spark | 100% (4/4) | 100% (4/4) | 100% (4/4) | 100% (4/4) | 100% (4/4) | 86% (6/7) | 2.6 MB | 1.738% | 1.181% | 24 | 10.0 |
| events 2,000,000 | pyarrow | 100% (3/3) | 100% (3/3) | 100% (3/3) | 100% (3/3) | 100% (3/3) | 100% (3/3) | 4.0 MB | 2.223% | 1.691% | 11 | 10.0 |
| events 2,000,000 | polars | 100% (3/3) | 100% (3/3) | 100% (3/3) | 100% (3/3) | 100% (3/3) | 100% (3/3) | 3.2 MB | 2.745% | 1.280% | 15 | 17.8 |
| events 2,000,000 | duckdb | 100% (3/3) | 100% (3/3) | 100% (3/3) | 100% (3/3) | 100% (3/3) | 100% (3/3) | 10.8 MB | 5.908% | 4.479% | 16 | 27.7 |
| events 2,000,000 | spark | 100% (3/3) | 100% (3/3) | 100% (3/3) | 100% (3/3) | 100% (3/3) | 100% (3/3) | 1.9 MB | 1.053% | 0.814% | 16 | 5.4 |

- **Every structured column is CONFIRMED by every writer, with no false
  CONFIRMED flags.** The ≥POSSIBLE precision of 86% is the `email_sha256`
  name hint, as in round 1.
- **Costs.** Spark is the cheapest, at 0.8–1.2% of uncompressed. DuckDB is
  the most expensive, at 8.1% on customers, close to the 10% limit, and only
  because the file has 9 row groups.

At S4 the structured results are identical to S3, since S4 adds only
free-text columns; its bytes are in the free-text section below.

## Round 2 results: free text

| Writer | Column | Rows with an email | S1 | S3 | S3 pages only (diagnostic) | S4 | Values read from pages at S3 | Expected emails among them |
|---|---|---:|---|---|---|---|---:|---:|
| pyarrow | customers.`notes` | 3.82% | flagged | flagged | flagged | flagged | 16,061 | 613.7 |
| pyarrow | tickets.`agent_notes` | 5.00% | flagged | flagged | flagged | flagged | 15,900 | 795.0 |
| pyarrow | tickets.`customer_reply` | 1.00% | flagged | flagged | flagged | flagged | 16,653 | 166.5 |
| pyarrow | tickets.`internal_comment` | 0.10% | flagged | flagged | flagged | flagged | 16,689 | 16.7 |
| pyarrow | tickets.`resolution` | 0.01% | flagged | flagged | flagged | flagged | 16,641 | 1.7 |
| polars | customers.`notes` | 3.82% | flagged | flagged | flagged | flagged | 15,033 | 574.4 |
| polars | tickets.`agent_notes` | 5.00% | flagged | flagged | flagged | flagged | 15,086 | 754.3 |
| polars | tickets.`customer_reply` | 1.00% | flagged | flagged | flagged | flagged | 15,768 | 157.7 |
| polars | tickets.`internal_comment` | 0.10% | flagged | flagged | flagged | flagged | 15,763 | 15.8 |
| polars | tickets.`resolution` | 0.01% | flagged | flagged | flagged | flagged | 15,751 | 1.6 |
| duckdb | customers.`notes` | 3.82% | flagged | flagged | flagged | flagged | 104,338 | 3986.7 |
| duckdb | tickets.`agent_notes` | 5.00% | flagged | flagged | flagged | flagged | 111,304 | 5565.2 |
| duckdb | tickets.`customer_reply` | 1.00% | flagged | flagged | flagged | flagged | 110,676 | 1106.8 |
| duckdb | tickets.`internal_comment` | 0.10% | flagged | flagged | flagged | flagged | 110,549 | 110.5 |
| duckdb | tickets.`resolution` | 0.01% | flagged | flagged | flagged | flagged | 110,533 | 11.1 |
| spark | customers.`notes` | 3.82% | flagged | flagged | flagged | flagged | 15,473 | 591.2 |
| spark | tickets.`agent_notes` | 5.00% | flagged | flagged | flagged | flagged | 15,419 | 771.0 |
| spark | tickets.`customer_reply` | 1.00% | flagged | flagged | flagged | flagged | 15,340 | 153.4 |
| spark | tickets.`internal_comment` | 0.10% | flagged | flagged | flagged | flagged | 16,237 | 16.2 |
| spark | tickets.`resolution` | 0.01% | flagged | flagged | flagged | flagged | 16,229 | 1.6 |

| Writer | Free-text columns (all large files) | Flagged at S4 | Correct | S4 precision | Sweep columns ≥0.1% found at S4 | 0.01% column found at S4 |
|---|---|---:|---:|---:|---|---|
| pyarrow | `customers.email_sha256`, `customers.notes`, `events.event_id`, `tickets.agent_notes`, `tickets.customer_reply`, `tickets.internal_comment`, `tickets.resolution` | 5 | 5 | 100% | 4/4 | yes |
| polars | `customers.email_sha256`, `customers.notes`, `events.event_id`, `tickets.agent_notes`, `tickets.customer_reply`, `tickets.internal_comment`, `tickets.resolution` | 5 | 5 | 100% | 4/4 | yes |
| duckdb | `customers.email_sha256`, `customers.notes`, `events.event_id`, `tickets.agent_notes`, `tickets.customer_reply`, `tickets.internal_comment`, `tickets.resolution` | 5 | 5 | 100% | 4/4 | yes |
| spark | `customers.email_sha256`, `customers.notes`, `events.event_id`, `tickets.agent_notes`, `tickets.customer_reply`, `tickets.internal_comment`, `tickets.resolution` | 5 | 5 | 100% | 4/4 | yes |

- **The S1 and S3 "flagged" entries are an artifact of the data, not a
  finding.** One of my templates starts a note with a lower-case email
  ("zuzu.visawa…@fintech.in wrote in: …"). Lower case sorts after the
  capitalized prose of every other note, so in every row group the column's
  max statistic is such a value. Real free text has no reason to do this
  reliably. S1 and S3 free-text detection here should be read as
  "unmeasured".
- **The pages-only column is a diagnostic added after the first run**, to
  separate the page sample from that artifact. It applies the same rule to
  the S3 page values alone.
  - It found every column. DuckDB's first page holds about 110,000 values,
    so 11 emails are expected even at 0.01%.
  - For pyarrow, polars and Spark, finding the 0.01% column was luck. Their
    S3 sample holds about 16,000 values (1.6 emails expected), but the first
    16,700 rows happen to contain 7 of the column's 100 emails.
  - All four writers keep the same row order, so this is one draw, not
    several.
- **S4 finds everything.** It reads every value of the free-text columns, so
  the rate does not matter. The cost is the whole chunk:

| File | Writer | S3 read | S4 read | S4 extra, by free-text column (compressed chunk bytes) | S4 % of uncompressed |
|---|---|---:|---:|---|---:|
| customers 1,000,000 | pyarrow | 6.6 MB | 86.0 MB | `email_sha256` 65.8 MB, `notes` 15.0 MB | 38.9% |
| customers 1,000,000 | polars | 3.8 MB | 47.5 MB | `email_sha256` 35.3 MB, `notes` 9.0 MB | 21.3% |
| customers 1,000,000 | duckdb | 17.9 MB | 88.5 MB | `email_sha256` 65.7 MB, `notes` 14.9 MB | 40.1% |
| customers 1,000,000 | spark | 2.6 MB | 82.5 MB | `email_sha256` 66.0 MB, `notes` 15.1 MB | 37.2% |
| events 2,000,000 | pyarrow | 4.0 MB | 74.6 MB | `event_id` 71.5 MB | 31.3% |
| events 2,000,000 | polars | 3.2 MB | 43.8 MB | `event_id` 41.1 MB | 17.4% |
| events 2,000,000 | duckdb | 10.8 MB | 77.7 MB | `event_id` 71.4 MB | 32.3% |
| events 2,000,000 | spark | 1.9 MB | 73.4 MB | `event_id` 72.2 MB | 30.9% |
| tickets 1,000,000 | pyarrow | 2.7 MB | 61.4 MB | `agent_notes` 16.1 MB, `customer_reply` 14.8 MB, `internal_comment` 14.5 MB, `resolution` 14.4 MB | 25.3% |
| tickets 1,000,000 | polars | 1.6 MB | 36.5 MB | `agent_notes` 9.8 MB, `customer_reply` 8.8 MB, `internal_comment` 8.5 MB, `resolution` 8.5 MB | 15.0% |
| tickets 1,000,000 | duckdb | 8.8 MB | 61.0 MB | `agent_notes` 16.0 MB, `customer_reply` 14.7 MB, `internal_comment` 14.4 MB, `resolution` 14.3 MB | 25.0% |
| tickets 1,000,000 | spark | 1.4 MB | 60.2 MB | `agent_notes` 16.1 MB, `customer_reply` 14.8 MB, `internal_comment` 14.5 MB, `resolution` 14.4 MB | 24.9% |

Most S4 bytes are not PII at all.

- **The length rule counts hex digests and UUIDs as free text:**
  `email_sha256` averages 68 stored bytes, and `event_id` 40.0–40.1 (36
  characters plus a 4-byte length prefix, just over the line).
- **Those two columns are 65–72 MB of the S4 read** on the pyarrow, DuckDB
  and Spark files.
- **Without them,** S4 on customers would add only the `notes` chunk,
  9–15 MB or about 4–7% of uncompressed, and on events nothing.
- **The `summary` decoy was never treated as free text.** It has about 1,700
  distinct values, so every writer dictionary-encoded it, and its average
  stored size is far below 40 bytes. The 100% precision is therefore tested
  only against digests and UUIDs, which never contain `@`.

## Round 2 results: the small-file lake (report only)

| Writer | Strategy | Files | Lake file bytes | Lake uncompressed | Bytes read | % of file bytes | % of uncompressed | Range reads | CONFIRMED recall (mean, min) | CONFIRMED precision (min) | `notes` flagged EMAIL_EMBEDDED |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|
| pyarrow | S1 | 100 | 163.1 MB | 234.3 MB | 264.3 KB | 0.2% | 0.1% | 200 | 0%, 0% | n/a | 100/100 files |
| pyarrow | S3 | 100 | 163.1 MB | 234.3 MB | 146.0 MB | 89.5% | 62.3% | 1,400 | 100%, 100% | 100% | 100/100 files |
| pyarrow | S4 | 100 | 163.1 MB | 234.3 MB | 149.3 MB | 91.6% | 63.7% | 1,400 | 100%, 100% | 100% | 100/100 files |
| polars | S1 | 100 | 93.3 MB | 224.6 MB | 227.1 KB | 0.2% | 0.1% | 200 | 0%, 0% | n/a | 100/100 files |
| polars | S3 | 100 | 93.3 MB | 224.6 MB | 88.3 MB | 94.6% | 39.3% | 2,080 | 100%, 100% | 100% | 100/100 files |
| polars | S4 | 100 | 93.3 MB | 224.6 MB | 88.1 MB | 94.4% | 39.2% | 1,880 | 100%, 100% | 100% | 100/100 files |
| duckdb | S1 | 100 | 149.8 MB | 221.9 MB | 168.0 KB | 0.1% | 0.1% | 200 | 0%, 0% | n/a | 100/100 files |
| duckdb | S3 | 100 | 149.8 MB | 221.9 MB | 149.6 MB | 99.9% | 67.4% | 2,400 | 100%, 100% | 100% | 100/100 files |
| duckdb | S4 | 100 | 149.8 MB | 221.9 MB | 149.4 MB | 99.7% | 67.3% | 2,200 | 100%, 100% | 100% | 100/100 files |
| spark | S1 | 100 | 151.4 MB | 222.0 MB | 262.4 KB | 0.2% | 0.1% | 200 | 0%, 0% | n/a | 100/100 files |
| spark | S3 | 100 | 151.4 MB | 222.0 MB | 151.2 MB | 99.9% | 68.1% | 2,400 | 100%, 100% | 100% | 100/100 files |
| spark | S4 | 100 | 151.4 MB | 222.0 MB | 151.0 MB | 99.7% | 68.0% | 2,200 | 100%, 100% | 100% | 100/100 files |

At 10,000 rows, a first page or a dictionary is most of a column chunk.

- **S3 reads 89–100% of the lake's file bytes (39–68% of uncompressed),** in
  14–24 range reads per file.
  - DuckDB and Spark write a single page per column, so their S3 reads every
    byte.
  - Reading each file whole would cost about the same bytes in one request
    instead of 14–24.
- **Recall and precision are perfect** at S3 in every file: 10,000-row
  samples are plenty.
- **S1 still confirms nothing** in any file.
- **`notes` is flagged in all 100 files by every writer, even at S1,** by
  the same max-statistic artifact.

## Round 2 verdict against the pre-registered criteria

**Primary:** for every writer including Spark, on the messy 1M- and 2M-row
files, S3 reaches at least 90% recall at CONFIRMED on the structured
value-detectable columns, with at least 95% precision, reading at most 10% of
uncompressed bytes.

**Secondary:** S4 detects embedded emails at rates down to 0.1% with at least
95% precision. Bytes are reported, with no threshold.

**Primary** (S3, CONFIRMED, structured columns):

| Writer | File | Recall | Precision | % of uncompressed | Result |
|---|---|---:|---:|---:|---|
| pyarrow | customers 1,000,000 | 100% (4/4) | 100% (4/4) | 2.99% | **pass** |
| pyarrow | events 2,000,000 | 100% (3/3) | 100% (3/3) | 1.69% | **pass** |
| polars | customers 1,000,000 | 100% (4/4) | 100% (4/4) | 1.72% | **pass** |
| polars | events 2,000,000 | 100% (3/3) | 100% (3/3) | 1.28% | **pass** |
| duckdb | customers 1,000,000 | 100% (4/4) | 100% (4/4) | 8.10% | **pass** |
| duckdb | events 2,000,000 | 100% (3/3) | 100% (3/3) | 4.48% | **pass** |
| spark | customers 1,000,000 | 100% (4/4) | 100% (4/4) | 1.18% | **pass** |
| spark | events 2,000,000 | 100% (3/3) | 100% (3/3) | 0.81% | **pass** |

**Secondary** (S4, EMAIL_EMBEDDED, rates down to 0.1%):

| Writer | Columns at ≥0.1% found | Precision over all large files | Result |
|---|---|---:|---|
| pyarrow | 4/4 | 100% (5/5) | **pass** |
| polars | 4/4 | 100% (5/5) | **pass** |
| duckdb | 4/4 | 100% (5/5) | **pass** |
| spark | 4/4 | 100% (5/5) | **pass** |

**Both criteria pass for all four writers.**

- **Primary.** Structured PII on messy data is found with full confidence
  from dictionaries and first pages, at 0.8–8.1% of uncompressed bytes.
- **Secondary.** Free text is found at every tested rate, but only by reading
  it all. That cost 15–40% of uncompressed per file, and most of it went on
  columns that are not text.

## Round 2 limitations

- **Cleaning is tuned to the junk.**
  - The placeholder list is exactly the list the generator used, so cleaning
    removes all the junk by construction.
  - Real lakes have placeholders nobody listed (`NULL`, `none`, `999999`,
    `xxx`), and they would count against the 80% rule.
  - The mess is also spread uniformly. Real junk clusters, for example a
    legacy partition that is all `N/A`, and could fill a whole first page or
    row group 0.
- **Free-text precision is barely tested.** The only free-text decoys that
  reached the rule were hex digests and UUIDs. Email-like tokens in real
  prose, such as `logo@2x.png`, `git@github.com` or quoted headers, were not
  generated. The "at least one value" rule will flag them.
- **The free-text rule depends on the writer.** It uses stored size, so a
  dictionary-encoded text column (like `summary`) is never treated as free
  text, and a hash or UUID column always is. Average length alone is a weak
  signal.
- **The S1 and S3 free-text results are an artifact** of the lower-case-first
  template (see above), and the 0.01% pages-only hit was luck.
- **One Spark configuration:** Spark 4.2.0 with parquet-java 1.17.0, local
  mode, `coalesce(1)`, and no Delta, Iceberg or Hive table settings. Older
  Spark (parquet-mr 1.12–1.13) and table formats with their own writer
  defaults were not tested.
- **Unchanged from round 1:**
  - synthetic data;
  - row group 0 sampling bias;
  - name-only types;
  - one configuration per writer;
  - warm-cache local wall times;
  - nested columns, encryption and real object-store latency not measured.

## Round 2 reproduce

From `spikes/parquet-pii`, with the round 1 venv and Docker:

```sh
gen/.venv/bin/python gen/generate_r2.py data2            # ~20 s, ~1.7 GB with Spark sources, seeded
docker run --rm -v "$PWD/data2:/data" -v "$PWD/gen:/gen:ro" \
  apache/spark@sha256:fc64959c04bd87b0ac686be9aaa9008b69cdb1afc695400528279c8b01f43d89 \
  /opt/spark/bin/spark-submit --driver-memory 4g /gen/spark_write.py /data   # ~40 s
rm -rf data2/_spark_src
cargo run --release --locked -- round2 data2              # writes results/round2.json
for s in setup mess junk encodings S1 S3 S4 freetext s4bytes lake verdict; do
  gen/.venv/bin/python report_r2.py results/round2.json data2 $s
done
```

`data2/` is git-ignored.
