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
