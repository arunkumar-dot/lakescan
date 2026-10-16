# Parquet fixtures for content scanning

Small, committed Parquet files used by the unit tests
(`src/content/tests.rs`, read straight from disk) and the end-to-end tests
(`tests/e2e_pii.rs`, uploaded to moto by `examples/seed_local.rs`). They are
synthetic: every name, email, number and address is generated.

## Reserved values

Wherever a reserved range exists, the fixtures use only values from it, so
no value can belong to a real person, host, phone line or card:

- Emails: the domains `example.com`, `example.org` and `example.net`
  (RFC 2606) and names under `.test` (RFC 6761).
- IPv4: `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24` (RFC 5737).
  IPv6: `2001:db8::/32` (RFC 3849).
- US phone numbers: `+1 415 555-0100` to `555-0199`, the range the North
  American Numbering Plan reserves for fiction.
- Card numbers: the card networks' published test numbers, eleven of them
  (four Visa, three Mastercard, two American Express, two Discover), so no
  single number is more than about 10% of a column. LakeScan drops a value
  that makes up over half of a sample, so a column of one test number
  would test nothing.

Aadhaar numbers, PAN numbers and Indian mobile numbers have no reserved
ranges. Those are synthetic and randomly generated: Verhoeff-valid
12-digit numbers, PAN-shaped strings, and 10-digit numbers starting 6 to
9. Any match with a real number is a coincidence. Names are random
combinations of common first and last names.

| File | Writer | Rows | Row groups |
|---|---|---:|---:|
| `pyarrow/customers.parquet` | pyarrow 25.0.1 | 12,000 | 3 |
| `polars/customers.parquet` | polars 1.44.2 | 12,000 | 3 |
| `duckdb/customers.parquet` | duckdb 1.5.6 | 12,000 | 3 |
| `spark/customers.parquet` | Spark 4.2.0 (parquet-java 1.17.0) | 12,000 | 1 |
| `gzip/pyarrow/customers.parquet` | pyarrow, GZIP | 12,000 | 3 |
| `gzip/spark/customers.parquet` | Spark, GZIP | 12,000 | 1 |
| `brotli/pyarrow/customers.parquet` | pyarrow, BROTLI | 12,000 | 3 |
| `escalation.parquet` | pyarrow | 8,000 | 4 |
| `bad/truncated.parquet` | the first 60% of `pyarrow/customers.parquet` | | |
| `bad/not_parquet.parquet` | a CSV file named `.parquet` | | |
| `skipped/too_large.parquet` | pyarrow, ZSTD, no dictionary | 16,000 | 1 |

Every writer runs at its defaults, except that the row-group size is set to
4,000 rows for pyarrow, polars and DuckDB, so that partial reads and
escalation have several row groups to work with. Spark writes one row group.
The `gzip/` and `brotli/` files hold the same rows as the others, with only
the codec changed (Athena writes GZIP Parquet by default for Hive tables).

Spark writes no dictionary for its high-cardinality columns (`email`,
`billing.email`, `pan`, `mobile_no`, `aadhaar_no`), so those are read from
plain-encoded data pages. `contact`, `card_number` and `last_login_ip` draw
from small reserved ranges, so Spark dictionary-encodes them, as the other
writers do.

## Ground truth

`customers.parquet`, every writer:

| Column | Type | Holds | Expected finding |
|---|---|---|---|
| `customer_id` | int64 | 1 to 12,000 | none |
| `full_name` | string | names | `pii-person-name`, likely (name only) |
| `email` | string | emails | `pii-email`, confirmed |
| `contact` | string | phones: `+91 98765 43210`, `+919876543210`, 10-digit, US E.164 in `+1415555` `0100`-`0199` | `pii-phone`, confirmed |
| `mobile_no` | int64 | 10-digit Indian mobiles | `pii-phone`, confirmed |
| `aadhaar_no` | int64 | Verhoeff-valid Aadhaar numbers | `pii-in-aadhaar`, confirmed |
| `pan` | string | PAN numbers | `pii-in-pan`, confirmed |
| `card_number` | string | published test numbers (Visa, Mastercard, American Express, Discover), 25% space-grouped as printed (4-6-5 for American Express) | `pii-card-number`, confirmed |
| `last_login_ip` | string | IPv4 from the RFC 5737 ranges (80%), IPv6 from `2001:db8::/32` (20%) | `pii-ip-address`, confirmed |
| `dob` | date | dates of birth | `pii-date-of-birth`, likely (name only) |
| `email_sha256` | string | SHA-256 hex digests of the emails: a decoy | none |
| `billing` | struct | `email` (emails), `city` | `billing.email`: `pii-email`, confirmed |
| `tags` | list of strings | | skipped (repeated) |
| `amount` | double | | skipped (unsupported type) |
| `signup_ts` | timestamp | | none |
| `notes` | string | free text without personal data | none |

The string PII columns are messy: 10–30% nulls, 2% blank strings, 2%
placeholders, 2% malformed values (an email without `@`, a phone cut to six
characters), 5% padded with whitespace, and 10% re-cased: upper-case names
and emails, and lower-case PANs (which LakeScan validates case-insensitively). The
placeholders are `N/A`, `unknown`, `-`, `0000000000`, `NOT PROVIDED` and
`999`. That list deliberately differs from LakeScan's cleaning list:
`NOT PROVIDED` and `999` are not on it, and stay in the sample as
non-matching values. The integer columns have 15–25% nulls.

`escalation.parquet`: `contact_email` is only nulls and junk (`N/A`, `""`,
blanks, `-`, `0000000000`) in row group 0, and emails in row groups 1 to 3.
Expected: `pii-email`, confirmed, found only by escalating past row group
0.

`bad/truncated.parquet` is `content-not-scanned` with reason `unreadable`,
and `bad/not_parquet.parquet` with reason `not-parquet`.

`skipped/too_large.parquet`: `email` holds ~600-byte emails in one 9.5 MB
data page (over LakeScan's 8 MiB page cap; ZSTD keeps the file at ~30 KB),
and `amount` is a double. Expected: `email` skipped as page-too-large, so
`content-not-scanned` with reason `no-column-examined`.

## Regenerating

With Python 3 and Docker:

```sh
cd tests/fixtures/parquet
python3 -m venv .venv
.venv/bin/pip install --only-binary=:all: -r requirements.txt
.venv/bin/python generate.py "$PWD"
docker run --rm -v "$PWD:/data" \
  apache/spark@sha256:fc64959c04bd87b0ac686be9aaa9008b69cdb1afc695400528279c8b01f43d89 \
  /opt/spark/bin/spark-submit --driver-memory 2g /data/spark_write.py /data
rm -rf _spark_src .venv
```

`spark_write.py` writes `spark/customers.parquet` and
`gzip/spark/customers.parquet`. Spark's output bytes differ from run to run
(the values do not), so the committed Spark files need not be rewritten
when only another fixture changes.

The Spark image is `apache/spark:4.2.0-python3`, pinned by digest. The
generator is seeded, so the values are reproducible with the pinned
versions in `requirements.txt`. The file bytes can differ with other writer
versions.
