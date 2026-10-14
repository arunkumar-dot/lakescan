# LakeScan: product definition

## What it is
LakeScan finds personal data (PII) in S3 data lakes, starting with Parquet files, at a fraction of the cost of Amazon Macie. Macie bills about $1 per GB of uncompressed data it inspects. LakeScan reads only the parts of each file that reveal what a column holds: the footer (schema), the first data page of each column, and dictionary pages where the writer uses them. Small files are read whole, in one request.

## Who it is for
Mid-size companies with a real S3 data lake and real legal exposure, but too small for enterprise data-security platforms and without a dedicated privacy team: SaaS, fintech and health-tech companies, including Indian companies facing full DPDP Act enforcement from 13 May 2027. They need to know where personal data lives and find Macie too expensive to run across the whole lake, or often enough.

## Why they choose it
- Cost: it runs in their own AWS account, so they pay only for compute and S3 requests (well under $1 per terabyte inside AWS) instead of Macie's ~$1 per GB inspected.
- Speed: on large files it reads under 10% of the data (0.8-8.1% in tests), so whole-lake scans stay fast, and stay cheap even outside AWS, where S3 egress costs ~$0.09 per GB.
- Compliance evidence: a personal-data inventory they can show an auditor, customer or regulator.
- Data never leaves their account: it runs on their own infrastructure with read-only access.
- CI-friendly: frozen exit codes, JSON output, suppressions with reasons and expiry dates.

## How it is sold
Source-available under FSL-1.1-ALv2: free to use inside your own organization, including PII scanning. Paid offerings (continuous monitoring with history and alerts, audit-ready evidence packs, support) are planned and will be validated with a waitlist.

## Non-goals
- Competing with enterprise data-security platforms (Cyera, BigID, Varonis) for large enterprises.
- General cloud security posture (ACLs, public access, encryption settings). AWS IAM Access Analyzer and Security Hub cover these.
- Storage cost optimization as the main value. The cost rules are a free extra.
- File formats other than Parquet, until Parquet works well.

## Evidence so far
Round 1 (clean synthetic data; pyarrow, Polars, DuckDB): structured PII was found with no false alarms, but PII embedded in free text was missed, so round 1 failed its pre-registered criteria.

Round 2 (messy synthetic data; pyarrow, Polars, DuckDB, Spark): passed both pre-registered criteria. Emails, phones, PAN, Aadhaar, card numbers and IPs were confirmed in every large file with no false confirmations, reading 0.8-8.1% of uncompressed bytes in 11-24 range reads per file. On messy data the footer alone confirms nothing; the first data pages do the work, and dictionary pages depend on the writer (Spark writes none for PII columns). Emails embedded in free text were found down to 0.01% of rows, but only by reading the whole column (15-40% of uncompressed bytes). On small files the partial reads save almost nothing, so one whole-file read is better. Details: docs/experiments/parquet-pii.md.

## Open questions
- Real-world placeholders, and junk that clusters (a bad batch, a backfill of nulls) instead of spreading evenly. Round 2's cleaning list matched the generator's own.
- Free text: a better trigger than average value length (hashes and UUIDs qualified), and precision against email-like tokens in real prose.
- Scan speed on real S3, where request count and latency matter more than bytes, especially for lakes of many small files.
- Validation on real data, which only early users can provide.

## Status
M0-M7: the metadata pipeline plus structured-PII scanning of Parquet files (opt-in with --pii). Next: a per-table PII inventory report (M8), then parallel scanning (M9).
