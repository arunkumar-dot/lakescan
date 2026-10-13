# LakeScan: product definition

## What it is
LakeScan finds personal data (PII) in S3 data lakes, starting with Parquet files, at a fraction of the cost of Amazon Macie. Macie bills about $1 per GB of uncompressed data it inspects. LakeScan reads only the parts of each file that reveal what a column holds: the footer (schema and min/max statistics), dictionary pages where the writer uses them, and the first data page of each column.

## Who it is for
Mid-size companies with a real S3 data lake and real legal exposure, but too small for enterprise data-security platforms and without a dedicated privacy team: SaaS, fintech and health-tech companies, including Indian companies facing full DPDP Act enforcement from 13 May 2027. They need to know where personal data lives and find Macie too expensive to run across the whole lake, or often enough.

## Why they choose it
- Cost: it runs in their own AWS account, so they pay only for compute and S3 requests (well under $1 per terabyte inside AWS) instead of Macie's ~$1 per GB inspected.
- Speed: it reads only the parts of each file that reveal what a column holds, so a whole-lake scan takes hours rather than days, and stays cheap even outside AWS, where S3 egress costs ~$0.09 per GB.
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
Round 1 (synthetic data; pyarrow, Polars, DuckDB): structured PII (emails, phones, PAN, Aadhaar, card numbers, IPs) was found with no false alarms while reading at most 7.3% of uncompressed bytes, often from the footer alone. Dictionary pages matter little: Polars and DuckDB never dictionary-encode high-cardinality columns. PII embedded in free text was missed, so round 1 failed its pre-registered criteria. Details: docs/experiments/parquet-pii.md.

## Open questions
- Do the results hold for Spark-written files and messy real-world values?
- Free-text PII needs far more reading; it will be an opt-in deep scan with its cost shown up front.

## Status
M0-M6 built the pipeline: hardened S3 listing, fixed-memory processing, findings, suppressions, text and JSON reports, a CLI, and CI with end-to-end tests. Content scanning is next.
