# LakeScan: product definition

## What it is
LakeScan finds personal data (PII) in S3 data lakes, starting with Parquet files, at a fraction of the cost of Amazon Macie. Macie bills about $1 per GB of uncompressed data it inspects. LakeScan reads only the parts of each file that reveal what a column holds: the footer (schema and statistics), dictionary pages (each column's distinct values), and, only where needed, a small sample of data pages.

## Who it is for
Mid-size companies with a real S3 data lake and real legal exposure, but too small for enterprise data-security platforms and without a dedicated privacy team: SaaS, fintech and health-tech companies, including Indian companies facing full DPDP Act enforcement from 13 May 2027. They need to know where personal data lives and find Macie too expensive to run across the whole lake, or often enough.

## Why they choose it
- Cost: it reads a small fraction of the bytes Macie bills for.
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

## Open question to answer first
High-cardinality columns such as emails and phone numbers are often not dictionary-encoded, because writers fall back to plain encoding once a dictionary grows too large. The first experiment measures (1) what share of PII columns the footer and dictionary reads catch, and (2) what fraction of each file's bytes they need. The pricing claim depends on these two numbers.

## Status
M0-M6 built the pipeline: hardened S3 listing, fixed-memory processing, findings, suppressions, text and JSON reports, a CLI, and CI with end-to-end tests. Content scanning is next.
