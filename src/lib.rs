//! `LakeScan` is a high-throughput S3 audit tool. It enumerates the objects in a
//! bucket, evaluates each one against a set of stateless rules, optionally
//! (`--pii`) samples the contents of Parquet files for personal data, sets
//! aside the findings an operator has explicitly suppressed, folds the rest
//! into bounded summaries, and streams a report out. The design constraint
//! that shapes every module is that memory must not grow with the size of
//! the bucket: a scan of ten objects and a scan of ten billion must occupy
//! the same resident set, so each stage below carries a fixed memory budget
//! and nothing between stages is ever fully materialized.
//!
//! The pipeline. Every listed object goes to [`rules`]; an object whose key
//! names a Parquet file also goes to [`content`] when `--pii` is given. Both
//! raise [`model::Finding`]s, which take the same path from there.
//! [`report`] has two inputs: the whole-bucket summaries [`aggregate`]
//! builds, and an optional per-finding stream of every finding that
//! survived [`suppress`] — a live JSON Lines feed, independent of whether a
//! summary is written at all. Suppressed findings go only to [`aggregate`],
//! which counts them per rule.
//!
//! ```text
//!   bucket + prefix                                --config (optional)
//!         |                                                |
//!         v                                                v
//!   +-----------+ ObjectMeta +---------+ Finding   +------------+ Finding +-----------+
//!   |  scanner  | ---------> |  rules  | --------> |  suppress  | ------> | aggregate |
//!   |   4 MB    | (streamed) |  2 MB   |      +--> | <= 36 MiB  |  kept + |   18 MB   |
//!   +-----------+            +---------+      |    | (config)   | suppr.  +-----------+
//!   one page live      |     stateless per    |    +------------+  counts       |
//!   at a time          |     object           |         |                       |
//!                      | *.parquet, *.parq    |         | kept findings         |
//!                      v (--pii only)         |         | optional, streamed    | summaries
//!               +-------------+ Finding       |         | as JSON Lines         |
//!               |   content   | --------------+         v                       v
//!               | --memory-   | + column detail  +-------------------------------------+
//!               | budget      |                  |                report               |
//!               +-------------+                  |                 1 MB                |
//!               --concurrency files at once,     +-------------------------------------+
//!               ranged GetObject, coalesced;     64 KB buffered streaming writer
//!               results applied in listing order
//!                                                                 |
//!                                                                 v
//!                                                          stdout / file
//!                                                          + ExitCode
//! ```
//!
//! The scanner's 4 MB is a worst case, not a guess: a page of 1000 keys of up
//! to 1 KiB each is held twice at once, once as the raw response body and
//! once as parsed `ObjectMeta` entries.
//!
//! The content stage's bound is `--memory-budget` (512 MiB by default) plus
//! a small fixed overhead per in-flight file. Up to `--concurrency` files
//! (16 by default) are scanned at once, and every fetched buffer, every
//! decode (its pages' declared sizes and a dictionary's slots, checked from
//! the headers before anything is allocated), the parsed footer, and every
//! column's sample are held under permits from one byte-counting semaphore
//! of that size; see `content::MemoryBudget`. One file never needs more
//! than [`content::file_need`] (~108 MiB at the default
//! `--pii-whole-file-max`, ~132 MiB at 64 MiB), and a smaller budget is a
//! usage error. The overhead outside the budget, per in-flight file: its
//! key, counts and findings (a few KiB), up to 12,288 first-page locations
//! (~0.8 MiB); the per-column scan records (a file has at most 16,384
//! leaf columns) are counted against the budget. Plus, in the driver's
//! ordered window, at most `--concurrency` + 1,024 listed objects (~1 KiB
//! each) waiting their turn. With the defaults: 512 MiB + 16 × ~1 MiB +
//! ~1 MiB. It depends on those settings and caps, never on the bucket.
//!
//! The suppress stage's bound comes from the config caps, not from the
//! bucket: it holds the `--config` entries and an index over them, sized
//! once before the scan and never grown by it. At the caps — 10,000
//! entries, each an exact key of 1 KiB (held twice: in the entry and in
//! the lookup index), a 1 KiB reason, a 63-byte bucket name, and a
//! 256-byte column path — that is about 3.6 KB per entry (3,392 bytes of
//! strings plus ~200 bytes of entry, hit counter and index slot), or
//! ~36 MB (34.3 MiB) worst case, within the 36 MiB shown above. A
//! realistic config is a few kilobytes. Loading the file briefly holds its
//! text and parsed TOML as well, before the scan starts.
//!
//! [`cli`] is the driver that wires the stages together for one run:
//! it parses the command line, opens the destinations, feeds every page
//! through the pipeline above, and turns the result into an [`ExitCode`].
//!
//! All domain types are defined once, in [`model`]. All failures are expressed
//! as [`LakeScanError`], and each maps to exactly one [`ExitCode`], whose
//! integer values are a frozen public contract. A file content scanning
//! cannot read is not a failure: it is a `content-not-scanned` finding.
//!
//! Bucket contents are attacker-controlled: anyone who can upload to a
//! scanned bucket chooses the bytes of every Parquet file, exactly as they
//! choose key names. One crafted file must never crash the scan or exhaust
//! memory. Two defenses make that so. Every page header is read and
//! checked before the `parquet` crate allocates anything for the page:
//! its declared sizes against the 8 MiB page cap, a dictionary's declared
//! value count, and its codec, so nothing allocated grows with what a file
//! merely claims; GZIP and BROTLI pages, whose `parquet` decoders are not
//! bounded, are decompressed by `content` itself, never past the declared
//! size. And the release build unwinds on panic rather than
//! aborting, so `content` can catch a panic inside the `parquet` parser
//! with `std::panic::catch_unwind` and turn it into a `content-not-scanned`
//! finding (reason `unreadable`) for that one file. The panic hook
//! installed by [`cli::run`] reports where a panic happened, never its
//! message, which could quote the scanned bytes.

pub mod aggregate;
pub mod cli;
pub mod content;
pub mod error;
pub mod model;
pub mod report;
pub mod rules;
pub mod scanner;
pub mod suppress;

pub use crate::error::{ExitCode, LakeScanError};
