//! `LakeScan` is a high-throughput S3 audit tool. It enumerates the objects in a
//! bucket, evaluates each one against a set of stateless rules, sets aside the
//! findings an operator has explicitly suppressed, folds the rest into
//! bounded summaries, and streams a report out. The
//! design constraint that shapes every module is that memory must not grow
//! with the size of the bucket: a scan of ten objects and a scan of ten
//! billion must occupy the same resident set, so each stage below carries a
//! fixed memory budget and nothing between stages is ever fully materialized.
//!
//! The pipeline. [`report`] has two inputs: the whole-bucket summaries
//! [`aggregate`] builds, and an optional per-finding stream of every
//! finding that survived [`suppress`] — a live JSON Lines feed,
//! independent of whether a summary is written at all. Suppressed findings
//! go only to [`aggregate`], which counts them per rule.
//!
//! ```text
//!   bucket + prefix                            --config (optional)
//!         |                                            |
//!         v                                            v
//!   +-----------+ ObjectMeta +---------+ Finding +------------+ Finding +-----------+
//!   |  scanner  | ---------> |  rules  | ------> |  suppress  | ------> | aggregate |
//!   |   4 MB    | (streamed) |  2 MB   |         | <= 32 MiB  |  kept + |   18 MB   |
//!   +-----------+            +---------+         | (config)   | suppr.  +-----------+
//!   one page live            stateless per       +------------+  counts       |
//!   at a time                object, no            |  bounded by the          |
//!                            accumulation          |  config, never by        | summaries
//!                                                  |  the bucket              |
//!                                    kept findings |                          |
//!                                 optional, streamed                          |
//!                                  as JSON Lines   v                          v
//!                                          +-------------------------------------+
//!                                          |                report               |
//!                                          |                 1 MB                |
//!                                          +-------------------------------------+
//!                                          64 KB buffered streaming writer
//!                                                           |
//!                                                           v
//!                                                    stdout / file
//!                                                    + ExitCode
//! ```
//!
//! The scanner's 4 MB is a worst case, not a guess: a page of 1000 keys of up
//! to 1 KiB each is held twice at once, once as the raw response body and
//! once as parsed `ObjectMeta` entries.
//!
//! The suppress stage's bound comes from the config caps, not from the
//! bucket: it holds the `--config` entries and an index over them, sized
//! once before the scan and never grown by it. At the caps — 10,000
//! entries, each an exact key of 1 KiB (held twice: in the entry and in
//! the lookup index), a 1 KiB reason, and a 63-byte bucket name — that is
//! about 3.3 KB per entry (3,136 bytes of strings plus ~150 bytes of entry,
//! hit counter and index slot), or ~33 MB (31.3 MiB) worst case, within
//! the 32 MiB shown above. A realistic config is a few kilobytes. Loading the file briefly holds its text and
//! parsed TOML as well, before the scan starts.
//!
//! [`cli`] is the driver that wires the five stages together for one run:
//! it parses the command line, opens the destinations, feeds every page
//! through the pipeline above, and turns the result into an [`ExitCode`].
//!
//! All domain types are defined once, in [`model`]. All failures are expressed
//! as [`LakeScanError`], and each maps to exactly one [`ExitCode`], whose
//! integer values are a frozen public contract.

pub mod aggregate;
pub mod cli;
pub mod error;
pub mod model;
pub mod report;
pub mod rules;
pub mod scanner;
pub mod suppress;

pub use crate::error::{ExitCode, LakeScanError};
