//! `LakeScan` is a high-throughput S3 audit tool. It enumerates the objects in a
//! bucket, evaluates each one against a set of stateless rules, folds the
//! resulting findings into bounded summaries, and streams a report out. The
//! design constraint that shapes every module is that memory must not grow
//! with the size of the bucket: a scan of ten objects and a scan of ten
//! billion must occupy the same resident set, so each stage below carries a
//! fixed memory budget and nothing between stages is ever fully materialized.
//!
//! The pipeline. [`report`] has two inputs: the whole-bucket summaries
//! [`aggregate`] builds, and an optional per-finding stream straight from
//! [`rules`] — a live JSON Lines feed, independent of whether a summary is
//! written at all.
//!
//! ```text
//!   bucket + prefix
//!         |
//!         v
//!   +-------------+   ObjectMeta   +-------------+   Finding   +-------------+
//!   |   scanner   | -------------> |    rules    | ----------> |  aggregate  |
//!   |    4 MB     |   (streamed)   |    2 MB     | (streamed)  |    18 MB    |
//!   +-------------+                +-------------+             +-------------+
//!   one page live                  stateless per    |          bounded sketches
//!   at a time                      object, no       |          only, static
//!                                  accumulation      |          bound each
//!                                                     \                 |
//!                                       Finding,        \                | summaries
//!                                 optional, streamed      \               |
//!                                  as JSON Lines            v              v
//!                                                   +-----------------------+
//!                                                   |         report        |
//!                                                   |          1 MB         |
//!                                                   +-----------------------+
//!                                                   64 KB buffered streaming
//!                                                             writer
//!                                                               |
//!                                                               v
//!                                                        stdout / file
//!                                                        + ExitCode
//! ```
//!
//! The scanner's 4 MB is a worst case, not a guess: a page of 1000 keys of up
//! to 1 KiB each is held twice at once, once as the raw response body and
//! once as parsed `ObjectMeta` entries.
//!
//! [`cli`] is the driver that wires the four stages together for one run:
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

pub use crate::error::{ExitCode, LakeScanError};
