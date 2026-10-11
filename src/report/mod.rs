//! Serializes results to an output sink.
//!
//! Single responsibility: render what the pipeline produced. The reporter
//! formats and writes; it does not compute, re-sort, or re-derive anything,
//! and it is the only module that touches the output destination.
//!
//! **Memory budget: 1 MB.** Output is a streaming writer behind a 64 KB
//! buffer. Records are written as they arrive, so no complete report is ever
//! materialized in memory regardless of how large the scan was.
