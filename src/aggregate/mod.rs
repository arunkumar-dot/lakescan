//! Folds the finding stream into bounded summaries.
//!
//! Single responsibility: answer whole-bucket questions — totals, top-k,
//! distributions, cardinalities — without ever holding the bucket in memory.
//!
//! **Memory budget: 18 MB.** Bounded sketches only. Every aggregator declares
//! a `const` upper bound on its own footprint, and no aggregator may use a
//! structure whose size grows with the number of objects or findings scanned.
//! This is the only module in the pipeline permitted to retain state across
//! objects, which is exactly why its bound is explicit and checked.
