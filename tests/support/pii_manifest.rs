//! The PII bucket's contents: the committed Parquet fixtures in
//! `tests/fixtures/parquet`, under the keys `examples/seed_local.rs`
//! uploads them to and `tests/e2e_pii.rs` scans.

/// The bucket the seeder (re)creates for the content-scanning tests.
pub(crate) const PII_BUCKET: &str = "lakescan-pii";

/// `(key, fixture path relative to tests/fixtures/parquet)`, in upload
/// order. The `lake/` files are all readable; the `bad/` ones are not; the
/// `skipped/` one is Parquet whose every candidate column is skipped.
pub(crate) const PII_OBJECTS: [(&str, &str); 11] = [
    (
        "lake/pyarrow/customers.parquet",
        "pyarrow/customers.parquet",
    ),
    ("lake/polars/customers.parquet", "polars/customers.parquet"),
    ("lake/duckdb/customers.parquet", "duckdb/customers.parquet"),
    ("lake/spark/customers.parquet", "spark/customers.parquet"),
    ("lake/escalation.parquet", "escalation.parquet"),
    (
        "lake/gzip/pyarrow/customers.parquet",
        "gzip/pyarrow/customers.parquet",
    ),
    (
        "lake/gzip/spark/customers.parquet",
        "gzip/spark/customers.parquet",
    ),
    (
        "lake/brotli/pyarrow/customers.parquet",
        "brotli/pyarrow/customers.parquet",
    ),
    ("bad/truncated.parquet", "bad/truncated.parquet"),
    ("bad/not_parquet.parquet", "bad/not_parquet.parquet"),
    ("skipped/too_large.parquet", "skipped/too_large.parquet"),
];

/// The fixture file at `path`, read from the repository.
pub(crate) fn fixture(path: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/parquet")
            .join(path),
    )
}
