//! The PII bucket's contents: the committed Parquet fixtures in
//! `tests/fixtures/parquet`, under the keys `examples/seed_local.rs`
//! uploads them to and `tests/e2e_pii.rs` scans.

/// The bucket the seeder (re)creates for the content-scanning tests.
pub(crate) const PII_BUCKET: &str = "lakescan-pii";

/// `(key, fixture path relative to tests/fixtures/parquet)`, in upload
/// order. The `lake/` files are all readable; the `bad/` ones are not.
pub(crate) const PII_OBJECTS: [(&str, &str); 7] = [
    (
        "lake/pyarrow/customers.parquet",
        "pyarrow/customers.parquet",
    ),
    ("lake/polars/customers.parquet", "polars/customers.parquet"),
    ("lake/duckdb/customers.parquet", "duckdb/customers.parquet"),
    ("lake/spark/customers.parquet", "spark/customers.parquet"),
    ("lake/escalation.parquet", "escalation.parquet"),
    ("bad/truncated.parquet", "bad/truncated.parquet"),
    ("bad/not_parquet.parquet", "bad/not_parquet.parquet"),
];

/// The fixture file at `path`, read from the repository.
pub(crate) fn fixture(path: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/parquet")
            .join(path),
    )
}
