//! The PII bucket's contents: the committed Parquet fixtures in
//! `tests/fixtures/parquet`, under the keys `examples/seed_local.rs`
//! uploads them to and `tests/e2e_pii.rs` scans.

/// The bucket the seeder (re)creates for the content-scanning tests.
pub(crate) const PII_BUCKET: &str = "lakescan-pii";

/// `(key, fixture path relative to tests/fixtures/parquet)`, in upload
/// order, laid out like a lake: Hive partitions (`dt=`, nested `region=`)
/// and Iceberg `data/` directories, so the inventory groups them into the
/// tables `lake/customers`, `lake/customers_gzip`, `lake/customers_brotli`
/// and `lake/events`. The `lake/` files are all readable; the `bad/` ones
/// are not; the `skipped/` one is Parquet whose every candidate column is
/// skipped.
pub(crate) const PII_OBJECTS: [(&str, &str); 11] = [
    (
        "lake/customers/dt=2026-01-01/part-0.parquet",
        "pyarrow/customers.parquet",
    ),
    (
        "lake/customers/dt=2026-01-02/part-0.parquet",
        "polars/customers.parquet",
    ),
    (
        "lake/customers/dt=2026-01-03/part-0.parquet",
        "duckdb/customers.parquet",
    ),
    (
        "lake/customers/dt=2026-01-04/region=in/part-0.parquet",
        "spark/customers.parquet",
    ),
    (
        "lake/customers_gzip/dt=2026-01-01/part-0.parquet",
        "gzip/pyarrow/customers.parquet",
    ),
    (
        "lake/customers_gzip/dt=2026-01-02/part-0.parquet",
        "gzip/spark/customers.parquet",
    ),
    (
        "lake/customers_brotli/data/part-0.parquet",
        "brotli/pyarrow/customers.parquet",
    ),
    (
        "lake/events/data/dt=2026-01-01/part-0.parquet",
        "escalation.parquet",
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
