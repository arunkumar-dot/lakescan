//! A fixed set of objects, findings, and a [`ScanInfo`], shared by the
//! golden text-summary test and the JSON summary tests, so both exercise
//! exactly the same input: listing findings, and content scans of a few
//! Parquet files in partitioned tables (made up here rather than read, so
//! the reporters are tested apart from `content`).

use std::time::{Duration, SystemTime};

use super::ScanInfo;
use crate::aggregate::Aggregates;
use crate::content::{ColumnFinding, FileOutcome, FileScan, FileStats};
use crate::model::{
    ColumnDetail, Confidence, Evidence, Finding, NotScannedReason, ObjectMeta, PiiType, RuleId,
    StorageClass,
};
use crate::rules::{self, EvalContext};
use crate::suppress::{Config, Date, Outcome, Suppressor};

/// The fixed "now" every fixture object and the fixture [`ScanInfo`] are
/// built relative to.
pub(super) fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn object(
    key: &str,
    size: u64,
    age_days: u64,
    etag: &str,
    storage_class: StorageClass,
) -> ObjectMeta {
    ObjectMeta {
        key: key.to_owned(),
        size,
        last_modified: now() - Duration::from_hours(24 * age_days),
        etag: etag.to_owned(),
        storage_class,
    }
}

/// The fixed objects every fixture is built from: covers every v1 rule at
/// least once (sensitive-key, reduced-redundancy, stale-standard,
/// small-object-cold-tier, zero-byte-object, unknown-storage-class), plus
/// a clean object and a folder marker that must *not* be flagged.
pub(super) fn objects() -> Vec<ObjectMeta> {
    vec![
        object(
            "reports/2024/summary.csv",
            2048,
            0,
            "etag-1",
            StorageClass::Standard,
        ),
        object("id_rsa", 512, 0, "etag-2", StorageClass::Standard),
        object(
            "docs/examples/id_rsa",
            400,
            0,
            "etag-9",
            StorageClass::Standard,
        ),
        object(
            "backups/archive.tar",
            4096,
            0,
            "etag-3",
            StorageClass::ReducedRedundancy,
        ),
        object(
            "old/dataset.bin",
            2 * 1024 * 1024 * 1024,
            200,
            "etag-4",
            StorageClass::Standard,
        ),
        object(
            "cold/thumbnail.jpg",
            1000,
            0,
            "etag-5",
            StorageClass::Glacier,
        ),
        object(
            "placeholder/empty.txt",
            0,
            0,
            "etag-6",
            StorageClass::Standard,
        ),
        object("folder-marker/", 0, 0, "etag-7", StorageClass::Standard),
        object(
            "unknown/object.dat",
            777,
            0,
            "etag-8",
            StorageClass::Other("FUTURE_TIER".to_owned()),
        ),
        object(
            "warehouse/customers/dt=2023-11-01/part-0.parquet",
            5_000_000,
            0,
            "etag-10",
            StorageClass::Standard,
        ),
        object(
            "warehouse/customers/dt=2023-11-02/part-0.parquet",
            4_000_000,
            0,
            "etag-11",
            StorageClass::Standard,
        ),
        object(
            "warehouse/orders/data/part-0.parquet",
            10_000,
            0,
            "etag-12",
            StorageClass::Standard,
        ),
        object("events.parquet", 2000, 0, "etag-13", StorageClass::Standard),
    ]
}

fn column(pii: PiiType, column: &str, confidence: Confidence, evidence: Evidence) -> ColumnFinding {
    ColumnFinding {
        pii,
        detail: ColumnDetail::new(column, confidence, evidence),
    }
}

/// What content scanning made of each fixture Parquet file: emails and
/// names in both customer partitions, phones in one, an unreadable orders
/// file, and an events file with nothing in it.
fn scan_of(key: &str) -> FileScan {
    let emails = column(
        PiiType::Email,
        "email",
        Confidence::Confirmed,
        Evidence::Values {
            matched: 1900,
            sampled: 2000,
        },
    );
    let names = column(
        PiiType::PersonName,
        "full_name",
        Confidence::Likely,
        Evidence::ColumnName,
    );
    let (outcome, columns) = match key {
        "warehouse/customers/dt=2023-11-01/part-0.parquet" => (
            FileOutcome::ScannedPartially,
            vec![
                emails,
                names,
                column(
                    PiiType::Phone,
                    "contact.phone",
                    Confidence::Likely,
                    Evidence::Values {
                        matched: 20,
                        sampled: 24,
                    },
                ),
            ],
        ),
        "warehouse/customers/dt=2023-11-02/part-0.parquet" => {
            (FileOutcome::ScannedWhole, vec![emails, names])
        }
        "warehouse/orders/data/part-0.parquet" => (
            FileOutcome::NotScanned(NotScannedReason::Unreadable),
            Vec::new(),
        ),
        _ => (FileOutcome::ScannedWhole, Vec::new()),
    };
    FileScan {
        outcome,
        columns,
        stats: FileStats::default(),
    }
}

/// The fixture suppression config: one entry that suppresses
/// `docs/examples/id_rsa`, one that expired before [`now`] (2023-11-14),
/// and one that matches nothing.
const CONFIG: &str = r#"
version = 1

[[suppress]]
rule = "sensitive-key"
key = "docs/examples/id_rsa"
reason = "Public example key used in our docs"
expires = 2024-06-30

[[suppress]]
rule = "zero-byte-object"
prefix = "tmp/"
reason = "Scratch space for the nightly job"
expires = 2023-10-01

[[suppress]]
rule = "reduced-redundancy"
key = "backups/2019.tar"
reason = "Legacy archive, migration tracked in OPS-142"

[[suppress]]
rule = "pii-person-name"
prefix = "warehouse/customers/"
column = "full_name"
reason = "Names are needed for invoicing (DPA section 4)"

[[suppress]]
rule = "content-not-scanned"
prefix = "warehouse/orders/"
reason = "Corrupt export; rerun tracked in DATA-77"
"#;

/// Runs the fixture objects through rules, content scanning (as made up
/// by [`scan_of`]), the fixture suppressions, and aggregation, exactly as
/// the driver does.
fn run() -> (Aggregates, Outcome) {
    let ctx = EvalContext { now: now() };
    let mut aggregates = Aggregates::new(now());
    aggregates.enable_content();
    // The fixture config is a constant, checked by the golden test; an
    // invalid one would show up there as a missing suppression.
    let config = Config::parse(CONFIG, "fixture.toml").unwrap_or_default();
    let mut suppressor = Suppressor::new(config, &scan_info_bucket(), Date::utc_of(now()));
    for object in &objects() {
        aggregates.observe_object(object);
        for finding in rules::evaluate(object, &ctx) {
            route(&mut aggregates, &mut suppressor, finding);
        }
        if crate::content::is_eligible(&object.key) {
            let scan = scan_of(&object.key);
            let mut suppressed = false;
            for finding in scan.findings(object) {
                let covered = route(&mut aggregates, &mut suppressor, finding);
                if finding.rule == RuleId::ContentNotScanned {
                    suppressed = covered;
                }
            }
            aggregates.observe_content(object, &scan, suppressed);
        }
    }
    (aggregates, suppressor.finish())
}

/// Sends `finding` where the driver would; returns whether it was
/// suppressed.
fn route(aggregates: &mut Aggregates, suppressor: &mut Suppressor, finding: Finding<'_>) -> bool {
    if let Some(entry) = suppressor.matching(&finding) {
        aggregates.observe_suppressed(finding, entry);
        true
    } else {
        aggregates.observe_finding(finding);
        false
    }
}

fn scan_info_bucket() -> String {
    "example-bucket".to_owned()
}

/// Builds the fixture [`Aggregates`] by observing every fixture object
/// (and every finding it raises, suppressed or not) once.
pub(super) fn aggregates() -> Aggregates {
    run().0
}

/// A lake one table over the inventory's table cap: [`MAX_TABLES`] + 1
/// tables of one Parquet file each, every file with an email column, so
/// the table that sorts last is left out with its file and its finding.
/// Every object has the same `ETag`, so duplicates are significant.
///
/// [`MAX_TABLES`]: crate::aggregate::MAX_TABLES
pub(super) fn crowded() -> Aggregates {
    let ctx = EvalContext { now: now() };
    let mut aggregates = Aggregates::new(now());
    aggregates.enable_content();
    for n in 0..=crate::aggregate::MAX_TABLES {
        let object = object(
            &format!("lake/t{n:05}/part-0.parquet"),
            1000,
            0,
            "same-etag",
            StorageClass::Standard,
        );
        aggregates.observe_object(&object);
        for finding in rules::evaluate(&object, &ctx) {
            aggregates.observe_finding(finding);
        }
        let scan = FileScan {
            outcome: FileOutcome::ScannedWhole,
            columns: vec![column(
                PiiType::Email,
                "email",
                Confidence::Confirmed,
                Evidence::Values {
                    matched: 40,
                    sampled: 40,
                },
            )],
            stats: FileStats::default(),
        };
        for finding in scan.findings(&object) {
            aggregates.observe_finding(finding);
        }
        aggregates.observe_content(&object, &scan, false);
    }
    aggregates
}

/// The fixed [`ScanInfo`] every fixture summary is rendered with,
/// including the fixture config's expired and unused entries.
pub(super) fn scan_info() -> ScanInfo {
    ScanInfo {
        bucket: scan_info_bucket(),
        prefix: Some("logs/".to_owned()),
        started_at: now(),
        elapsed: Duration::from_millis(1234),
        suppressions: run().1,
    }
}
