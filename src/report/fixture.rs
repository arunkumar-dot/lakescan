//! A fixed set of objects, findings, and a [`ScanInfo`], shared by the
//! golden text-summary test and the JSON summary tests, so both exercise
//! exactly the same input.

use std::time::{Duration, SystemTime};

use super::ScanInfo;
use crate::aggregate::Aggregates;
use crate::model::{ObjectMeta, StorageClass};
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
    ]
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
"#;

/// Runs the fixture objects through rules, the fixture suppressions, and
/// aggregation, exactly as the driver does.
fn run() -> (Aggregates, Outcome) {
    let ctx = EvalContext { now: now() };
    let mut aggregates = Aggregates::new(now());
    // The fixture config is a constant, checked by the golden test; an
    // invalid one would show up there as a missing suppression.
    let config = Config::parse(CONFIG, "fixture.toml").unwrap_or_default();
    let mut suppressor = Suppressor::new(config, &scan_info_bucket(), Date::utc_of(now()));
    for object in &objects() {
        aggregates.observe_object(object);
        for finding in rules::evaluate(object, &ctx) {
            if suppressor.suppresses(&finding) {
                aggregates.observe_suppressed(finding);
            } else {
                aggregates.observe_finding(finding);
            }
        }
    }
    (aggregates, suppressor.finish())
}

fn scan_info_bucket() -> String {
    "example-bucket".to_owned()
}

/// Builds the fixture [`Aggregates`] by observing every fixture object
/// (and every finding it raises, suppressed or not) once.
pub(super) fn aggregates() -> Aggregates {
    run().0
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
