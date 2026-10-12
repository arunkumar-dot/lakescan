//! A fixed set of objects, findings, and a [`ScanInfo`], shared by the
//! golden text-summary test and the JSON summary tests, so both exercise
//! exactly the same input.

use std::time::{Duration, SystemTime};

use super::ScanInfo;
use crate::aggregate::Aggregates;
use crate::model::{ObjectMeta, StorageClass};
use crate::rules::{self, EvalContext};

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

/// Builds the fixture [`Aggregates`] by observing every fixture object
/// (and every finding it raises) once.
pub(super) fn aggregates() -> Aggregates {
    let ctx = EvalContext { now: now() };
    let mut aggregates = Aggregates::new(now());
    for object in &objects() {
        aggregates.observe_object(object);
        for finding in rules::evaluate(object, &ctx) {
            aggregates.observe_finding(finding);
        }
    }
    aggregates
}

/// The fixed [`ScanInfo`] every fixture summary is rendered with.
pub(super) fn scan_info() -> ScanInfo {
    ScanInfo {
        bucket: "example-bucket".to_owned(),
        prefix: Some("logs/".to_owned()),
        started_at: now(),
        elapsed: Duration::from_millis(1234),
    }
}
