//! End-to-end integration test: `scanner` → `rules` → `aggregate`, wired
//! together exactly as a future driver (the M4 CLI) will, using only the
//! crate's public API. This file lives outside `src/`, so it cannot reach
//! into any private item — if it compiles, the pieces really do fit
//! together from the outside.

use std::collections::VecDeque;
use std::future::Future;
use std::time::{Duration, SystemTime};

use lakescan::aggregate::Aggregates;
use lakescan::error::LakeScanError;
use lakescan::model::{ObjectMeta, RuleId, Severity, StorageClass};
use lakescan::rules::{self, EvalContext};
use lakescan::scanner::{PageSource, Scanner};

/// A `PageSource` driven by a pre-scripted queue of pages, so the pipeline
/// can be exercised with no network — the same technique `scanner`'s own
/// tests use, rebuilt here against only the public `PageSource` trait.
struct FakeSource {
    pages: VecDeque<(Vec<ObjectMeta>, Option<String>)>,
}

impl FakeSource {
    fn new(pages: Vec<(Vec<ObjectMeta>, Option<String>)>) -> Self {
        Self {
            pages: pages.into(),
        }
    }
}

impl PageSource for FakeSource {
    fn fetch_page(
        &mut self,
        _continuation: Option<String>,
        out: &mut Vec<ObjectMeta>,
    ) -> impl Future<Output = Result<Option<String>, LakeScanError>> + Send {
        std::future::ready(match self.pages.pop_front() {
            Some((entries, next)) => {
                out.extend(entries);
                Ok(next)
            }
            None => Ok(None),
        })
    }
}

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_hours(24 * 10_000)
}

fn object(key: &str, size: u64, age_days: u64, storage_class: StorageClass) -> ObjectMeta {
    ObjectMeta {
        key: key.to_owned(),
        size,
        last_modified: now() - Duration::from_hours(24 * age_days),
        etag: format!("etag-{key}"),
        storage_class,
    }
}

#[tokio::test]
async fn scanner_rules_and_aggregate_compose_end_to_end() -> Result<(), LakeScanError> {
    // Page 1: a clean object and a sensitive-looking key.
    let page_one = vec![
        object("reports/summary.csv", 2048, 1, StorageClass::Standard),
        object("id_rsa", 512, 1, StorageClass::Standard),
    ];
    // Page 2: a stale large object and a deprecated storage class, plus a
    // zero-byte object that is a genuine (non-folder-marker) finding.
    let page_two = vec![
        object(
            "archive/huge.bin",
            2 * 1024 * 1024 * 1024,
            200,
            StorageClass::Standard,
        ),
        object("legacy/data.bin", 4096, 1, StorageClass::ReducedRedundancy),
        object("scratch/empty.tmp", 0, 1, StorageClass::Standard),
    ];

    let mut scanner = Scanner::new(FakeSource::new(vec![
        (page_one, Some("token-1".to_owned())),
        (page_two, None),
    ]));
    let ctx = EvalContext { now: now() };
    let mut aggregates = Aggregates::new(now());

    let mut page_count = 0_u64;
    while let Some(page) = scanner.next_page().await? {
        page_count += 1;
        for object in page {
            aggregates.observe_object(object);
            for finding in rules::evaluate(object, &ctx) {
                aggregates.observe_finding(finding);
            }
        }
    }

    assert_eq!(page_count, 2);
    assert_eq!(aggregates.total_objects(), 5);
    assert_eq!(
        aggregates.total_bytes(),
        2048 + 512 + 2 * 1024 * 1024 * 1024 + 4096
    );

    // sensitive-key: id_rsa -> High.
    let sensitive = aggregates.matrix_cell(RuleId::SensitiveKey, Severity::High);
    assert_eq!(sensitive.count, 1);
    assert_eq!(sensitive.bytes, 512);

    // reduced-redundancy: legacy/data.bin -> Medium.
    let reduced = aggregates.matrix_cell(RuleId::ReducedRedundancy, Severity::Medium);
    assert_eq!(reduced.count, 1);
    assert_eq!(reduced.bytes, 4096);

    // stale-standard: archive/huge.bin, 2 GiB and 200 days old -> Medium
    // (size >= 1 GiB threshold).
    let stale = aggregates.matrix_cell(RuleId::StaleStandard, Severity::Medium);
    assert_eq!(stale.count, 1);

    // zero-byte-object: scratch/empty.tmp -> Info.
    let zero_byte = aggregates.matrix_cell(RuleId::ZeroByteObject, Severity::Info);
    assert_eq!(zero_byte.count, 1);

    // Worst severity across every finding is the SensitiveKey High.
    assert_eq!(aggregates.worst_severity(), Some(Severity::High));

    // Sample ordering: exactly the one SensitiveKey finding, and it's the
    // id_rsa key.
    let sensitive_samples = aggregates.samples_for(RuleId::SensitiveKey);
    assert_eq!(sensitive_samples.len(), 1);
    let first_sensitive = sensitive_samples.first();
    assert_eq!(
        first_sensitive.map(|sample| sample.key.as_str()),
        Some("id_rsa")
    );
    assert_eq!(
        first_sensitive.and_then(|sample| sample.severity),
        Some(Severity::High)
    );

    // Largest objects: the 2 GiB object must sort first.
    let largest = aggregates.largest_objects();
    assert_eq!(
        largest.first().map(|sample| sample.key.as_str()),
        Some("archive/huge.bin")
    );

    Ok(())
}
