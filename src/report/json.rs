//! The JSON summary writer. See `report`'s module doc for the schema these
//! view structs mirror field-for-field; this file only decides *how* to
//! pull each value out of [`Aggregates`], never what it means.

use std::collections::BTreeMap;
use std::io::Write;

use serde::Serialize;

use super::rfc3339::format_rfc3339;
use super::{TOOL_NAME, TOOL_VERSION};
use crate::aggregate::{Aggregates, CountBytes, Sample};
use crate::error::LakeScanError;
use crate::model::{RuleId, Severity};
use crate::suppress::{Entry, Outcome, Pattern};

#[derive(Serialize)]
struct ToolSection {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct ScanSection<'a> {
    bucket: &'a str,
    prefix: Option<&'a str>,
    started_at: String,
    elapsed_ms: u64,
}

#[derive(Serialize)]
struct VerdictSection {
    worst_severity: Option<&'static str>,
}

#[derive(Serialize)]
struct StorageClassEntry<'a> {
    storage_class: &'a str,
    count: u64,
    bytes: u64,
}

/// The combined count and bytes of *every* unrecognized object, named in
/// `unrecognized_storage_classes` or not: that list only names the 8
/// lexicographically smallest distinct unrecognized class names, but this
/// total — [`Aggregates::unrecognized_totals`] — is exact regardless, so
/// `by_storage_class`'s counts plus this field's count always equal
/// `object_count` (and the same for bytes).
#[derive(Serialize)]
struct UnrecognizedTotals {
    count: u64,
    bytes: u64,
}

#[derive(Serialize)]
struct InventorySection<'a> {
    object_count: u64,
    total_bytes: u64,
    by_storage_class: Vec<StorageClassEntry<'a>>,
    unrecognized_storage_classes: Vec<&'a str>,
    unrecognized_storage_class_totals: UnrecognizedTotals,
}

/// One count or byte total per severity. Used both for a finding's
/// `counts` and its `bytes` — same shape, different cells of the matrix.
#[derive(Serialize)]
struct SeverityTotals {
    critical: u64,
    high: u64,
    medium: u64,
    low: u64,
    info: u64,
}

impl SeverityTotals {
    fn counts(aggregates: &Aggregates, rule: RuleId) -> Self {
        Self {
            critical: aggregates.matrix_cell(rule, Severity::Critical).count,
            high: aggregates.matrix_cell(rule, Severity::High).count,
            medium: aggregates.matrix_cell(rule, Severity::Medium).count,
            low: aggregates.matrix_cell(rule, Severity::Low).count,
            info: aggregates.matrix_cell(rule, Severity::Info).count,
        }
    }

    fn bytes(aggregates: &Aggregates, rule: RuleId) -> Self {
        Self {
            critical: aggregates.matrix_cell(rule, Severity::Critical).bytes,
            high: aggregates.matrix_cell(rule, Severity::High).bytes,
            medium: aggregates.matrix_cell(rule, Severity::Medium).bytes,
            low: aggregates.matrix_cell(rule, Severity::Low).bytes,
            info: aggregates.matrix_cell(rule, Severity::Info).bytes,
        }
    }

    /// Whether every cell is zero, i.e. this rule raised no finding at all.
    fn is_all_zero(&self) -> bool {
        [self.critical, self.high, self.medium, self.low, self.info]
            .into_iter()
            .all(|n| n == 0)
    }
}

/// A plain `{count, bytes}` pair.
#[derive(Serialize)]
struct Totals {
    count: u64,
    bytes: u64,
}

impl From<CountBytes> for Totals {
    fn from(cell: CountBytes) -> Self {
        Self {
            count: cell.count,
            bytes: cell.bytes,
        }
    }
}

#[derive(Serialize)]
struct FindingSummary {
    rule: &'static str,
    title: &'static str,
    counts: SeverityTotals,
    bytes: SeverityTotals,
    suppressed: Totals,
}

/// One `--config` entry: exactly one of `key` or `prefix` is present.
#[derive(Serialize)]
struct SuppressionEntry<'a> {
    rule: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<&'a str>,
    reason: &'a str,
    expires: Option<String>,
}

impl<'a> SuppressionEntry<'a> {
    fn from_entry(entry: &'a Entry) -> Self {
        let (key, prefix) = match &entry.pattern {
            Pattern::Key(key) => (Some(key.as_str()), None),
            Pattern::Prefix(prefix) => (None, Some(prefix.as_str())),
        };
        Self {
            rule: entry.rule.code(),
            key,
            prefix,
            reason: &entry.reason,
            expires: entry.expires.map(|date| date.to_string()),
        }
    }
}

#[derive(Serialize)]
struct SuppressionsSection<'a> {
    expired: Vec<SuppressionEntry<'a>>,
    unused: Vec<SuppressionEntry<'a>>,
}

impl<'a> SuppressionsSection<'a> {
    fn from_outcome(outcome: &'a Outcome) -> Self {
        Self {
            expired: outcome
                .expired
                .iter()
                .map(SuppressionEntry::from_entry)
                .collect(),
            unused: outcome
                .unused
                .iter()
                .map(SuppressionEntry::from_entry)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct SampleEntry<'a> {
    key: &'a str,
    key_truncated: bool,
    severity: Option<&'static str>,
    size: u64,
    storage_class: &'a str,
    last_modified: String,
}

impl<'a> SampleEntry<'a> {
    fn from_sample(sample: &'a Sample) -> Self {
        Self {
            key: &sample.key,
            key_truncated: sample.key_truncated,
            severity: sample.severity.map(Severity::code),
            size: sample.size,
            storage_class: sample.storage_class.as_wire(),
            last_modified: format_rfc3339(sample.last_modified),
        }
    }
}

#[derive(Serialize)]
struct SizeBucket {
    lower: u64,
    upper: Option<u64>,
    count: u64,
    bytes: u64,
}

#[derive(Serialize)]
struct AgeBucket {
    lower_seconds: u64,
    upper_seconds: Option<u64>,
    count: u64,
    bytes: u64,
}

#[derive(Serialize)]
struct DistinctContentSection {
    estimate: f64,
    duplicate_lower_bound: f64,
    duplicates_significant: bool,
}

/// The `samples` section: a map from rule code to that rule's samples.
///
/// A `BTreeMap`, so keys come out alphabetically — not [`RuleId::ALL`]
/// order. That is a deliberate non-goal: JSON object keys are unordered by
/// the format's own spec, `serde_json`'s own `Value` re-sorts them to this
/// same alphabetical order on parse regardless of how they were written,
/// and any reasonable consumer (`jq`, `.get(code)`) looks a key up by name
/// rather than relying on where it sits.
type SamplesSection<'a> = BTreeMap<&'static str, Vec<SampleEntry<'a>>>;

#[derive(Serialize)]
struct Summary<'a> {
    schema_version: u32,
    tool: ToolSection,
    scan: ScanSection<'a>,
    verdict: VerdictSection,
    inventory: InventorySection<'a>,
    findings: Vec<FindingSummary>,
    suppressions: SuppressionsSection<'a>,
    samples: SamplesSection<'a>,
    largest_objects: Vec<SampleEntry<'a>>,
    size_histogram: Vec<SizeBucket>,
    age_histogram: Vec<AgeBucket>,
    distinct_content: DistinctContentSection,
}

fn inventory_section(aggregates: &Aggregates) -> InventorySection<'_> {
    // The known classes with a non-zero count, in `StorageClass::KNOWN`
    // order — this field's schema is known-only (count and bytes per
    // class), unlike `nonzero_storage_classes`, which also folds in the
    // unrecognized ones; `unrecognized_storage_classes` below covers those
    // separately, as names only.
    let by_storage_class = crate::model::StorageClass::KNOWN
        .iter()
        .filter_map(|class| {
            let stats = aggregates.class_stats(class)?;
            (stats.count > 0).then(|| StorageClassEntry {
                storage_class: class.as_wire(),
                count: stats.count,
                bytes: stats.bytes,
            })
        })
        .collect();

    let unrecognized_storage_classes = aggregates.other_classes().map(|(name, _)| name).collect();
    let unrecognized_totals = aggregates.unrecognized_totals();

    InventorySection {
        object_count: aggregates.total_objects(),
        total_bytes: aggregates.total_bytes(),
        by_storage_class,
        unrecognized_storage_classes,
        unrecognized_storage_class_totals: UnrecognizedTotals {
            count: unrecognized_totals.count,
            bytes: unrecognized_totals.bytes,
        },
    }
}

fn findings_section(aggregates: &Aggregates) -> Vec<FindingSummary> {
    RuleId::ALL
        .into_iter()
        .filter_map(|rule| {
            let counts = SeverityTotals::counts(aggregates, rule);
            let suppressed = aggregates.suppressed(rule);
            if counts.is_all_zero() && suppressed.count == 0 {
                return None;
            }
            Some(FindingSummary {
                rule: rule.code(),
                title: rule.title(),
                counts,
                bytes: SeverityTotals::bytes(aggregates, rule),
                suppressed: suppressed.into(),
            })
        })
        .collect()
}

fn samples_section(aggregates: &Aggregates) -> SamplesSection<'_> {
    RuleId::ALL
        .into_iter()
        .filter_map(|rule| {
            let samples = aggregates.samples_for(rule);
            if samples.is_empty() {
                return None;
            }
            let entries = samples.into_iter().map(SampleEntry::from_sample).collect();
            Some((rule.code(), entries))
        })
        .collect()
}

fn size_histogram_section(aggregates: &Aggregates) -> Vec<SizeBucket> {
    (0..aggregates.size_bucket_count())
        .filter_map(|index| {
            let cell = aggregates.size_bucket(index);
            if cell.count == 0 {
                return None;
            }
            let (lower, upper) = Aggregates::size_bucket_bounds(index);
            Some(SizeBucket {
                lower,
                upper,
                count: cell.count,
                bytes: cell.bytes,
            })
        })
        .collect()
}

fn age_histogram_section(aggregates: &Aggregates) -> Vec<AgeBucket> {
    (0..aggregates.age_bucket_count())
        .filter_map(|index| {
            let cell = aggregates.age_bucket(index);
            if cell.count == 0 {
                return None;
            }
            let (lower, upper) = Aggregates::age_bucket_bounds(index);
            Some(AgeBucket {
                lower_seconds: lower.as_secs(),
                upper_seconds: upper.map(|d| d.as_secs()),
                count: cell.count,
                bytes: cell.bytes,
            })
        })
        .collect()
}

/// Builds the full [`Summary`] view from `info` and `aggregates`.
fn build<'a>(info: &'a super::ScanInfo, aggregates: &'a Aggregates) -> Summary<'a> {
    Summary {
        schema_version: 1,
        tool: ToolSection {
            name: TOOL_NAME,
            version: TOOL_VERSION,
        },
        scan: ScanSection {
            bucket: &info.bucket,
            prefix: info.prefix.as_deref(),
            started_at: format_rfc3339(info.started_at),
            elapsed_ms: u64::try_from(info.elapsed.as_millis()).unwrap_or(u64::MAX),
        },
        verdict: VerdictSection {
            worst_severity: aggregates.worst_severity().map(Severity::code),
        },
        inventory: inventory_section(aggregates),
        findings: findings_section(aggregates),
        suppressions: SuppressionsSection::from_outcome(&info.suppressions),
        samples: samples_section(aggregates),
        largest_objects: aggregates
            .largest_objects()
            .into_iter()
            .map(SampleEntry::from_sample)
            .collect(),
        size_histogram: size_histogram_section(aggregates),
        age_histogram: age_histogram_section(aggregates),
        distinct_content: DistinctContentSection {
            estimate: aggregates.distinct_content_estimate(),
            duplicate_lower_bound: aggregates.duplicate_lower_bound(),
            duplicates_significant: aggregates.duplicates_significant(),
        },
    }
}

/// Writes the JSON summary to `out`.
pub(super) fn write<W: Write>(
    out: &mut W,
    info: &super::ScanInfo,
    aggregates: &Aggregates,
) -> Result<(), LakeScanError> {
    let summary = build(info, aggregates);
    serde_json::to_writer(&mut *out, &summary).map_err(|err| LakeScanError::Report(err.into()))
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::write;
    use crate::report::fixture;

    fn render() -> Result<Value, Box<dyn std::error::Error>> {
        let mut buf = Vec::new();
        write(&mut buf, &fixture::scan_info(), &fixture::aggregates())?;
        Ok(serde_json::from_slice(&buf)?)
    }

    #[test]
    fn parses_and_has_schema_version_one() -> Result<(), Box<dyn std::error::Error>> {
        let value = render()?;
        assert_eq!(value.get("schema_version"), Some(&Value::from(1)));
        Ok(())
    }

    #[test]
    fn scan_and_inventory_counts_match_the_fixture() -> Result<(), Box<dyn std::error::Error>> {
        let value = render()?;

        assert_eq!(
            value.get("scan").and_then(|s| s.get("bucket")),
            Some(&Value::from("example-bucket"))
        );
        assert_eq!(
            value.get("scan").and_then(|s| s.get("prefix")),
            Some(&Value::from("logs/"))
        );
        assert_eq!(
            value.get("scan").and_then(|s| s.get("started_at")),
            Some(&Value::from("2023-11-14T22:13:20Z"))
        );
        assert_eq!(
            value.get("scan").and_then(|s| s.get("elapsed_ms")),
            Some(&Value::from(1234))
        );

        assert_eq!(
            value.get("inventory").and_then(|i| i.get("object_count")),
            Some(&Value::from(9))
        );
        assert_eq!(
            value
                .get("inventory")
                .and_then(|i| i.get("unrecognized_storage_classes")),
            Some(&Value::from(vec!["FUTURE_TIER"]))
        );
        Ok(())
    }

    #[test]
    fn by_storage_class_plus_unrecognized_totals_equal_the_grand_totals()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = render()?;
        let inventory = value.get("inventory").cloned().unwrap_or(Value::Null);

        let by_class = inventory.get("by_storage_class").and_then(Value::as_array);
        let known_count: u64 = by_class
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.get("count").and_then(Value::as_u64))
            .sum();
        let known_bytes: u64 = by_class
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.get("bytes").and_then(Value::as_u64))
            .sum();

        let unrecognized = inventory.get("unrecognized_storage_class_totals");
        let unrecognized_count = unrecognized
            .and_then(|u| u.get("count"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let unrecognized_bytes = unrecognized
            .and_then(|u| u.get("bytes"))
            .and_then(Value::as_u64)
            .unwrap_or(0);

        // The fixture's one unrecognized object (FUTURE_TIER) must be
        // accounted for here, not silently dropped between the two
        // fields.
        assert_eq!(unrecognized_count, 1);
        assert_eq!(unrecognized_bytes, 777);

        assert_eq!(
            Some(&Value::from(known_count + unrecognized_count)),
            inventory.get("object_count")
        );
        assert_eq!(
            Some(&Value::from(known_bytes + unrecognized_bytes)),
            inventory.get("total_bytes")
        );
        Ok(())
    }

    #[test]
    fn every_findings_entry_carries_its_suppressed_totals() -> Result<(), Box<dyn std::error::Error>>
    {
        let value = render()?;
        let findings = value
            .get("findings")
            .and_then(Value::as_array)
            .ok_or("no findings array")?;
        for entry in findings {
            let suppressed = entry.get("suppressed").ok_or("no suppressed field")?;
            let expected = if entry.get("rule") == Some(&Value::from("sensitive-key")) {
                serde_json::json!({ "count": 1, "bytes": 400 })
            } else {
                serde_json::json!({ "count": 0, "bytes": 0 })
            };
            assert_eq!(suppressed, &expected, "{entry}");
        }
        Ok(())
    }

    #[test]
    fn suppressions_lists_expired_and_unused_entries() -> Result<(), Box<dyn std::error::Error>> {
        let value = render()?;
        assert_eq!(
            value.get("suppressions"),
            Some(&serde_json::json!({
                "expired": [{
                    "rule": "zero-byte-object",
                    "prefix": "tmp/",
                    "reason": "Scratch space for the nightly job",
                    "expires": "2023-10-01"
                }],
                "unused": [{
                    "rule": "reduced-redundancy",
                    "key": "backups/2019.tar",
                    "reason": "Legacy archive, migration tracked in OPS-142",
                    "expires": null
                }]
            }))
        );
        Ok(())
    }

    #[test]
    fn a_rule_whose_findings_were_all_suppressed_is_still_listed()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = fixture::now();
        let object = crate::model::ObjectMeta {
            key: "id_rsa".to_owned(),
            size: 64,
            last_modified: now,
            etag: "etag".to_owned(),
            storage_class: crate::model::StorageClass::Standard,
        };
        let mut aggregates = crate::aggregate::Aggregates::new(now);
        aggregates.observe_object(&object);
        let ctx = crate::rules::EvalContext { now };
        for finding in crate::rules::evaluate(&object, &ctx) {
            aggregates.observe_suppressed(finding);
        }

        let mut buf = Vec::new();
        write(&mut buf, &fixture::scan_info(), &aggregates)?;
        let value: Value = serde_json::from_slice(&buf)?;

        assert_eq!(
            value.get("verdict").and_then(|v| v.get("worst_severity")),
            Some(&Value::Null)
        );
        let findings = value.get("findings").and_then(Value::as_array);
        let entry = findings.and_then(|f| f.first()).ok_or("rule not listed")?;
        assert_eq!(findings.map(Vec::len), Some(1));
        assert_eq!(entry.get("rule"), Some(&Value::from("sensitive-key")));
        assert_eq!(entry.pointer("/counts/high"), Some(&Value::from(0)));
        assert_eq!(
            entry.get("suppressed"),
            Some(&serde_json::json!({ "count": 1, "bytes": 64 }))
        );
        Ok(())
    }

    #[test]
    fn distinct_content_reports_whether_duplicates_are_significant()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = render()?;
        // Every fixture object has its own etag: nothing significant.
        assert_eq!(
            value.pointer("/distinct_content/duplicates_significant"),
            Some(&Value::Bool(false))
        );
        Ok(())
    }

    #[test]
    fn worst_severity_is_high() -> Result<(), Box<dyn std::error::Error>> {
        let value = render()?;
        assert_eq!(
            value.get("verdict").and_then(|v| v.get("worst_severity")),
            Some(&Value::from("high"))
        );
        Ok(())
    }

    #[test]
    fn findings_are_in_rule_id_all_order() -> Result<(), Box<dyn std::error::Error>> {
        let value = render()?;
        let rules: Vec<&str> = value
            .get("findings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.get("rule").and_then(Value::as_str))
            .collect();

        assert_eq!(
            rules,
            [
                "sensitive-key",
                "reduced-redundancy",
                "stale-standard",
                "small-object-cold-tier",
                "zero-byte-object",
                "unknown-storage-class",
            ]
        );
        Ok(())
    }

    #[test]
    fn samples_has_one_entry_per_rule_with_a_finding_and_the_right_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = render()?;
        let samples = value.get("samples").cloned().unwrap_or(Value::Null);
        let mut keys: Vec<&str> = samples
            .as_object()
            .into_iter()
            .flat_map(serde_json::Map::keys)
            .map(String::as_str)
            .collect();
        keys.sort_unstable();

        let mut expected = [
            "sensitive-key",
            "reduced-redundancy",
            "stale-standard",
            "small-object-cold-tier",
            "zero-byte-object",
            "unknown-storage-class",
        ];
        expected.sort_unstable();
        assert_eq!(keys, expected);

        let sensitive = samples.get("sensitive-key").and_then(Value::as_array);
        let first = sensitive.and_then(|entries| entries.first());
        assert_eq!(
            first.and_then(|e| e.get("key")),
            Some(&Value::from("id_rsa"))
        );
        assert_eq!(
            first.and_then(|e| e.get("last_modified")),
            Some(&Value::from("2023-11-14T22:13:20Z"))
        );
        Ok(())
    }

    #[test]
    fn largest_objects_is_sorted_by_size_descending() -> Result<(), Box<dyn std::error::Error>> {
        let value = render()?;
        let first_key = value
            .get("largest_objects")
            .and_then(Value::as_array)
            .and_then(|entries| entries.first())
            .and_then(|e| e.get("key"));
        assert_eq!(first_key, Some(&Value::from("old/dataset.bin")));
        Ok(())
    }
}
