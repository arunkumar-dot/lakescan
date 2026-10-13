//! End-to-end tests: the built `lakescan` binary against a live
//! S3-compatible server seeded by `examples/seed_local.rs`.
//!
//! Ignored by default, since they need that server. To run them:
//!
//! ```text
//! docker run --rm -d -p 5000:5000 motoserver/moto:5.2.3
//! export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1
//! export LAKESCAN_E2E_ENDPOINT=http://localhost:5000
//! cargo run --example seed_local -- "$LAKESCAN_E2E_ENDPOINT"
//! cargo test --test e2e -- --ignored
//! ```

#[path = "support/seed_manifest.rs"]
mod seed_manifest;

use std::collections::BTreeMap;
use std::error::Error;
use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

use seed_manifest::{BUCKET, HOSTILE_KEYS};

type TestResult = Result<(), Box<dyn Error>>;

/// The seeded server's endpoint, or an error explaining how to provide one.
fn endpoint() -> Result<String, Box<dyn Error>> {
    std::env::var("LAKESCAN_E2E_ENDPOINT").map_err(|_| {
        "LAKESCAN_E2E_ENDPOINT is not set. These tests need a seeded S3-compatible \
         server: start motoserver/moto:5.2.3 on port 5000, run \
         `cargo run --example seed_local -- http://localhost:5000`, then set \
         LAKESCAN_E2E_ENDPOINT=http://localhost:5000 (see this file's header)"
            .into()
    })
}

/// Runs the built binary as `lakescan scan <target> --endpoint-url <endpoint>
/// --quiet <extra...>`.
fn scan(target: &str, extra: &[&str]) -> Result<Output, Box<dyn Error>> {
    let endpoint = endpoint()?;
    let output = Command::new(env!("CARGO_BIN_EXE_lakescan"))
        .args([
            "scan",
            target,
            "--endpoint-url",
            endpoint.as_str(),
            "--quiet",
        ])
        .args(extra)
        .output()?;
    Ok(output)
}

/// A findings file path unique to this process and test.
fn findings_path(test: &str) -> PathBuf {
    std::env::temp_dir().join(format!("lakescan-e2e-{}-{test}.jsonl", std::process::id()))
}

/// One scan of the demo bucket: its exit code, its JSON summary, and every
/// record from its findings stream.
struct DemoScan {
    code: Option<i32>,
    summary: Value,
    findings: Vec<Value>,
}

/// Scans the demo bucket with a JSON summary and a findings file.
fn scan_demo_bucket(test: &str) -> Result<DemoScan, Box<dyn Error>> {
    let path = findings_path(test);
    let path_arg = path.to_str().ok_or("temp path is not UTF-8")?;
    let output = scan(
        &format!("s3://{BUCKET}"),
        &["--format", "json", "--findings", path_arg],
    )?;
    let findings_text = std::fs::read_to_string(&path);
    std::fs::remove_file(&path).ok();

    let summary: Value = serde_json::from_slice(&output.stdout).map_err(|err| {
        format!(
            "stdout is not a JSON summary ({err}); stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    })?;
    let findings = findings_text?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()?;
    Ok(DemoScan {
        code: output.status.code(),
        summary,
        findings,
    })
}

fn str_field<'a>(value: &'a Value, field: &str) -> Result<&'a str, Box<dyn Error>> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {field:?} in {value}").into())
}

fn u64_field(value: &Value, field: &str) -> Result<u64, Box<dyn Error>> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing integer field {field:?} in {value}").into())
}

fn array_field<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>, Box<dyn Error>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing array field {field:?} in {value}").into())
}

/// `rule code -> severity code -> count`, non-zero counts only.
type RuleCounts = BTreeMap<String, BTreeMap<String, u64>>;

fn expected_rule_counts() -> RuleCounts {
    let rule = |counts: &[(&str, u64)]| {
        counts
            .iter()
            .map(|(severity, count)| ((*severity).to_owned(), *count))
            .collect::<BTreeMap<_, _>>()
    };
    BTreeMap::from([
        // id_rsa, .env.production, infra/terraform.tfstate;
        // app/.git/config, certs/server.pem.
        (
            "sensitive-key".to_owned(),
            rule(&[("high", 3), ("medium", 2)]),
        ),
        // backups/old.tar.
        ("reduced-redundancy".to_owned(), rule(&[("medium", 1)])),
        // cold/thumb.jpg (GLACIER), cold/tiny.csv (STANDARD_IA).
        ("small-object-cold-tier".to_owned(), rule(&[("low", 2)])),
        // placeholder/empty.txt and the three hostile keys; folder-marker/
        // is exempt.
        ("zero-byte-object".to_owned(), rule(&[("info", 4)])),
    ])
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn the_default_scan_fails_and_accounts_for_every_object_and_finding() -> TestResult {
    let DemoScan {
        code,
        summary,
        findings,
    } = scan_demo_bucket("default")?;
    assert_eq!(code, Some(1), "default --fail-on high should fail");

    let objects = seed_manifest::objects();
    let inventory = summary.get("inventory").ok_or("summary has no inventory")?;
    assert_eq!(
        u64_field(inventory, "object_count")?,
        u64::try_from(objects.len())?
    );
    let written_bytes: usize = objects.iter().map(|object| object.body.len()).sum();
    assert_eq!(
        u64_field(inventory, "total_bytes")?,
        u64::try_from(written_bytes)?
    );

    let mut written_classes: BTreeMap<String, u64> = BTreeMap::new();
    for object in &objects {
        *written_classes
            .entry(object.storage_class.to_owned())
            .or_default() += 1;
    }
    let mut listed_classes = BTreeMap::new();
    for class in array_field(inventory, "by_storage_class")? {
        listed_classes.insert(
            str_field(class, "storage_class")?.to_owned(),
            u64_field(class, "count")?,
        );
    }
    assert_eq!(listed_classes, written_classes);

    // The summary's per-rule matrix.
    let mut summary_counts = RuleCounts::new();
    for rule in array_field(&summary, "findings")? {
        let counts = rule
            .get("counts")
            .and_then(Value::as_object)
            .ok_or("finding has no counts")?;
        let nonzero = counts
            .iter()
            .filter_map(|(severity, count)| {
                count
                    .as_u64()
                    .filter(|count| *count > 0)
                    .map(|count| (severity.clone(), count))
            })
            .collect();
        summary_counts.insert(str_field(rule, "rule")?.to_owned(), nonzero);
    }
    assert_eq!(summary_counts, expected_rule_counts());

    // The findings stream, independently.
    let mut stream_counts = RuleCounts::new();
    for finding in &findings {
        *stream_counts
            .entry(str_field(finding, "rule")?.to_owned())
            .or_default()
            .entry(str_field(finding, "severity")?.to_owned())
            .or_default() += 1;
    }
    assert_eq!(stream_counts, expected_rule_counts());

    // Every finding names a key that was actually written.
    for finding in &findings {
        let key = str_field(finding, "key")?;
        assert!(
            objects.iter().any(|object| object.key == key),
            "finding for unwritten key {key:?}"
        );
    }

    Ok(())
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn every_hostile_key_round_trips_byte_for_byte() -> TestResult {
    let DemoScan { findings, .. } = scan_demo_bucket("hostile")?;

    let zero_byte_keys: Vec<&str> = findings
        .iter()
        .filter(|finding| str_field(finding, "rule").ok() == Some("zero-byte-object"))
        .map(|finding| str_field(finding, "key"))
        .collect::<Result<_, _>>()?;

    for hostile in HOSTILE_KEYS {
        assert!(
            zero_byte_keys
                .iter()
                .any(|key| key.as_bytes() == hostile.as_bytes()),
            "{hostile:?} did not round-trip; zero-byte keys were {zero_byte_keys:?}"
        );
    }
    Ok(())
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn fail_on_none_exits_zero() -> TestResult {
    let output = scan(&format!("s3://{BUCKET}"), &["--fail-on", "none"])?;
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn a_nonexistent_bucket_exits_two() -> TestResult {
    let output = scan("s3://lakescan-e2e-no-such-bucket", &[])?;
    let stderr = String::from_utf8(output.stderr)?;
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.starts_with("lakescan: usage: "), "stderr: {stderr}");
    assert_eq!(stderr.lines().count(), 1, "stderr: {stderr}");
    Ok(())
}
