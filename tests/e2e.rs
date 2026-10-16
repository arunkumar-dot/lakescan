//! End-to-end tests: the built `lakescan` binary against a live
//! S3-compatible server seeded by `examples/seed_local.rs`.
//!
//! Ignored by default, since they need that server. To run them:
//!
//! ```text
//! docker run --rm -d -p 5001:5000 motoserver/moto:5.2.3
//! AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1 \
//!   cargo run --example seed_local -- http://localhost:5001
//! AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1 \
//!   LAKESCAN_E2E_ENDPOINT=http://localhost:5001 \
//!   cargo test --test e2e -- --ignored
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
         server: start motoserver/moto:5.2.3 on host port 5001, run \
         `cargo run --example seed_local -- http://localhost:5001`, then set \
         LAKESCAN_E2E_ENDPOINT=http://localhost:5001 (see this file's header)"
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

/// Scans the demo bucket with a JSON summary, a findings file, and any
/// `extra` arguments.
fn scan_demo_bucket(test: &str, extra: &[&str]) -> Result<DemoScan, Box<dyn Error>> {
    let path = findings_path(test);
    let path_arg = path.to_str().ok_or("temp path is not UTF-8")?;
    let mut args = vec!["--format", "json", "--findings", path_arg];
    args.extend_from_slice(extra);
    let output = scan(&format!("s3://{BUCKET}"), &args)?;
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
    } = scan_demo_bucket("default", &[])?;
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
    let DemoScan { findings, .. } = scan_demo_bucket("hostile", &[])?;

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

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn a_config_suppressing_id_rsa_lowers_high_by_one_but_still_fails() -> TestResult {
    let config_path =
        std::env::temp_dir().join(format!("lakescan-e2e-{}-suppress.toml", std::process::id()));
    std::fs::write(
        &config_path,
        format!(
            "version = 1\n\n[[suppress]]\nrule = \"sensitive-key\"\nkey = \"id_rsa\"\n\
             reason = \"Demo key, not a real secret\"\nbucket = \"{BUCKET}\"\n"
        ),
    )?;
    let config_arg = config_path.to_str().ok_or("temp path is not UTF-8")?;
    let result = scan_demo_bucket("suppressed", &["--config", config_arg]);
    std::fs::remove_file(&config_path).ok();
    let DemoScan {
        code,
        summary,
        findings,
    } = result?;

    // Two High sensitive-key findings remain (.env.production and
    // infra/terraform.tfstate), so the default --fail-on high still fails.
    assert_eq!(code, Some(1));

    let sensitive = array_field(&summary, "findings")?
        .iter()
        .find(|entry| str_field(entry, "rule").ok() == Some("sensitive-key"))
        .ok_or("sensitive-key missing from the summary")?;
    let counts = sensitive.get("counts").ok_or("no counts")?;
    assert_eq!(u64_field(counts, "high")?, 2);
    assert_eq!(u64_field(counts, "medium")?, 2);

    let id_rsa_bytes = seed_manifest::objects()
        .iter()
        .find(|object| object.key == "id_rsa")
        .map(|object| object.body.len())
        .ok_or("id_rsa missing from the manifest")?;
    let suppressed = sensitive.get("suppressed").ok_or("no suppressed field")?;
    assert_eq!(u64_field(suppressed, "count")?, 1);
    assert_eq!(
        u64_field(suppressed, "bytes")?,
        u64::try_from(id_rsa_bytes)?
    );

    // The one entry was used and has not expired.
    assert_eq!(
        summary.get("suppressions"),
        Some(&serde_json::json!({ "expired": [], "unused": [] }))
    );

    // Suppressed findings never reach the stream.
    assert!(
        findings
            .iter()
            .all(|finding| str_field(finding, "key").ok() != Some("id_rsa")),
        "id_rsa was suppressed but still streamed"
    );
    // 12 findings in the demo bucket, minus the suppressed one.
    assert_eq!(findings.len(), 11);
    Ok(())
}
