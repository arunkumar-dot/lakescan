//! End-to-end tests for `--pii`: the built `lakescan` binary against the
//! `lakescan-pii` bucket that `examples/seed_local.rs` fills with the
//! committed Parquet fixtures (`tests/fixtures/parquet`).
//!
//! Ignored by default, like `tests/e2e.rs`, and run the same way:
//!
//! ```text
//! docker run --rm -d -p 5001:5000 motoserver/moto:5.2.3
//! export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1
//! export LAKESCAN_E2E_ENDPOINT=http://localhost:5001
//! cargo run --example seed_local -- "$LAKESCAN_E2E_ENDPOINT"
//! cargo test --test e2e_pii -- --ignored
//! ```

#[path = "support/pii_manifest.rs"]
mod pii_manifest;

use std::collections::BTreeSet;
use std::error::Error;
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

use pii_manifest::{PII_BUCKET, PII_OBJECTS};

type TestResult = Result<(), Box<dyn Error>>;

/// `(key, rule, column, confidence)` of one finding.
type Found = (String, String, String, String);

/// Every `customers.parquet` under `lake/`: four writers at their default
/// codecs, then GZIP (pyarrow, Spark) and BROTLI (pyarrow).
const WRITERS: [&str; 7] = [
    "pyarrow",
    "polars",
    "duckdb",
    "spark",
    "gzip/pyarrow",
    "gzip/spark",
    "brotli/pyarrow",
];

/// What every writer's `customers.parquet` truly holds, with the
/// confidence expected: `(column, rule, confidence)`.
const CUSTOMERS: [(&str, &str, &str); 10] = [
    ("full_name", "pii-person-name", "likely"),
    ("email", "pii-email", "confirmed"),
    ("contact", "pii-phone", "confirmed"),
    ("mobile_no", "pii-phone", "confirmed"),
    ("aadhaar_no", "pii-in-aadhaar", "confirmed"),
    ("pan", "pii-in-pan", "confirmed"),
    ("card_number", "pii-card-number", "confirmed"),
    ("last_login_ip", "pii-ip-address", "confirmed"),
    ("dob", "pii-date-of-birth", "likely"),
    ("billing.email", "pii-email", "confirmed"),
];

fn expected_lake() -> BTreeSet<Found> {
    let mut expected = BTreeSet::new();
    for writer in WRITERS {
        for (column, rule, confidence) in CUSTOMERS {
            expected.insert((
                format!("lake/{writer}/customers.parquet"),
                rule.to_owned(),
                column.to_owned(),
                confidence.to_owned(),
            ));
        }
    }
    expected.insert((
        "lake/escalation.parquet".to_owned(),
        "pii-email".to_owned(),
        "contact_email".to_owned(),
        "confirmed".to_owned(),
    ));
    expected
}

fn endpoint() -> Result<String, Box<dyn Error>> {
    std::env::var("LAKESCAN_E2E_ENDPOINT").map_err(|_| {
        "LAKESCAN_E2E_ENDPOINT is not set; see this file's header for how to run these tests".into()
    })
}

/// One run of the binary: exit code, JSON summary, findings stream, stderr.
struct Run {
    code: Option<i32>,
    summary: Value,
    findings: Vec<Value>,
    stderr: String,
}

/// Scans `s3://lakescan-pii/<prefix>` with a JSON summary, a findings
/// file, and `extra` arguments.
fn run(test: &str, prefix: &str, extra: &[&str]) -> Result<Run, Box<dyn Error>> {
    let findings_path: PathBuf = std::env::temp_dir().join(format!(
        "lakescan-e2e-pii-{}-{test}.jsonl",
        std::process::id()
    ));
    let findings_arg = findings_path.to_str().ok_or("temp path is not UTF-8")?;
    let output = Command::new(env!("CARGO_BIN_EXE_lakescan"))
        .args([
            "scan",
            &format!("s3://{PII_BUCKET}/{prefix}"),
            "--endpoint-url",
            &endpoint()?,
            "--format",
            "json",
            "--findings",
            findings_arg,
        ])
        .args(extra)
        .output()?;
    let findings_text = std::fs::read_to_string(&findings_path);
    std::fs::remove_file(&findings_path).ok();
    let stderr = String::from_utf8(output.stderr)?;
    let summary: Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("stdout is not a JSON summary ({err}); stderr: {stderr}"))?;
    let findings = findings_text?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()?;
    Ok(Run {
        code: output.status.code(),
        summary,
        findings,
        stderr,
    })
}

fn text(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Every PII finding in the stream, as `(key, rule, column, confidence)`.
fn pii_found(run: &Run) -> BTreeSet<Found> {
    run.findings
        .iter()
        .filter(|f| text(f, "rule").starts_with("pii-"))
        .map(|f| {
            (
                text(f, "key"),
                text(f, "rule"),
                text(f, "column"),
                text(f, "confidence"),
            )
        })
        .collect()
}

fn content_u64(run: &Run, pointer: &str) -> Result<u64, Box<dyn Error>> {
    run.summary
        .pointer(&format!("/content/{pointer}"))
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("no /content/{pointer} in {}", run.summary).into())
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn every_writer_s_pii_is_found_at_the_expected_confidence() -> TestResult {
    let run = run("lake", "lake/", &["--pii"])?;
    assert_eq!(
        run.code,
        Some(1),
        "confirmed PII is High; stderr: {}",
        run.stderr
    );
    assert_eq!(pii_found(&run), expected_lake());
    assert_eq!(content_u64(&run, "files_eligible")?, 8);
    assert_eq!(content_u64(&run, "scanned_whole")?, 8);
    // One repeated column (tags) per customers file, and nothing else
    // skipped but the one double (amount) in each.
    assert_eq!(content_u64(&run, "columns_skipped/repeated")?, 7);
    assert_eq!(content_u64(&run, "columns_skipped/unsupported_type")?, 8);
    for reason in ["page_too_large", "unreadable", "unsupported_codec"] {
        assert_eq!(content_u64(&run, &format!("columns_skipped/{reason}"))?, 0);
    }
    // Names and dates of birth rest on the column name alone, with no
    // counts; everything else on values.
    for finding in run
        .findings
        .iter()
        .filter(|f| text(f, "rule").starts_with("pii-"))
    {
        let by_name = matches!(
            text(finding, "rule").as_str(),
            "pii-person-name" | "pii-date-of-birth"
        );
        let expected = if by_name { "column-name" } else { "values" };
        assert_eq!(text(finding, "evidence"), expected, "{finding}");
        assert_eq!(finding.get("matched").is_some(), !by_name, "{finding}");
    }
    // Hashed emails are never an email finding.
    assert!(
        run.findings
            .iter()
            .all(|f| text(f, "column") != "email_sha256"),
        "email_sha256 was reported"
    );
    Ok(())
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn escalation_finds_emails_after_a_junk_first_row_group() -> TestResult {
    let run = run("escalation", "lake/escalation", &["--pii"])?;
    let email = run
        .findings
        .iter()
        .find(|f| text(f, "column") == "contact_email")
        .ok_or("contact_email not found")?;
    assert_eq!(text(email, "confidence"), "confirmed");
    // Row group 0 is all junk: every sampled value came from later ones.
    assert!(email.get("matched") == email.get("sampled"), "{email}");
    Ok(())
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn partial_reads_find_the_same_and_read_fewer_bytes() -> TestResult {
    let whole = run("whole", "lake/", &["--pii"])?;
    let partial = run("partial", "lake/", &["--pii", "--pii-whole-file-max", "0"])?;
    assert_eq!(pii_found(&partial), expected_lake());
    assert_eq!(content_u64(&partial, "scanned_partially")?, 8);
    assert_eq!(content_u64(&partial, "scanned_whole")?, 0);
    let (whole_bytes, partial_bytes) = (
        content_u64(&whole, "bytes_read")?,
        content_u64(&partial, "bytes_read")?,
    );
    // Whole reads fetch exactly every lake/ file, once.
    let mut lake_bytes = 0;
    for (key, path) in PII_OBJECTS {
        if key.starts_with("lake/") {
            lake_bytes += u64::try_from(pii_manifest::fixture(path)?.len())?;
        }
    }
    assert_eq!(whole_bytes, lake_bytes);
    assert!(
        partial_bytes < whole_bytes,
        "partial {partial_bytes} >= whole {whole_bytes}"
    );
    assert!(content_u64(&partial, "get_requests")? > content_u64(&whole, "get_requests")?);
    Ok(())
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn unreadable_files_are_reported_and_exit_six_when_nothing_was_scanned() -> TestResult {
    let run = run("bad", "bad/", &["--pii"])?;
    assert_eq!(run.code, Some(6), "stderr: {}", run.stderr);
    assert_eq!(content_u64(&run, "not_scanned/not-parquet")?, 1);
    assert_eq!(content_u64(&run, "not_scanned/unreadable")?, 1);
    assert!(
        run.stderr
            .contains("no Parquet file could be content-scanned (2 eligible"),
        "{}",
        run.stderr
    );
    let reasons: BTreeSet<(String, String)> = run
        .findings
        .iter()
        .filter(|f| text(f, "rule") == "content-not-scanned")
        .map(|f| (text(f, "key"), text(f, "reason")))
        .collect();
    assert_eq!(
        reasons,
        BTreeSet::from([
            (
                "bad/not_parquet.parquet".to_owned(),
                "not-parquet".to_owned()
            ),
            ("bad/truncated.parquet".to_owned(), "unreadable".to_owned()),
        ])
    );
    Ok(())
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn gzip_and_brotli_files_are_decoded_and_their_pii_found() -> TestResult {
    for (prefix, writers) in [
        ("lake/gzip/", &["gzip/pyarrow", "gzip/spark"][..]),
        ("lake/brotli/", &["brotli/pyarrow"][..]),
    ] {
        for (test, extra) in [
            ("whole", &["--pii"][..]),
            ("partial", &["--pii", "--pii-whole-file-max", "0"][..]),
        ] {
            let run = run(&format!("codec-{test}"), prefix, extra)?;
            assert_eq!(run.code, Some(1), "{prefix} {test}; stderr: {}", run.stderr);
            let expected: BTreeSet<Found> = expected_lake()
                .into_iter()
                .filter(|(key, ..)| {
                    writers
                        .iter()
                        .any(|w| key == &format!("lake/{w}/customers.parquet"))
                })
                .collect();
            assert_eq!(expected.len(), CUSTOMERS.len() * writers.len());
            assert_eq!(pii_found(&run), expected, "{prefix} {test}");
            assert_eq!(content_u64(&run, "columns_skipped/unreadable")?, 0);
            assert_eq!(content_u64(&run, "not_scanned/no-column-examined")?, 0);
        }
    }
    Ok(())
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn a_lake_of_files_with_every_column_skipped_exits_six() -> TestResult {
    // Parquet that opens, but whose one string column has a data page over
    // the page cap: no value was examined, so the file was not scanned.
    for extra in [&["--pii"][..], &["--pii", "--pii-whole-file-max", "0"][..]] {
        let run = run("skipped", "skipped/", extra)?;
        assert_eq!(run.code, Some(6), "stderr: {}", run.stderr);
        assert_eq!(content_u64(&run, "not_scanned/no-column-examined")?, 1);
        assert_eq!(content_u64(&run, "columns_skipped/page_too_large")?, 1);
        assert_eq!(content_u64(&run, "columns_examined")?, 0);
        assert!(
            run.stderr.contains(
                "no Parquet file could be content-scanned (1 eligible: no-column-examined=1)"
            ),
            "{}",
            run.stderr
        );
        let reasons: Vec<(String, String)> = run
            .findings
            .iter()
            .map(|f| (text(f, "rule"), text(f, "reason")))
            .collect();
        assert_eq!(
            reasons,
            [(
                "content-not-scanned".to_owned(),
                "no-column-examined".to_owned()
            )]
        );
    }
    Ok(())
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn a_whole_bucket_scan_reports_both_and_does_not_exit_six() -> TestResult {
    let run = run("all", "", &["--pii"])?;
    assert_eq!(run.code, Some(1), "stderr: {}", run.stderr);
    assert_eq!(
        content_u64(&run, "files_eligible")?,
        u64::try_from(PII_OBJECTS.len())?
    );
    assert_eq!(pii_found(&run), expected_lake());
    Ok(())
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn a_column_suppression_covers_exactly_that_column() -> TestResult {
    let config = std::env::temp_dir().join(format!("lakescan-e2e-pii-{}.toml", std::process::id()));
    std::fs::write(
        &config,
        "version = 1\n\n[[suppress]]\nrule = \"pii-email\"\nprefix = \"lake/\"\n\
         column = \"email\"\nreason = \"Consented marketing contacts\"\n",
    )?;
    let config_arg = config.to_str().ok_or("temp path is not UTF-8")?.to_owned();
    let result = run("suppressed", "lake/", &["--pii", "--config", &config_arg]);
    std::fs::remove_file(&config).ok();
    let run = result?;

    let expected: BTreeSet<Found> = expected_lake()
        .into_iter()
        .filter(|(_, rule, column, _)| !(rule == "pii-email" && column == "email"))
        .collect();
    assert_eq!(pii_found(&run), expected);
    let email = run
        .summary
        .get("findings")
        .and_then(Value::as_array)
        .and_then(|all| all.iter().find(|f| text(f, "rule") == "pii-email"))
        .ok_or("pii-email missing from the summary")?;
    assert_eq!(
        email.pointer("/suppressed/count").and_then(Value::as_u64),
        Some(u64::try_from(WRITERS.len())?)
    );
    Ok(())
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn without_pii_nothing_is_read() -> TestResult {
    let run = run("off", "lake/", &[])?;
    assert_eq!(run.summary.get("content"), Some(&Value::Null));
    assert!(pii_found(&run).is_empty());
    Ok(())
}
