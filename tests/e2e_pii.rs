//! End-to-end tests for `--pii`: the built `lakescan` binary against the
//! `lakescan-pii` bucket that `examples/seed_local.rs` fills with the
//! committed Parquet fixtures (`tests/fixtures/parquet`), laid out in
//! partitioned tables (see `tests/support/pii_manifest.rs`).
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
//!
//! Set `LAKESCAN_E2E_CONCURRENCY` to run every `--pii` scan at that
//! `--concurrency` (the CLI default, 16, otherwise); CI runs the suite at 1
//! and at 16. Whatever it is, the outputs must be identical, which one
//! test checks directly.

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

/// What every `customers.parquet` truly holds, with the confidence
/// expected: `(column, rule, confidence)`.
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

/// The keys of every writer's `customers.parquet`: four writers at their
/// default codecs, then GZIP (pyarrow, Spark) and BROTLI (pyarrow).
fn customer_keys() -> Vec<&'static str> {
    PII_OBJECTS
        .iter()
        .filter(|(_, path)| path.ends_with("customers.parquet"))
        .map(|(key, _)| *key)
        .collect()
}

fn expected_for(keys: &[&str]) -> BTreeSet<Found> {
    let mut expected = BTreeSet::new();
    for key in keys {
        for (column, rule, confidence) in CUSTOMERS {
            expected.insert((
                (*key).to_owned(),
                rule.to_owned(),
                column.to_owned(),
                confidence.to_owned(),
            ));
        }
    }
    expected
}

fn expected_lake() -> BTreeSet<Found> {
    let mut expected = expected_for(&customer_keys());
    expected.insert((
        "lake/events/data/dt=2026-01-01/part-0.parquet".to_owned(),
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

/// One run of the binary: exit code, JSON summary, findings stream,
/// inventory CSV, stderr.
struct Run {
    code: Option<i32>,
    summary: Value,
    findings: Vec<Value>,
    inventory: String,
    html: String,
    stderr: String,
}

fn temp_path(test: &str, extension: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "lakescan-e2e-pii-{}-{test}.{extension}",
        std::process::id()
    ))
}

/// Scans `s3://lakescan-pii/<prefix>` with a JSON summary, a findings
/// file, an inventory CSV (with `--pii`), and `extra` arguments.
fn run(test: &str, prefix: &str, extra: &[&str]) -> Result<Run, Box<dyn Error>> {
    let findings_path = temp_path(test, "jsonl");
    let inventory_path = temp_path(test, "csv");
    let html_path = temp_path(test, "html");
    let html_arg = html_path.to_str().ok_or("temp path is not UTF-8")?;
    let findings_arg = findings_path.to_str().ok_or("temp path is not UTF-8")?;
    let inventory_arg = inventory_path.to_str().ok_or("temp path is not UTF-8")?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_lakescan"));
    command
        .args([
            "scan",
            &format!("s3://{PII_BUCKET}/{prefix}"),
            "--endpoint-url",
            &endpoint()?,
            "--format",
            "json",
            "--findings",
            findings_arg,
            "--html",
            html_arg,
        ])
        .args(extra);
    if extra.contains(&"--pii") {
        command.args(["--inventory", inventory_arg]);
        if !extra.contains(&"--concurrency")
            && let Ok(concurrency) = std::env::var("LAKESCAN_E2E_CONCURRENCY")
        {
            command.args(["--concurrency", &concurrency]);
        }
    }
    let output = command.output()?;
    let findings_text = std::fs::read_to_string(&findings_path);
    let inventory = std::fs::read_to_string(&inventory_path).unwrap_or_default();
    let html = std::fs::read_to_string(&html_path).unwrap_or_default();
    std::fs::remove_file(&html_path).ok();
    std::fs::remove_file(&findings_path).ok();
    std::fs::remove_file(&inventory_path).ok();
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
        inventory,
        html,
        stderr,
    })
}

/// Writes `body` to a temp config file and runs with `--config` pointing
/// at it.
fn run_with_config(
    test: &str,
    prefix: &str,
    body: &str,
    extra: &[&str],
) -> Result<Run, Box<dyn Error>> {
    let config = temp_path(test, "toml");
    std::fs::write(&config, body)?;
    let config_arg = config.to_str().ok_or("temp path is not UTF-8")?.to_owned();
    let mut args = extra.to_vec();
    args.extend(["--config", &config_arg]);
    let result = run(test, prefix, &args);
    std::fs::remove_file(&config).ok();
    result
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

/// A strict RFC 4180 reader: records of fields, quotes undone.
fn parse_csv(text: &str) -> Option<Vec<Vec<String>>> {
    let (mut records, mut record, mut field) = (Vec::new(), Vec::new(), String::new());
    let mut chars = text.chars().peekable();
    let (mut quoted, mut at_start) = (false, true);
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                chars.next();
                field.push('"');
            }
            (true, '"') => quoted = false,
            (false, '"') if at_start => quoted = true,
            (false, ',') => {
                record.push(std::mem::take(&mut field));
                at_start = true;
                continue;
            }
            (false, '\r') if chars.peek() == Some(&'\n') => {
                chars.next();
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
                at_start = true;
                continue;
            }
            (false, '"' | '\r' | '\n') => return None,
            (_, c) => field.push(c),
        }
        at_start = false;
    }
    (!quoted && field.is_empty() && record.is_empty()).then_some(records)
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
fn the_inventory_groups_partitioned_files_into_tables() -> TestResult {
    let run = run("tables", "lake/", &["--pii"])?;
    let tables = run
        .summary
        .pointer("/pii_inventory/tables")
        .and_then(Value::as_array)
        .ok_or("no pii_inventory tables")?;
    let summary: Vec<(String, u64, u64, usize)> = tables
        .iter()
        .map(|t| {
            (
                text(t, "table"),
                t.get("files_eligible").and_then(Value::as_u64).unwrap_or(0),
                t.get("files_scanned").and_then(Value::as_u64).unwrap_or(0),
                t.get("columns")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            // Hive partitions, one nested (dt=/region=).
            ("lake/customers".to_owned(), 4, 4, CUSTOMERS.len()),
            // Iceberg data/.
            ("lake/customers_brotli".to_owned(), 1, 1, CUSTOMERS.len()),
            ("lake/customers_gzip".to_owned(), 2, 2, CUSTOMERS.len()),
            // Iceberg data/ with a partition under it.
            ("lake/events".to_owned(), 1, 1, 1),
        ]
    );
    let customers = tables.first().ok_or("no table")?;
    assert_eq!(
        text(customers, "example_key"),
        "lake/customers/dt=2026-01-01/part-0.parquet"
    );
    let email = customers
        .get("columns")
        .and_then(Value::as_array)
        .and_then(|columns| columns.iter().find(|c| text(c, "column") == "email"))
        .ok_or("no email column")?;
    assert_eq!(
        email,
        &serde_json::json!({
            "column": "email",
            "rule": "pii-email",
            "highest_confidence": "confirmed",
            "evidence": "values",
            "files_confirmed": 4,
            "files_likely": 0,
            "files_possible": 0,
            "files_suppressed": 0,
            "status": "UNDOCUMENTED",
            "reason": null
        })
    );
    assert_eq!(
        run.summary.pointer("/pii_inventory/left_out"),
        Some(&serde_json::json!({ "files": 0, "findings": 0 }))
    );
    assert_eq!(
        run.summary.pointer("/pii_inventory/summary"),
        Some(&serde_json::json!({
            "tables_with_pii": 4,
            "pii_columns": 3 * CUSTOMERS.len() + 1,
            "undocumented": 3 * CUSTOMERS.len() + 1,
            "documented": 0,
            "tables_not_fully_scanned": 0,
            "tables_not_fully_scanned_documented": 0
        }))
    );
    assert!(tables.iter().all(|t| text(t, "status") == "pii_found"));
    Ok(())
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn escalation_finds_emails_after_a_junk_first_row_group() -> TestResult {
    let run = run("escalation", "lake/events/", &["--pii"])?;
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
fn gzip_and_brotli_files_are_decoded_and_their_pii_found() -> TestResult {
    for (prefix, keys) in [
        (
            "lake/customers_gzip/",
            &[
                "lake/customers_gzip/dt=2026-01-01/part-0.parquet",
                "lake/customers_gzip/dt=2026-01-02/part-0.parquet",
            ][..],
        ),
        (
            "lake/customers_brotli/",
            &["lake/customers_brotli/data/part-0.parquet"][..],
        ),
    ] {
        for (test, extra) in [
            ("whole", &["--pii"][..]),
            ("partial", &["--pii", "--pii-whole-file-max", "0"][..]),
        ] {
            let run = run(&format!("codec-{test}"), prefix, extra)?;
            assert_eq!(run.code, Some(1), "{prefix} {test}; stderr: {}", run.stderr);
            assert_eq!(pii_found(&run), expected_for(keys), "{prefix} {test}");
            assert_eq!(content_u64(&run, "columns_skipped/unreadable")?, 0);
            assert_eq!(content_u64(&run, "not_scanned/no-column-examined")?, 0);
        }
    }
    Ok(())
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn unreadable_files_are_reported_and_exit_six() -> TestResult {
    let run = run("bad", "bad/", &["--pii"])?;
    assert_eq!(run.code, Some(6), "stderr: {}", run.stderr);
    assert_eq!(content_u64(&run, "not_scanned/not-parquet")?, 1);
    assert_eq!(content_u64(&run, "not_scanned/unreadable")?, 1);
    assert!(
        run.stderr.contains(
            "2 of 2 eligible Parquet files could not be content-scanned and are not documented \
             (not-parquet=1, unreadable=1)"
        ),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("content-not-scanned suppression"),
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
                "1 of 1 eligible Parquet files could not be content-scanned and are not \
                 documented (no-column-examined=1)"
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
fn a_mixed_lake_fails_closed_until_its_unscannable_files_are_documented() -> TestResult {
    // The whole bucket: eight readable files with confirmed PII, and three
    // that cannot be scanned. Undocumented, those win: exit 6, not 1.
    let run_all = run("all", "", &["--pii"])?;
    assert_eq!(run_all.code, Some(6), "stderr: {}", run_all.stderr);
    assert!(
        run_all
            .stderr
            .contains("3 of 11 eligible Parquet files could not be content-scanned"),
        "{}",
        run_all.stderr
    );
    assert_eq!(
        content_u64(&run_all, "files_eligible")?,
        u64::try_from(PII_OBJECTS.len())?
    );
    assert_eq!(pii_found(&run_all), expected_lake());
    assert_eq!(
        run_all.summary.get("coverage"),
        Some(&serde_json::json!({
            "files_eligible": 11,
            "files_scanned": 8,
            "not_scanned_suppressed": 0,
            "not_scanned_unsuppressed": 3,
            "percent": 72.7
        }))
    );

    // One bad file documented, the other two not: still exit 6.
    let one = run_with_config(
        "one-documented",
        "",
        "version = 1\n\n[[suppress]]\nrule = \"content-not-scanned\"\n\
         key = \"bad/truncated.parquet\"\nreason = \"Truncated upload, INC-7\"\n",
        &["--pii"],
    )?;
    assert_eq!(one.code, Some(6), "stderr: {}", one.stderr);
    assert!(one.stderr.contains("2 of 11"), "{}", one.stderr);

    // All documented: the run exits by severity (1, confirmed PII), and
    // the inventory says why each table is short of files.
    let documented = run_with_config(
        "all-documented",
        "",
        "version = 1\n\n[[suppress]]\nrule = \"content-not-scanned\"\nprefix = \"bad/\"\n\
         reason = \"Quarantined uploads, INC-7\"\n\n[[suppress]]\n\
         rule = \"content-not-scanned\"\nkey = \"skipped/too_large.parquet\"\n\
         reason = \"Blob column, no personal data\"\nexpires = 2099-12-31\n",
        &["--pii"],
    )?;
    assert_eq!(documented.code, Some(1), "stderr: {}", documented.stderr);
    assert_eq!(documented.stderr, "");
    assert_eq!(
        documented
            .summary
            .pointer("/coverage/not_scanned_suppressed"),
        Some(&Value::from(3))
    );
    let bad = documented
        .summary
        .pointer("/pii_inventory/tables")
        .and_then(Value::as_array)
        .and_then(|tables| tables.iter().find(|t| text(t, "table") == "bad"))
        .ok_or("no bad table")?;
    // Nothing in bad/ was read, so its PII is unknown, not absent.
    assert_eq!(text(bad, "status"), "not_scanned");
    assert_eq!(
        documented
            .summary
            .pointer("/pii_inventory/summary/tables_not_fully_scanned"),
        Some(&Value::from(2))
    );
    assert_eq!(
        bad.get("not_scanned"),
        Some(&serde_json::json!({
            "not-parquet": { "suppressed": 1, "unsuppressed": 0 },
            "unreadable": { "suppressed": 1, "unsuppressed": 0 }
        }))
    );
    Ok(())
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn a_column_suppression_documents_that_location_in_the_inventory_and_csv() -> TestResult {
    let run = run_with_config(
        "suppressed",
        "lake/",
        "version = 1\n\n[[suppress]]\nrule = \"pii-email\"\nprefix = \"lake/\"\n\
         column = \"email\"\nreason = \"Consented marketing contacts, DPA-12\"\n",
        &["--pii"],
    )?;

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
        email.pointer("/suppressed/count"),
        Some(&Value::from(u64::try_from(customer_keys().len())?))
    );
    // PII rules carry no bytes.
    assert_eq!(email.pointer("/bytes/high"), Some(&Value::from(0)));
    assert_eq!(email.pointer("/suppressed/bytes"), Some(&Value::from(0)));

    // The CSV: a header, then one row per (table, column, rule).
    let rows = parse_csv(&run.inventory).ok_or("the inventory is not valid CSV")?;
    assert_eq!(
        rows.first().map(|header| header.join(",")),
        Some(
            "table,column,rule,highest_confidence,evidence,files_confirmed,files_likely,\
             files_possible,files_suppressed,status,reason,example_key"
                .to_owned()
        )
    );
    // 3 customers tables of 10 locations each, events' 1, and the header.
    assert_eq!(rows.len(), 3 * CUSTOMERS.len() + 1 + 1);
    let row = |table: &str, column: &str| {
        rows.iter()
            .find(|r| {
                r.first().map(String::as_str) == Some(table)
                    && r.get(1).map(String::as_str) == Some(column)
            })
            .cloned()
            .unwrap_or_default()
    };
    assert_eq!(
        row("lake/customers", "email"),
        [
            "lake/customers",
            "email",
            "pii-email",
            "confirmed",
            "values",
            "0",
            "0",
            "0",
            "4",
            "documented",
            "Consented marketing contacts, DPA-12",
            "lake/customers/dt=2026-01-01/part-0.parquet",
        ]
    );
    assert_eq!(
        row("lake/customers", "billing.email"),
        [
            "lake/customers",
            "billing.email",
            "pii-email",
            "confirmed",
            "values",
            "4",
            "0",
            "0",
            "0",
            "UNDOCUMENTED",
            "",
            "lake/customers/dt=2026-01-01/part-0.parquet",
        ]
    );
    // The JSON inventory says the same.
    let status = run
        .summary
        .pointer("/pii_inventory/tables/0/columns")
        .and_then(Value::as_array)
        .and_then(|columns| columns.iter().find(|c| text(c, "column") == "email"))
        .map(|c| (text(c, "status"), text(c, "reason")));
    assert_eq!(
        status,
        Some((
            "documented".to_owned(),
            "Consented marketing contacts, DPA-12".to_owned()
        ))
    );
    Ok(())
}

/// `summary` without the fields that time a run.
fn untimed(mut summary: Value) -> Value {
    if let Some(scan) = summary.get_mut("scan").and_then(Value::as_object_mut) {
        scan.remove("started_at");
        scan.remove("elapsed_ms");
    }
    summary
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn every_output_is_identical_at_concurrency_1_and_16() -> TestResult {
    for whole_file_max in ["0", "8388608"] {
        let mut runs = Vec::new();
        for concurrency in ["1", "16"] {
            runs.push(run(
                &format!("c{concurrency}-{whole_file_max}"),
                "",
                &[
                    "--pii",
                    "--concurrency",
                    concurrency,
                    "--pii-whole-file-max",
                    whole_file_max,
                ],
            )?);
        }
        let [one, sixteen] = runs.as_slice() else {
            return Err("two runs expected".into());
        };
        assert_eq!(one.code, sixteen.code);
        assert_eq!(
            untimed(one.summary.clone()),
            untimed(sixteen.summary.clone())
        );
        assert_eq!(one.findings, sixteen.findings);
        assert_eq!(one.inventory, sixteen.inventory);
        // The HTML report, without its timing lines.
        let untimed_html = |html: &str| {
            html.lines()
                .filter(|line| !line.contains("class=\"timing\""))
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(untimed_html(&one.html), untimed_html(&sixteen.html));
        assert!(one.html.contains("<h2>PII inventory</h2>"));
        assert_eq!(one.stderr, sixteen.stderr);
        assert_ne!(one.inventory, "");
    }
    Ok(())
}

#[test]
#[ignore = "needs a seeded S3-compatible server; see this file's header"]
fn without_pii_nothing_is_read() -> TestResult {
    let run = run("off", "lake/", &[])?;
    assert_eq!(run.summary.get("content"), Some(&Value::Null));
    assert_eq!(run.summary.get("coverage"), Some(&Value::Null));
    assert_eq!(run.summary.get("pii_inventory"), Some(&Value::Null));
    assert!(pii_found(&run).is_empty());
    // Without --pii, the HTML report has the metadata sections only.
    assert!(run.html.contains("<h2>Metadata findings</h2>"));
    assert!(!run.html.contains("PII inventory"));
    Ok(())
}
