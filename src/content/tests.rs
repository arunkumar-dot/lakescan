//! Tests for whole files: built in memory with the `parquet` crate's own
//! writer and read back through an in-memory [`ObjectReader`].
//!
//! [`ObjectReader`]: super::ObjectReader

use std::time::SystemTime;

use super::testing::{
    Layout, MemoryReader, Values, aadhaars, digests, emails, mobiles, parquet_file,
};
use super::{FileOutcome, FileScan, PAGE_CAP, is_eligible, scan_file};
use crate::model::{Confidence, Evidence, NotScannedReason, ObjectMeta, PiiType, StorageClass};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn object(key: &str, size: usize) -> ObjectMeta {
    ObjectMeta {
        key: key.to_owned(),
        size: u64::try_from(size).unwrap_or(u64::MAX),
        last_modified: SystemTime::UNIX_EPOCH,
        etag: "etag".to_owned(),
        storage_class: StorageClass::Standard,
    }
}

/// Scans `body` stored as `key` with `whole_file_max`.
async fn scan(key: &str, body: Vec<u8>, whole_file_max: u64) -> (FileScan, MemoryReader) {
    let meta = object(key, body.len());
    let mut reader = MemoryReader::default().with(key, body);
    let scan = scan_file(&mut reader, &meta, whole_file_max).await;
    (scan, reader)
}

/// `(column, type, confidence)` for every finding, in column order.
fn verdicts(scan: &FileScan) -> Vec<(String, PiiType, Confidence)> {
    scan.columns
        .iter()
        .map(|c| (c.detail.column.clone(), c.pii, c.detail.confidence))
        .collect()
}

/// A customers-like table: emails, a hashed-email decoy, INT64 phones and
/// Aadhaar numbers, a name, a date of birth, a repeated column and a
/// double.
fn customers(rows: usize) -> Vec<(&'static str, Values)> {
    vec![
        ("email", Values::Text(emails(rows))),
        ("email_sha256", Values::Text(digests(rows))),
        ("mobile_no", Values::Int64(mobiles(rows))),
        ("c9", Values::Int64(aadhaars(rows))),
        (
            "full_name",
            Values::Text((0..rows).map(|i| Some(format!("Person {i}"))).collect()),
        ),
        (
            "dob",
            Values::Date((0..rows).map(|i| i32::try_from(i).ok()).collect()),
        ),
        (
            "tags",
            Values::RepeatedText((0..rows).map(|i| format!("tag{i}")).collect()),
        ),
        (
            "score",
            Values::Double(
                (0..rows)
                    .map(|i| f64::from(u32::try_from(i).unwrap_or(0)))
                    .collect(),
            ),
        ),
    ]
}

fn expected_customers() -> Vec<(String, PiiType, Confidence)> {
    vec![
        ("email".to_owned(), PiiType::Email, Confidence::Confirmed),
        (
            "mobile_no".to_owned(),
            PiiType::Phone,
            Confidence::Confirmed,
        ),
        ("c9".to_owned(), PiiType::InAadhaar, Confidence::Confirmed),
        (
            "full_name".to_owned(),
            PiiType::PersonName,
            Confidence::Likely,
        ),
        ("dob".to_owned(), PiiType::DateOfBirth, Confidence::Likely),
    ]
}

#[test]
fn parquet_keys_are_eligible_in_any_case() {
    for key in ["a.parquet", "dir/b.PARQUET", "c.Parq", ".parquet"] {
        assert!(is_eligible(key), "{key}");
    }
    for key in ["a.parquet.bak", "a.csv", "parquet", "a.par", ""] {
        assert!(!is_eligible(key), "{key}");
    }
}

#[tokio::test]
async fn a_small_file_is_read_whole_in_one_request() -> TestResult {
    let body = parquet_file(&customers(500), Layout::default())?;
    let size = body.len();
    let (scan, reader) = scan("t.parquet", body, super::DEFAULT_WHOLE_FILE_MAX).await;
    assert_eq!(scan.outcome, FileOutcome::ScannedWhole);
    assert_eq!(verdicts(&scan), expected_customers());
    assert_eq!(reader.reads.len(), 1);
    assert_eq!(scan.stats.get_requests, 1);
    assert_eq!(scan.stats.bytes_read, u64::try_from(size)?);
    // 6 candidate columns (dob is checked by name), repeated and double skipped.
    assert_eq!(scan.stats.columns_examined, 6);
    assert_eq!(scan.stats.skipped_repeated, 1);
    assert_eq!(scan.stats.skipped_unsupported_type, 1);
    Ok(())
}

#[tokio::test]
async fn partial_reads_with_an_offset_index_agree_with_whole_reads() -> TestResult {
    let layout = Layout {
        row_group_rows: 2000,
        ..Layout::default()
    };
    let body = parquet_file(&customers(6000), layout)?;
    let size = u64::try_from(body.len())?;
    let (scan, _) = scan("t.parquet", body, 0).await;
    assert_eq!(scan.outcome, FileOutcome::ScannedPartially);
    assert_eq!(verdicts(&scan), expected_customers());
    assert!(
        scan.stats.bytes_read < size,
        "{} of {size}",
        scan.stats.bytes_read
    );
    Ok(())
}

#[tokio::test]
async fn partial_reads_without_an_offset_index_grow_a_window() -> TestResult {
    let layout = Layout {
        row_group_rows: 2000,
        offset_index: false,
        dictionary: false,
        ..Layout::default()
    };
    let body = parquet_file(&customers(6000), layout)?;
    let (scan, _) = scan("t.parquet", body, 0).await;
    assert_eq!(scan.outcome, FileOutcome::ScannedPartially);
    assert_eq!(verdicts(&scan), expected_customers());
    Ok(())
}

#[tokio::test]
async fn hashed_emails_named_email_are_never_an_email_finding() -> TestResult {
    let body = parquet_file(
        &[("email_sha256", Values::Text(digests(100)))],
        Layout::default(),
    )?;
    let (scan, _) = scan("t.parquet", body, super::DEFAULT_WHOLE_FILE_MAX).await;
    assert!(scan.columns.is_empty(), "{:?}", verdicts(&scan));
    Ok(())
}

#[tokio::test]
async fn junk_in_row_group_zero_escalates_to_later_row_groups() -> TestResult {
    // Row group 0 (rows 0-999): nulls and placeholders only. Later row
    // groups: real emails.
    let mut values: Vec<Option<String>> = (0..1000)
        .map(|i| match i % 4 {
            0 => None,
            1 => Some("N/A".to_owned()),
            2 => Some("   ".to_owned()),
            _ => Some("unknown".to_owned()),
        })
        .collect();
    values.extend(emails(2000));
    let layout = Layout {
        row_group_rows: 1000,
        ..Layout::default()
    };
    for whole_file_max in [0, super::DEFAULT_WHOLE_FILE_MAX] {
        let body = parquet_file(&[("contact", Values::Text(values.clone()))], layout)?;
        let (scan, _) = scan("t.parquet", body, whole_file_max).await;
        let found = scan.columns.first().ok_or("no finding")?;
        assert_eq!(found.pii, PiiType::Email);
        assert_eq!(found.detail.confidence, Confidence::Confirmed);
        assert_eq!(
            found.detail.evidence,
            Evidence::Values {
                matched: 1000,
                sampled: 1000
            },
            "row group 0 contributes nothing"
        );
    }
    Ok(())
}

#[tokio::test]
async fn at_most_two_thousand_values_are_kept_per_row_group() -> TestResult {
    let body = parquet_file(&[("email", Values::Text(emails(5000)))], Layout::default())?;
    let (scan, _) = scan("t.parquet", body, super::DEFAULT_WHOLE_FILE_MAX).await;
    let found = scan.columns.first().ok_or("no finding")?;
    assert_eq!(
        found.detail.evidence,
        Evidence::Values {
            matched: 2000,
            sampled: 2000
        }
    );
    Ok(())
}

#[tokio::test]
async fn a_dominant_default_value_is_dropped_before_matching() -> TestResult {
    // 70% one default address, 30% free text: without the default there
    // is no email left to report.
    let values: Vec<Option<String>> = (0..100)
        .map(|i| {
            Some(if i < 70 {
                "noreply@example.com".to_owned()
            } else {
                format!("see ticket {i}")
            })
        })
        .collect();
    let body = parquet_file(&[("contact", Values::Text(values))], Layout::default())?;
    let (scan, _) = scan("t.parquet", body, super::DEFAULT_WHOLE_FILE_MAX).await;
    assert!(scan.columns.is_empty(), "{:?}", verdicts(&scan));
    Ok(())
}

#[tokio::test]
async fn a_page_over_the_cap_skips_the_column() -> TestResult {
    // One data page of ~9 MiB of emails, plus a small column.
    let rows = 300_000;
    let layout = Layout {
        dictionary: false,
        page_bytes: usize::MAX,
        ..Layout::default()
    };
    let body = parquet_file(
        &[
            ("email", Values::Text(emails(rows))),
            ("mobile_no", Values::Int64(mobiles(rows))),
        ],
        layout,
    )?;
    assert!(u64::try_from(body.len())? > PAGE_CAP);
    let (scan, _) = scan("t.parquet", body, 0).await;
    assert_eq!(scan.outcome, FileOutcome::ScannedPartially);
    assert_eq!(scan.stats.skipped_page_too_large, 1);
    assert_eq!(
        scan.columns.iter().map(|c| c.pii).collect::<Vec<_>>(),
        [PiiType::Phone]
    );
    Ok(())
}

#[tokio::test]
async fn files_that_cannot_be_scanned_say_why() -> TestResult {
    let good = parquet_file(&customers(50), Layout::default())?;
    let truncated = good
        .get(..good.len() - 100)
        .map(<[u8]>::to_vec)
        .ok_or("short")?;
    let mut encrypted = good.clone();
    let tail = encrypted.len() - 4;
    encrypted.splice(tail.., *b"PARE");
    let mut huge_footer = b"PAR1".to_vec();
    huge_footer.extend_from_slice(&[0; 32]);
    huge_footer.extend_from_slice(&(17 * 1024 * 1024_u32).to_le_bytes());
    huge_footer.extend_from_slice(b"PAR1");
    let mut corrupt = b"PAR1".to_vec();
    corrupt.extend_from_slice(&[7; 64]);
    corrupt.extend_from_slice(&64_u32.to_le_bytes());
    corrupt.extend_from_slice(b"PAR1");

    let cases = [
        (b"id,email\n1,x\n".to_vec(), NotScannedReason::NotParquet),
        (Vec::new(), NotScannedReason::NotParquet),
        (b"PAR".to_vec(), NotScannedReason::NotParquet),
        (truncated, NotScannedReason::Unreadable),
        (corrupt, NotScannedReason::Unreadable),
        (encrypted, NotScannedReason::Encrypted),
        (huge_footer, NotScannedReason::FooterTooLarge),
    ];
    for (body, reason) in cases {
        for whole_file_max in [0, super::DEFAULT_WHOLE_FILE_MAX] {
            let (scan, _) = scan("t.parquet", body.clone(), whole_file_max).await;
            assert_eq!(
                scan.outcome,
                FileOutcome::NotScanned(reason),
                "{reason:?} with whole-file max {whole_file_max}"
            );
            assert_eq!(scan.columns, []);
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_refused_read_is_access_denied() -> TestResult {
    let body = parquet_file(&customers(50), Layout::default())?;
    let meta = object("t.parquet", body.len());
    let mut reader = MemoryReader::default().with("t.parquet", body);
    reader.denied.insert("t.parquet".to_owned());
    let scan = scan_file(&mut reader, &meta, 0).await;
    assert_eq!(
        scan.outcome,
        FileOutcome::NotScanned(NotScannedReason::AccessDenied)
    );
    Ok(())
}

#[tokio::test]
async fn an_object_shorter_than_listed_is_unreadable() -> TestResult {
    let body = parquet_file(&customers(50), Layout::default())?;
    let meta = object("t.parquet", body.len() + 10);
    let mut reader = MemoryReader::default().with("t.parquet", body);
    let scan = scan_file(&mut reader, &meta, super::DEFAULT_WHOLE_FILE_MAX).await;
    assert_eq!(
        scan.outcome,
        FileOutcome::NotScanned(NotScannedReason::Unreadable)
    );
    Ok(())
}

#[tokio::test]
async fn findings_carry_the_column_and_never_a_value() -> TestResult {
    let body = parquet_file(&customers(100), Layout::default())?;
    let (scan, _) = scan("t.parquet", body, super::DEFAULT_WHOLE_FILE_MAX).await;
    let meta = object("t.parquet", 1);
    let rendered = format!("{:?}", scan.findings(&meta).collect::<Vec<_>>());
    assert!(rendered.contains("mobile_no"));
    for value in ["person.1@example1.com", "9876000001"] {
        assert!(!rendered.contains(value), "{value} leaked: {rendered}");
    }
    Ok(())
}

/// The committed fixtures (`tests/fixtures/parquet`), one per writer: what
/// each column truly holds and the confidence expected for it.
fn expected_fixture_columns() -> Vec<(&'static str, PiiType, Confidence)> {
    vec![
        ("full_name", PiiType::PersonName, Confidence::Likely),
        ("email", PiiType::Email, Confidence::Confirmed),
        ("contact", PiiType::Phone, Confidence::Confirmed),
        ("mobile_no", PiiType::Phone, Confidence::Confirmed),
        ("aadhaar_no", PiiType::InAadhaar, Confidence::Confirmed),
        ("pan", PiiType::InPan, Confidence::Confirmed),
        ("card_number", PiiType::CardNumber, Confidence::Confirmed),
        ("last_login_ip", PiiType::IpAddress, Confidence::Confirmed),
        ("dob", PiiType::DateOfBirth, Confidence::Likely),
        ("billing.email", PiiType::Email, Confidence::Confirmed),
    ]
}

fn fixture(path: &str) -> std::io::Result<Vec<u8>> {
    std::fs::read(format!(
        "{}/tests/fixtures/parquet/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
}

#[tokio::test]
async fn every_writer_fixture_is_classified_by_both_read_paths() -> TestResult {
    let expected: Vec<(String, PiiType, Confidence)> = expected_fixture_columns()
        .into_iter()
        .map(|(column, pii, confidence)| (column.to_owned(), pii, confidence))
        .collect();
    for writer in [
        "pyarrow",
        "polars",
        "duckdb",
        "spark",
        "gzip/pyarrow",
        "gzip/spark",
        "brotli/pyarrow",
    ] {
        let body = fixture(&format!("{writer}/customers.parquet"))?;
        let size = u64::try_from(body.len())?;
        let (whole, _) = scan("c.parquet", body.clone(), super::DEFAULT_WHOLE_FILE_MAX).await;
        let (partial, _) = scan("c.parquet", body, 0).await;
        assert_eq!(whole.outcome, FileOutcome::ScannedWhole, "{writer}");
        assert_eq!(partial.outcome, FileOutcome::ScannedPartially, "{writer}");
        assert_eq!(verdicts(&whole), expected, "{writer}, whole");
        assert_eq!(verdicts(&partial), expected, "{writer}, partial");
        assert_eq!(whole.stats.skipped_repeated, 1, "{writer}: tags");
        assert!(
            partial.stats.bytes_read < size,
            "{writer}: partial read {} of {size}",
            partial.stats.bytes_read
        );
    }
    Ok(())
}

#[tokio::test]
async fn the_escalation_fixture_is_found_past_row_group_zero() -> TestResult {
    for whole_file_max in [0, super::DEFAULT_WHOLE_FILE_MAX] {
        let (scan, _) = scan("e.parquet", fixture("escalation.parquet")?, whole_file_max).await;
        assert_eq!(
            verdicts(&scan),
            [(
                "contact_email".to_owned(),
                PiiType::Email,
                Confidence::Confirmed
            )]
        );
    }
    Ok(())
}

#[tokio::test]
async fn the_bad_fixtures_are_not_scanned() -> TestResult {
    for (path, reason) in [
        ("bad/truncated.parquet", NotScannedReason::Unreadable),
        ("bad/not_parquet.parquet", NotScannedReason::NotParquet),
        (
            "skipped/too_large.parquet",
            NotScannedReason::NoColumnExamined,
        ),
    ] {
        for whole_file_max in [0, super::DEFAULT_WHOLE_FILE_MAX] {
            let (scan, _) = scan("b.parquet", fixture(path)?, whole_file_max).await;
            assert_eq!(scan.outcome, FileOutcome::NotScanned(reason), "{path}");
        }
    }
    Ok(())
}

/// `body` with the page header at `offset` replaced by `header`, written
/// over the old header and the start of the page body: a crafted file.
fn patched(mut body: Vec<u8>, offset: usize, header: &[u8]) -> Vec<u8> {
    for (byte, new) in body.iter_mut().skip(offset).zip(header) {
        *byte = *new;
    }
    body
}

/// The offset, declared uncompressed size and compressed size of the
/// first page header of the first column chunk in `body`.
fn first_page(body: &[u8]) -> Result<(usize, i32, i32), Box<dyn std::error::Error>> {
    let tail = body.len() - 8;
    let footer_len = u32::from_le_bytes(body.get(tail..tail + 4).ok_or("short")?.try_into()?);
    let footer = body
        .get(tail - usize::try_from(footer_len)?..tail)
        .ok_or("short footer")?;
    let metadata = parquet::file::metadata::ParquetMetaDataReader::decode_metadata(footer)?;
    let chunk = metadata.row_group(0).column(0);
    let offset = usize::try_from(
        chunk
            .dictionary_page_offset()
            .unwrap_or(chunk.data_page_offset()),
    )?;
    match super::header::read(body.get(offset..).ok_or("offset past the end")?) {
        super::header::Read::Header(h) => Ok((
            offset,
            i32::try_from(h.uncompressed)?,
            i32::try_from(h.compressed)?,
        )),
        other => Err(format!("no header: {other:?}").into()),
    }
}

#[tokio::test]
async fn a_page_declaring_a_huge_uncompressed_size_is_never_decoded() -> TestResult {
    let layout = Layout {
        dictionary: false,
        ..Layout::default()
    };
    let body = parquet_file(&[("email", Values::Text(emails(500)))], layout)?;
    let (offset, _, compressed) = first_page(&body)?;
    let header =
        super::header::tests::encode(super::header::DATA_PAGE, i32::MAX - 7, compressed, None);
    let crafted = patched(body, offset, &header);
    for whole_file_max in [0, super::DEFAULT_WHOLE_FILE_MAX] {
        let before = super::read::fault::decodes();
        let (scan, _) = scan("crafted.parquet", crafted.clone(), whole_file_max).await;
        assert_eq!(
            super::read::fault::decodes(),
            before,
            "a decode was attempted"
        );
        // Its only column skipped, the file was not scanned.
        assert_eq!(
            scan.outcome,
            FileOutcome::NotScanned(NotScannedReason::NoColumnExamined)
        );
        assert_eq!(scan.stats.skipped_page_too_large, 1);
        assert_eq!(scan.columns, []);
    }
    Ok(())
}

#[tokio::test]
async fn a_dictionary_declaring_billions_of_values_is_never_decoded() -> TestResult {
    let body = parquet_file(&[("email", Values::Text(emails(500)))], Layout::default())?;
    let (offset, uncompressed, compressed) = first_page(&body)?;
    let header = super::header::tests::encode(
        super::header::DICTIONARY_PAGE,
        uncompressed,
        compressed,
        Some(i32::MAX),
    );
    let crafted = patched(body, offset, &header);
    for whole_file_max in [0, super::DEFAULT_WHOLE_FILE_MAX] {
        let before = super::read::fault::decodes();
        let (scan, _) = scan("crafted.parquet", crafted.clone(), whole_file_max).await;
        assert_eq!(
            super::read::fault::decodes(),
            before,
            "a decode was attempted"
        );
        assert_eq!(scan.stats.skipped_page_too_large, 1);
    }
    Ok(())
}

fn gzip_and_brotli() -> [parquet::basic::Compression; 2] {
    use parquet::basic::{BrotliLevel, Compression, GzipLevel};
    [
        Compression::GZIP(GzipLevel::default()),
        Compression::BROTLI(BrotliLevel::default()),
    ]
}

#[tokio::test]
async fn gzip_and_brotli_pages_are_decompressed_by_lakescan() -> TestResult {
    for compression in gzip_and_brotli() {
        for (dictionary, v2) in [(true, false), (false, false), (true, true), (false, true)] {
            let layout = Layout {
                dictionary,
                compression,
                v2,
                ..Layout::default()
            };
            let body = parquet_file(&customers(500), layout)?;
            for whole_file_max in [0, super::DEFAULT_WHOLE_FILE_MAX] {
                let (scan, _) = scan("z.parquet", body.clone(), whole_file_max).await;
                let case = format!("{compression:?} dictionary={dictionary} v2={v2}");
                assert_eq!(verdicts(&scan), expected_customers(), "{case}");
                assert_eq!(scan.stats.skipped_unreadable, 0, "{case}");
            }
        }
    }
    Ok(())
}

/// `body` with the first page header's declared uncompressed size (field
/// 2, right after the page type) changed by `delta`, in place: the new
/// size must encode to as many bytes as the old one.
fn redeclared(mut body: Vec<u8>, delta: i32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let zigzag = |value: i32| {
        let mut raw = (i64::from(value) << 1).cast_unsigned();
        let mut out = Vec::new();
        loop {
            let byte = u8::try_from(raw & 0x7f).unwrap_or(0);
            raw >>= 7;
            if raw == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    };
    let (offset, uncompressed, _) = first_page(&body)?;
    let (old, new) = (zigzag(uncompressed), zigzag(uncompressed + delta));
    let at = offset + 3;
    assert_eq!(body.get(offset..at), Some(&[0x15, 0x00, 0x15][..]));
    assert_eq!(body.get(at..at + old.len()), Some(&old[..]));
    assert_eq!(old.len(), new.len());
    for (byte, new) in body.iter_mut().skip(at).zip(new) {
        *byte = new;
    }
    Ok(body)
}

#[tokio::test]
async fn a_compressed_page_whose_output_differs_from_its_declared_size_is_unreadable() -> TestResult
{
    // One email data page, no dictionary. Declared one byte short, the
    // stream has more to give: it is cut there, not decompressed in full.
    // Declared one byte long, it ends early. Either way `parquet` never
    // sees the page.
    for compression in gzip_and_brotli() {
        let layout = Layout {
            compression,
            dictionary: false,
            ..Layout::default()
        };
        let body = parquet_file(&[("email", Values::Text(emails(500)))], layout)?;
        for delta in [-1, 1] {
            let crafted = redeclared(body.clone(), delta)?;
            for whole_file_max in [0, super::DEFAULT_WHOLE_FILE_MAX] {
                let before = super::read::fault::decodes();
                let (scan, _) = scan("z.parquet", crafted.clone(), whole_file_max).await;
                let case = format!("{compression:?} declared {delta:+}");
                assert_eq!(super::read::fault::decodes(), before, "{case}");
                assert_eq!(scan.stats.skipped_unreadable, 1, "{case}");
                assert_eq!(
                    scan.outcome,
                    FileOutcome::NotScanned(NotScannedReason::NoColumnExamined),
                    "{case}"
                );
            }
        }
        // Unchanged, the same file decodes.
        let (scan, _) = scan("z.parquet", body, 0).await;
        assert_eq!(scan.stats.columns_examined, 1);
    }
    Ok(())
}

/// `body` with every column chunk's codec rewritten to LZO in the footer.
fn as_lzo(body: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use parquet::file::metadata::{ParquetMetaDataReader, ParquetMetaDataWriter};
    let tail = body.len() - 8;
    let footer_len = usize::try_from(u32::from_le_bytes(
        body.get(tail..tail + 4).ok_or("short")?.try_into()?,
    ))?;
    let footer_start = tail - footer_len;
    let metadata =
        ParquetMetaDataReader::decode_metadata(body.get(footer_start..tail).ok_or("short")?)?;
    let mut groups = Vec::new();
    for group in metadata.row_groups() {
        let columns = group
            .columns()
            .iter()
            .map(|chunk| {
                chunk
                    .clone()
                    .into_builder()
                    .set_compression(parquet::basic::Compression::LZO)
                    .build()
            })
            .collect::<Result<Vec<_>, _>>()?;
        groups.push(
            group
                .clone()
                .into_builder()
                .set_column_metadata(columns)
                .build()?,
        );
    }
    let metadata = metadata.into_builder().set_row_groups(groups).build();
    let mut out = body.get(..footer_start).ok_or("short")?.to_vec();
    ParquetMetaDataWriter::new(&mut out, &metadata).finish()?;
    Ok(out)
}

#[tokio::test]
async fn an_lzo_column_is_skipped_as_an_unsupported_codec() -> TestResult {
    let body = parquet_file(
        &[
            ("email", Values::Text(emails(500))),
            ("dob", Values::Date((0..500).map(Some).collect())),
        ],
        Layout::default(),
    )?;
    let body = as_lzo(&body)?;
    for whole_file_max in [0, super::DEFAULT_WHOLE_FILE_MAX] {
        let (scan, _) = scan("lzo.parquet", body.clone(), whole_file_max).await;
        assert_eq!(scan.stats.skipped_unsupported_codec, 1);
        assert_eq!(scan.stats.skipped_unreadable, 0);
        // No value was read, so the file was not scanned, though the date
        // of birth, found by its name alone, still stands.
        assert_eq!(
            scan.outcome,
            FileOutcome::NotScanned(NotScannedReason::NoColumnExamined)
        );
        assert_eq!(
            verdicts(&scan),
            [("dob".to_owned(), PiiType::DateOfBirth, Confidence::Likely)]
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_file_with_no_column_to_read_still_counts_as_scanned() -> TestResult {
    let doubles = parquet_file(
        &[("amount", Values::Double(vec![1.5; 100]))],
        Layout::default(),
    )?;
    for whole_file_max in [0, super::DEFAULT_WHOLE_FILE_MAX] {
        let (scan, _) = scan("d.parquet", doubles.clone(), whole_file_max).await;
        assert!(
            matches!(
                scan.outcome,
                FileOutcome::ScannedWhole | FileOutcome::ScannedPartially
            ),
            "{:?}",
            scan.outcome
        );
        assert_eq!(scan.stats.skipped_unsupported_type, 1);
    }
    Ok(())
}

#[tokio::test]
async fn snappy_zstd_and_lz4_pages_are_decoded() -> TestResult {
    use parquet::basic::{Compression, ZstdLevel};
    for compression in [
        Compression::SNAPPY,
        Compression::ZSTD(ZstdLevel::default()),
        Compression::LZ4_RAW,
    ] {
        let layout = Layout {
            compression,
            ..Layout::default()
        };
        let body = parquet_file(&[("email", Values::Text(emails(500)))], layout)?;
        for whole_file_max in [0, super::DEFAULT_WHOLE_FILE_MAX] {
            let (scan, _) = scan("z.parquet", body.clone(), whole_file_max).await;
            assert_eq!(
                scan.columns.iter().map(|c| c.pii).collect::<Vec<_>>(),
                [PiiType::Email],
                "{compression:?}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_panic_inside_decoding_costs_one_file_not_the_scan() -> TestResult {
    let body = parquet_file(&customers(100), Layout::default())?;
    super::read::fault::arm();
    let (panicked, _) = scan("a.parquet", body.clone(), super::DEFAULT_WHOLE_FILE_MAX).await;
    super::read::fault::disarm();
    assert_eq!(
        panicked.outcome,
        FileOutcome::NotScanned(NotScannedReason::Unreadable)
    );
    assert_eq!(panicked.columns, []);
    let (next, _) = scan("b.parquet", body, super::DEFAULT_WHOLE_FILE_MAX).await;
    assert_eq!(next.outcome, FileOutcome::ScannedWhole);
    assert_eq!(verdicts(&next), expected_customers());
    Ok(())
}
