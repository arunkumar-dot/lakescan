//! Parquet PII spike: how much PII can be found from the footer, statistics,
//! dictionary pages and first data pages, and how many bytes does it take?
//!
//! Throwaway measurement code for docs/experiments/parquet-pii.md. It is not
//! part of lakescan and must never be imported by it.
//!
//!     cargo run --release -- <data_dir>      # reads <data_dir>/manifest.json

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use bytes::Bytes;
use parquet::basic::{PageType, Type as PhysicalType};
use parquet::column::page::{Page, PageMetadata, PageReader};
use parquet::column::reader::{ColumnReader, get_column_reader};
use parquet::data_type::ByteArray;
use parquet::errors::Result as PqResult;
use parquet::file::metadata::{
    ColumnChunkMetaData, ParquetMetaData, ParquetMetaDataOptions, ParquetMetaDataReader,
};
use parquet::file::page_index::offset_index::PageLocation;
use parquet::file::reader::{ChunkReader, Length};
use parquet::file::serialized_reader::SerializedPageReader;
use regex::Regex;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------- counting I/O

/// A local file where every fetch is one counted "range read", the unit an
/// object store bills and that dominates latency.
struct Counted {
    file: File,
    len: u64,
    bytes: AtomicU64,
    ranges: AtomicU64,
}

impl Counted {
    fn open(path: &Path) -> Arc<Self> {
        let file = File::open(path).unwrap();
        let len = file.metadata().unwrap().len();
        Arc::new(Self {
            file,
            len,
            bytes: AtomicU64::new(0),
            ranges: AtomicU64::new(0),
        })
    }

    fn read_range(&self, start: u64, len: usize) -> Vec<u8> {
        let len = len.min((self.len - start) as usize);
        let mut buf = vec![0; len];
        self.file.read_exact_at(&mut buf, start).unwrap();
        self.bytes.fetch_add(len as u64, Ordering::Relaxed);
        self.ranges.fetch_add(1, Ordering::Relaxed);
        buf
    }
}

/// How many bytes a header probe fetches. Page headers are usually well
/// under 100 bytes; a header longer than this costs a second probe.
const PROBE: usize = 1024;

#[derive(Clone)]
struct Src(Arc<Counted>);

impl Length for Src {
    fn len(&self) -> u64 {
        self.0.len
    }
}

impl ChunkReader for Src {
    type T = ProbeRead;

    /// Used by the page reader only to parse a page header of unknown
    /// length: fetch PROBE bytes at a time, each fetch one counted range.
    fn get_read(&self, start: u64) -> PqResult<ProbeRead> {
        Ok(ProbeRead {
            src: self.0.clone(),
            next: start,
            buf: Vec::new(),
            pos: 0,
        })
    }

    /// An exact range: one counted read.
    fn get_bytes(&self, start: u64, length: usize) -> PqResult<Bytes> {
        Ok(Bytes::from(self.0.read_range(start, length)))
    }
}

struct ProbeRead {
    src: Arc<Counted>,
    next: u64,
    buf: Vec<u8>,
    pos: usize,
}

impl Read for ProbeRead {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.pos == self.buf.len() {
            if self.next >= self.src.len {
                return Ok(0);
            }
            self.buf = self.src.read_range(self.next, PROBE);
            self.next += self.buf.len() as u64;
            self.pos = 0;
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Yields only the first page of a column chunk, then reports the chunk as
/// exhausted, so decoding one data page never fetches the next one.
struct FirstPageOnly<P: PageReader> {
    inner: P,
    done: bool,
}

impl<P: PageReader> Iterator for FirstPageOnly<P> {
    type Item = PqResult<Page>;
    fn next(&mut self) -> Option<Self::Item> {
        self.get_next_page().transpose()
    }
}

impl<P: PageReader> PageReader for FirstPageOnly<P> {
    fn get_next_page(&mut self) -> PqResult<Option<Page>> {
        if self.done {
            return Ok(None);
        }
        let page = self.inner.get_next_page()?;
        if matches!(page, Some(Page::DataPage { .. } | Page::DataPageV2 { .. })) {
            self.done = true;
        }
        Ok(page)
    }
    fn peek_next_page(&mut self) -> PqResult<Option<PageMetadata>> {
        if self.done {
            Ok(None)
        } else {
            self.inner.peek_next_page()
        }
    }
    fn skip_next_page(&mut self) -> PqResult<()> {
        self.done = true;
        Ok(())
    }
}

// ---------------------------------------------------------------- detectors

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Pii {
    Email,
    Phone,
    InPan,
    InAadhaar,
    CardNumber,
    IpAddress,
    EmailEmbedded,
    PersonName,
    DateOfBirth,
}

/// Value-detectable types, strictest validator first: checksums, then
/// parsers, then structured regexes, then loose ones.
const VALUE_TYPES: [Pii; 7] = [
    Pii::InAadhaar,
    Pii::CardNumber,
    Pii::IpAddress,
    Pii::InPan,
    Pii::Email,
    Pii::Phone,
    Pii::EmailEmbedded,
];

struct Detectors {
    email: Regex,
    email_anywhere: Regex,
    pan: Regex,
    e164: Regex,
    indian: Regex,
}

impl Detectors {
    fn new() -> Self {
        Self {
            email: Regex::new(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$").unwrap(),
            email_anywhere: Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap(),
            pan: Regex::new(r"^[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]$").unwrap(),
            e164: Regex::new(r"^\+[1-9][0-9]{7,14}$").unwrap(),
            indian: Regex::new(r"^(?:\+?91|0)?[6-9][0-9]{9}$").unwrap(),
        }
    }

    fn validates(&self, t: Pii, v: &str) -> bool {
        let v = v.trim();
        match t {
            Pii::Email => self.email.is_match(v),
            Pii::EmailEmbedded => !self.email.is_match(v) && self.email_anywhere.is_match(v),
            Pii::InPan => self.pan.is_match(v),
            Pii::Phone => {
                let s: String = v.chars().filter(|c| !" -().".contains(*c)).collect();
                self.e164.is_match(&s) || self.indian.is_match(&s)
            }
            Pii::InAadhaar => {
                let s: String = v.chars().filter(|c| *c != ' ').collect();
                s.len() == 12
                    && s.bytes().all(|b| b.is_ascii_digit())
                    && (b'2'..=b'9').contains(&s.as_bytes()[0])
                    && verhoeff_valid(&s)
            }
            Pii::CardNumber => {
                let s: String = v.chars().filter(|c| *c != ' ' && *c != '-').collect();
                (13..=19).contains(&s.len())
                    && s.bytes().all(|b| b.is_ascii_digit())
                    && luhn_valid(&s)
            }
            Pii::IpAddress => v.parse::<IpAddr>().is_ok(),
            Pii::PersonName | Pii::DateOfBirth => false,
        }
    }
}

fn verhoeff_valid(s: &str) -> bool {
    const D: [[u8; 10]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];
    const P: [[u8; 10]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];
    let mut c = 0u8;
    for (i, b) in s.bytes().rev().enumerate() {
        c = D[c as usize][P[i % 8][(b - b'0') as usize] as usize];
    }
    c == 0
}

fn luhn_valid(s: &str) -> bool {
    let mut sum = 0u32;
    for (i, b) in s.bytes().rev().enumerate() {
        let mut d = (b - b'0') as u32;
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum % 10 == 0
}

/// Name-based hint from column-name tokens (split on non-alphanumerics).
fn name_hint(column: &str) -> Option<Pii> {
    let lower = column.to_lowercase();
    let tokens: Vec<&str> = lower.split(|c: char| !c.is_ascii_alphanumeric()).collect();
    let has = |words: &[&str]| tokens.iter().any(|t| words.contains(t));
    if has(&["email", "e_mail", "mail"]) {
        Some(Pii::Email)
    } else if has(&["phone", "mobile", "msisdn", "tel", "telephone"]) {
        Some(Pii::Phone)
    } else if has(&["dob", "birth", "birthdate", "birthday"]) {
        Some(Pii::DateOfBirth)
    } else if has(&["aadhaar", "aadhar", "uidai"]) {
        Some(Pii::InAadhaar)
    } else if has(&["pan"]) {
        Some(Pii::InPan)
    } else if has(&["card", "cc", "ccnum", "cardnumber"]) {
        Some(Pii::CardNumber)
    } else if has(&["ip", "ipaddr", "ipv4", "ipv6"]) {
        Some(Pii::IpAddress)
    } else if has(&["name", "fullname", "firstname", "lastname", "surname"]) {
        Some(Pii::PersonName)
    } else {
        None
    }
}

/// Pre-registered column rule: a type qualifies when >= 80% of non-null
/// sampled values validate; among qualifying types the strictest wins.
fn classify(det: &Detectors, samples: &[String]) -> Option<Pii> {
    let values: Vec<&str> = samples
        .iter()
        .map(|s| s.as_str())
        .filter(|s| !s.trim().is_empty())
        .collect();
    if values.is_empty() {
        return None;
    }
    VALUE_TYPES.into_iter().find(|&t| {
        let ok = values.iter().filter(|v| det.validates(t, v)).count();
        ok * 100 >= values.len() * 80
    })
}

/// Supplementary rule, declared before running and NOT used for the verdict:
/// EMAIL_EMBEDDED qualifies at >= 1% of sampled values (free text rarely
/// carries PII in most rows), when no pre-registered type qualified.
fn classify_supplementary(det: &Detectors, samples: &[String]) -> Option<Pii> {
    if let Some(t) = classify(det, samples) {
        return Some(t);
    }
    let values: Vec<&str> = samples
        .iter()
        .map(|s| s.as_str())
        .filter(|s| !s.trim().is_empty())
        .collect();
    let hits = values
        .iter()
        .filter(|v| det.validates(Pii::EmailEmbedded, v))
        .count();
    (hits > 0 && hits * 100 >= values.len()).then_some(Pii::EmailEmbedded)
}

// ---------------------------------------------------------------- value decoding

fn stat_value(ty: PhysicalType, bytes: &[u8]) -> Option<String> {
    match ty {
        PhysicalType::BYTE_ARRAY | PhysicalType::FIXED_LEN_BYTE_ARRAY => {
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
        PhysicalType::INT32 if bytes.len() == 4 => {
            Some(i32::from_le_bytes(bytes.try_into().ok()?).to_string())
        }
        PhysicalType::INT64 if bytes.len() == 8 => {
            Some(i64::from_le_bytes(bytes.try_into().ok()?).to_string())
        }
        PhysicalType::DOUBLE if bytes.len() == 8 => {
            Some(f64::from_le_bytes(bytes.try_into().ok()?).to_string())
        }
        PhysicalType::FLOAT if bytes.len() == 4 => {
            Some(f32::from_le_bytes(bytes.try_into().ok()?).to_string())
        }
        _ => None,
    }
}

/// Dictionary pages are PLAIN-encoded: decode them by physical type.
fn decode_plain(ty: PhysicalType, type_len: usize, buf: &[u8], n: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(n);
    let mut pos = 0usize;
    for _ in 0..n {
        match ty {
            PhysicalType::BYTE_ARRAY => {
                let len = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()) as usize;
                pos += 4;
                out.push(String::from_utf8_lossy(&buf[pos..pos + len]).into_owned());
                pos += len;
            }
            PhysicalType::FIXED_LEN_BYTE_ARRAY => {
                out.push(String::from_utf8_lossy(&buf[pos..pos + type_len]).into_owned());
                pos += type_len;
            }
            PhysicalType::INT32 | PhysicalType::FLOAT => {
                out.push(stat_value(ty, &buf[pos..pos + 4]).unwrap());
                pos += 4;
            }
            PhysicalType::INT64 | PhysicalType::DOUBLE => {
                out.push(stat_value(ty, &buf[pos..pos + 8]).unwrap());
                pos += 8;
            }
            _ => break,
        }
    }
    out
}

fn first_data_page_values(src: &Src, col: &ColumnChunkMetaData, rows: usize) -> Vec<String> {
    let pages = SerializedPageReader::new(Arc::new(src.clone()), col, rows, None).unwrap();
    let pages = FirstPageOnly {
        inner: pages,
        done: false,
    };
    let descr = col.column_descr_ptr();
    let mut def = Vec::new();
    match get_column_reader(descr, Box::new(pages)) {
        ColumnReader::ByteArrayColumnReader(mut r) => {
            let mut v: Vec<ByteArray> = Vec::new();
            r.read_records(rows, Some(&mut def), None, &mut v).unwrap();
            v.iter()
                .map(|b| String::from_utf8_lossy(b.data()).into_owned())
                .collect()
        }
        ColumnReader::Int64ColumnReader(mut r) => {
            let mut v = Vec::new();
            r.read_records(rows, Some(&mut def), None, &mut v).unwrap();
            v.iter().map(|x| x.to_string()).collect()
        }
        ColumnReader::Int32ColumnReader(mut r) => {
            let mut v = Vec::new();
            r.read_records(rows, Some(&mut def), None, &mut v).unwrap();
            v.iter().map(|x| x.to_string()).collect()
        }
        ColumnReader::DoubleColumnReader(mut r) => {
            let mut v = Vec::new();
            r.read_records(rows, Some(&mut def), None, &mut v).unwrap();
            v.iter().map(|x| x.to_string()).collect()
        }
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------- manifest + results

#[derive(Deserialize)]
struct Manifest {
    versions: BTreeMap<String, String>,
    files: Vec<FileTruth>,
}

#[derive(Deserialize)]
struct FileTruth {
    path: String,
    writer: String,
    dataset: String,
    rows: u64,
    columns: BTreeMap<String, ColumnTruth>,
}

#[derive(Deserialize, Clone)]
struct ColumnTruth {
    #[serde(rename = "type")]
    ty: Option<Pii>,
    name_honest: Option<bool>,
}

#[derive(Serialize)]
struct ColumnResult {
    column: String,
    truth: Option<Pii>,
    name_honest: Option<bool>,
    samples: usize,
    value_flag: Option<Pii>,
    supplementary_flag: Option<Pii>,
    name_hint: Option<Pii>,
}

#[derive(Serialize)]
struct StrategyResult {
    file: String,
    writer: String,
    dataset: String,
    rows: u64,
    row_groups: usize,
    strategy: String,
    file_bytes: u64,
    uncompressed_bytes: i64,
    bytes_read: u64,
    ranges: u64,
    wall_ms: f64,
    pct_of_file: f64,
    pct_of_uncompressed: f64,
    value_detectable: usize,
    value_recall: f64,
    all_pii: usize,
    combined_recall: f64,
    value_flags: usize,
    value_precision: Option<f64>,
    combined_flags: usize,
    combined_precision: Option<f64>,
    supplementary_value_recall: f64,
    supplementary_value_precision: Option<f64>,
    columns: Vec<ColumnResult>,
}

#[derive(Serialize)]
struct EncodingRow {
    writer: String,
    dataset: String,
    rows: u64,
    column: String,
    truth: Option<Pii>,
    row_groups: usize,
    dictionary_page: bool,
    data_page_encodings: Vec<String>,
    label: String,
    dictionary_bytes: Option<i64>,
}

fn read_footer(src: &Counted) -> ParquetMetaData {
    let tail = src.read_range(src.len - 8, 8);
    assert_eq!(&tail[4..], b"PAR1");
    let footer_len = u32::from_le_bytes(tail[..4].try_into().unwrap()) as u64;
    let footer = src.read_range(src.len - 8 - footer_len, footer_len as usize);
    let options = ParquetMetaDataOptions::new().with_encoding_stats_as_mask(false);
    ParquetMetaDataReader::decode_metadata_with_options(&footer, Some(&options)).unwrap()
}

fn data_page_encodings(col: &ColumnChunkMetaData) -> Vec<String> {
    match col.page_encoding_stats() {
        Some(stats) => {
            let mut v: Vec<String> = stats
                .iter()
                .filter(|s| {
                    s.page_type == PageType::DATA_PAGE || s.page_type == PageType::DATA_PAGE_V2
                })
                .map(|s| format!("{:?}", s.encoding))
                .collect();
            v.sort();
            v.dedup();
            v
        }
        None => col.encodings().map(|e| format!("{e:?}?")).collect(),
    }
}

fn encoding_label(col: &ColumnChunkMetaData) -> String {
    let dict = col.dictionary_page_offset().is_some();
    let encs = data_page_encodings(col);
    let is_dict = |e: &String| e.starts_with("RLE_DICTIONARY") || e.starts_with("PLAIN_DICTIONARY");
    if col.page_encoding_stats().is_none() {
        return format!(
            "{} (no page stats: {})",
            if dict { "dictionary" } else { "no dictionary" },
            encs.join(",")
        );
    }
    match (dict, encs.iter().all(is_dict), encs.iter().any(is_dict)) {
        (true, true, _) => "dictionary".to_string(),
        (true, false, true) => format!(
            "dictionary, then fallback to {}",
            encs.iter()
                .filter(|e| !is_dict(e))
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        ),
        _ => format!("no dictionary: {}", encs.join(",")),
    }
}

fn pct(n: usize, d: usize) -> f64 {
    if d == 0 {
        f64::NAN
    } else {
        100.0 * n as f64 / d as f64
    }
}

fn measure(det: &Detectors, data: &Path, truth: &FileTruth, strategy: u8) -> StrategyResult {
    let path = data.join(&truth.path);
    let counted = Counted::open(&path);
    let src = Src(counted.clone());
    let started = Instant::now();

    // S0: footer.
    let meta = read_footer(&counted);
    let schema = meta.file_metadata().schema_descr();
    let ncols = schema.num_columns();
    let mut samples: Vec<Vec<String>> = vec![Vec::new(); ncols];

    // S1: min/max statistics from every row group (already in the footer).
    if strategy >= 1 {
        for rg in meta.row_groups() {
            for (i, col) in rg.columns().iter().enumerate() {
                if let Some(stats) = col.statistics() {
                    for b in [stats.min_bytes_opt(), stats.max_bytes_opt()]
                        .into_iter()
                        .flatten()
                    {
                        if let Some(v) = stat_value(col.column_type(), b) {
                            samples[i].push(v);
                        }
                    }
                }
            }
        }
    }

    let rg0 = meta.row_group(0);
    let rows0 = rg0.num_rows() as usize;
    // S2: the dictionary page of every dictionary-encoded column, exact range.
    if strategy >= 2 {
        for (i, col) in rg0.columns().iter().enumerate() {
            let Some(dict_offset) = col.dictionary_page_offset() else {
                continue;
            };
            assert!(dict_offset < col.data_page_offset());
            let location = PageLocation {
                offset: col.data_page_offset(),
                compressed_page_size: 0, // never fetched: we stop after the dictionary page
                first_row_index: 0,
            };
            let mut pages =
                SerializedPageReader::new(Arc::new(src.clone()), col, rows0, Some(vec![location]))
                    .unwrap();
            match pages.get_next_page().unwrap() {
                Some(Page::DictionaryPage {
                    buf, num_values, ..
                }) => {
                    let type_len = col.column_descr().type_length().max(0) as usize;
                    samples[i].extend(decode_plain(
                        col.column_type(),
                        type_len,
                        &buf,
                        num_values as usize,
                    ));
                }
                other => panic!(
                    "expected a dictionary page, got {:?}",
                    other.map(|p| p.page_type())
                ),
            }
        }
    }
    // S3: the first data page of every column without a dictionary page.
    if strategy >= 3 {
        for (i, col) in rg0.columns().iter().enumerate() {
            if col.dictionary_page_offset().is_none() {
                samples[i].extend(first_data_page_values(&src, col, rows0));
            }
        }
    }
    let wall_ms = started.elapsed().as_secs_f64() * 1000.0;

    let uncompressed: i64 = meta
        .row_groups()
        .iter()
        .flat_map(|rg| rg.columns())
        .map(|c| c.uncompressed_size())
        .sum();
    let mut columns = Vec::new();
    for i in 0..ncols {
        let name = schema.column(i).name().to_string();
        let t = truth.columns.get(&name).cloned().unwrap_or(ColumnTruth {
            ty: None,
            name_honest: None,
        });
        columns.push(ColumnResult {
            column: name.clone(),
            truth: t.ty,
            name_honest: t.name_honest,
            samples: samples[i].len(),
            value_flag: classify(det, &samples[i]),
            supplementary_flag: classify_supplementary(det, &samples[i]),
            name_hint: name_hint(&name),
        });
    }

    let is_value_type = |t: Option<Pii>| t.is_some_and(|t| VALUE_TYPES.contains(&t));
    let value_cols: Vec<&ColumnResult> =
        columns.iter().filter(|c| is_value_type(c.truth)).collect();
    let pii_cols: Vec<&ColumnResult> = columns.iter().filter(|c| c.truth.is_some()).collect();
    let value_hits = value_cols
        .iter()
        .filter(|c| c.value_flag.is_some() && c.value_flag == c.truth)
        .count();
    let supp_hits = value_cols
        .iter()
        .filter(|c| c.supplementary_flag.is_some() && c.supplementary_flag == c.truth)
        .count();
    let combined = |c: &ColumnResult| c.value_flag.or(c.name_hint);
    let combined_hits = pii_cols
        .iter()
        .filter(|c| combined(c).is_some() && combined(c) == c.truth)
        .count();
    let flagged: Vec<&ColumnResult> = columns.iter().filter(|c| c.value_flag.is_some()).collect();
    let flagged_ok = flagged.iter().filter(|c| c.value_flag == c.truth).count();
    let supp_flagged: Vec<&ColumnResult> = columns
        .iter()
        .filter(|c| c.supplementary_flag.is_some())
        .collect();
    let supp_ok = supp_flagged
        .iter()
        .filter(|c| c.supplementary_flag == c.truth)
        .count();
    let comb_flagged: Vec<&ColumnResult> =
        columns.iter().filter(|c| combined(c).is_some()).collect();
    let comb_ok = comb_flagged
        .iter()
        .filter(|c| combined(c) == c.truth)
        .count();

    let bytes_read = counted.bytes.load(Ordering::Relaxed);
    StrategyResult {
        file: truth.path.clone(),
        writer: truth.writer.clone(),
        dataset: truth.dataset.clone(),
        rows: truth.rows,
        row_groups: meta.num_row_groups(),
        strategy: format!("S{strategy}"),
        file_bytes: counted.len,
        uncompressed_bytes: uncompressed,
        bytes_read,
        ranges: counted.ranges.load(Ordering::Relaxed),
        wall_ms,
        pct_of_file: 100.0 * bytes_read as f64 / counted.len as f64,
        pct_of_uncompressed: 100.0 * bytes_read as f64 / uncompressed as f64,
        value_detectable: value_cols.len(),
        value_recall: pct(value_hits, value_cols.len()),
        all_pii: pii_cols.len(),
        combined_recall: pct(combined_hits, pii_cols.len()),
        value_flags: flagged.len(),
        value_precision: (!flagged.is_empty()).then(|| pct(flagged_ok, flagged.len())),
        combined_flags: comb_flagged.len(),
        combined_precision: (!comb_flagged.is_empty()).then(|| pct(comb_ok, comb_flagged.len())),
        supplementary_value_recall: pct(supp_hits, value_cols.len()),
        supplementary_value_precision: (!supp_flagged.is_empty())
            .then(|| pct(supp_ok, supp_flagged.len())),
        columns,
    }
}

fn encodings(data: &Path, truth: &FileTruth) -> Vec<EncodingRow> {
    let counted = Counted::open(&data.join(&truth.path));
    let meta = read_footer(&counted);
    let rg0 = meta.row_group(0);
    rg0.columns()
        .iter()
        .filter_map(|col| {
            let name = col.column_descr().name().to_string();
            let t = truth.columns.get(&name)?.ty?;
            Some(EncodingRow {
                writer: truth.writer.clone(),
                dataset: truth.dataset.clone(),
                rows: truth.rows,
                column: name,
                truth: Some(t),
                row_groups: meta.num_row_groups(),
                dictionary_page: col.dictionary_page_offset().is_some(),
                data_page_encodings: data_page_encodings(col),
                label: encoding_label(col),
                dictionary_bytes: col
                    .dictionary_page_offset()
                    .map(|d| col.data_page_offset() - d),
            })
        })
        .collect()
}

fn main() {
    let data = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: parquet-pii-spike <data_dir>"),
    );
    let manifest: Manifest =
        serde_json::from_str(&std::fs::read_to_string(data.join("manifest.json")).unwrap())
            .unwrap();
    let det = Detectors::new();

    let mut results = Vec::new();
    let mut enc = Vec::new();
    for f in &manifest.files {
        enc.extend(encodings(&data, f));
        for s in 0..=3 {
            let r = measure(&det, &data, f, s);
            eprintln!(
                "{:8} {:10} {} rows={:>8} read={:>10} ({:6.3}% file, {:6.3}% uncompr) ranges={:>4} recall={:5.1}% prec={:?} {:7.1}ms",
                r.writer,
                r.dataset,
                r.strategy,
                r.rows,
                r.bytes_read,
                r.pct_of_file,
                r.pct_of_uncompressed,
                r.ranges,
                r.value_recall,
                r.value_precision,
                r.wall_ms
            );
            results.push(r);
        }
    }
    let out = serde_json::json!({ "versions": manifest.versions, "probe_bytes": PROBE, "encodings": enc, "results": results });
    let out_dir = data.parent().unwrap().join("results");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(
        out_dir.join("results.json"),
        serde_json::to_string_pretty(&out).unwrap(),
    )
    .unwrap();
    eprintln!("wrote {}", out_dir.join("results.json").display());
}
