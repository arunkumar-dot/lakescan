//! Round 2: messy values, confidence levels, free text and a small-file lake.
//!
//!     cargo run --release -- round2 <data_dir>   # writes results/round2.json
//!
//! Detection rules, declared before the first run:
//!
//! - Cleaning, before any share is computed: trim whitespace; drop nulls,
//!   empty and whitespace-only values, and values equal (ignoring ASCII case)
//!   to a placeholder in `PLACEHOLDERS`.
//! - Structured types (`STRUCTURED`, strictest first): the value rule passes
//!   for type T when >= 80% of cleaned values validate as T.
//!   CONFIRMED: the value rule passes on >= 30 cleaned values.
//!   LIKELY: the value rule passes on fewer than 30, or a name hint plus at
//!   least one cleaned value that validates as the hinted type.
//!   POSSIBLE: a name hint only.
//! - Free text: a BYTE_ARRAY column whose average value length, summed
//!   total_uncompressed_size / summed num_values over all row groups, exceeds
//!   40 bytes. It is flagged EMAIL_EMBEDDED when at least one cleaned sampled
//!   value contains an email (round 1's unanchored email regex).
//!
//! Strategies (cumulative): S1 footer + min/max statistics of every row
//! group; S3 adds row group 0's dictionary pages and the first data page of
//! each column without a dictionary; S4 adds every page of every row group
//! of the free-text columns, each chunk fetched as one range (for those
//! columns this replaces the S3 reads, so no byte is counted twice).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use bytes::{Buf, Bytes};
use parquet::basic::Type as PhysicalType;
use parquet::column::page::{Page, PageReader};
use parquet::column::reader::{ColumnReader, get_column_reader};
use parquet::data_type::ByteArray;
use parquet::errors::Result as PqResult;
use parquet::file::metadata::{ColumnChunkMetaData, ParquetMetaData};
use parquet::file::page_index::offset_index::PageLocation;
use parquet::file::reader::{ChunkReader, Length};
use parquet::file::serialized_reader::SerializedPageReader;
use serde::{Deserialize, Serialize};

use crate::{
    Counted, Detectors, EncodingRow, Manifest, Pii, Src, decode_plain, encodings,
    first_data_page_values, name_hint, read_footer, stat_value,
};

const STRUCTURED: [Pii; 6] = [
    Pii::InAadhaar,
    Pii::CardNumber,
    Pii::IpAddress,
    Pii::InPan,
    Pii::Email,
    Pii::Phone,
];
const PLACEHOLDERS: [&str; 5] = ["N/A", "unknown", "-", "0000000000", "test@test.com"];
const CONFIRM_MIN: usize = 30;
const FREE_TEXT_AVG_BYTES: f64 = 40.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Conf {
    Possible,
    Likely,
    Confirmed,
}

const LEVELS: [Conf; 3] = [Conf::Confirmed, Conf::Likely, Conf::Possible];

fn clean(raw: &[String]) -> Vec<&str> {
    raw.iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !PLACEHOLDERS.iter().any(|p| s.eq_ignore_ascii_case(p)))
        .collect()
}

/// True when at least 80% of `values` validate as `t` (stops early once
/// more than 20% have failed).
fn value_rule(det: &Detectors, t: Pii, values: &[&str]) -> bool {
    let max_fail = values.len() - (values.len() * 80).div_ceil(100);
    let mut fail = 0;
    for v in values {
        if !det.validates(t, v) {
            fail += 1;
            if fail > max_fail {
                return false;
            }
        }
    }
    true
}

fn classify(det: &Detectors, cleaned: &[&str], hint: Option<Pii>) -> Option<(Pii, Conf)> {
    if !cleaned.is_empty()
        && let Some(t) = STRUCTURED
            .into_iter()
            .find(|&t| value_rule(det, t, cleaned))
    {
        let conf = if cleaned.len() >= CONFIRM_MIN {
            Conf::Confirmed
        } else {
            Conf::Likely
        };
        return Some((t, conf));
    }
    let h = hint?;
    if cleaned.iter().any(|v| det.validates(h, v)) {
        Some((h, Conf::Likely))
    } else {
        Some((h, Conf::Possible))
    }
}

// ---------------------------------------------------------------- whole-chunk reads

/// One column chunk already fetched in a single range; serves the page
/// reader's requests from memory, translating file offsets.
struct Window {
    base: u64,
    data: Bytes,
    file_len: u64,
}

impl Length for Window {
    fn len(&self) -> u64 {
        self.file_len
    }
}

impl ChunkReader for Window {
    type T = bytes::buf::Reader<Bytes>;
    fn get_read(&self, start: u64) -> PqResult<Self::T> {
        Ok(self.data.slice((start - self.base) as usize..).reader())
    }
    fn get_bytes(&self, start: u64, length: usize) -> PqResult<Bytes> {
        let s = (start - self.base) as usize;
        Ok(self.data.slice(s..s + length))
    }
}

fn all_values(counted: &Arc<Counted>, col: &ColumnChunkMetaData, rows: usize) -> Vec<String> {
    let (start, len) = col.byte_range();
    let window = Window {
        base: start,
        data: Bytes::from(counted.read_range(start, len as usize)),
        file_len: counted.len,
    };
    let pages = SerializedPageReader::new(Arc::new(window), col, rows, None).unwrap();
    match get_column_reader(col.column_descr_ptr(), Box::new(pages)) {
        ColumnReader::ByteArrayColumnReader(mut r) => {
            let (mut v, mut def): (Vec<ByteArray>, Vec<i16>) = (Vec::new(), Vec::new());
            r.read_records(rows, Some(&mut def), None, &mut v).unwrap();
            v.iter()
                .map(|b| String::from_utf8_lossy(b.data()).into_owned())
                .collect()
        }
        _ => Vec::new(),
    }
}

fn dictionary_values(src: &Src, col: &ColumnChunkMetaData, rows: usize) -> Vec<String> {
    let location = PageLocation {
        offset: col.data_page_offset(),
        compressed_page_size: 0, // never fetched: we stop after the dictionary page
        first_row_index: 0,
    };
    let mut pages =
        SerializedPageReader::new(Arc::new(src.clone()), col, rows, Some(vec![location])).unwrap();
    match pages.get_next_page().unwrap() {
        Some(Page::DictionaryPage {
            buf, num_values, ..
        }) => decode_plain(
            col.column_type(),
            col.column_descr().type_length().max(0) as usize,
            &buf,
            num_values as usize,
        ),
        other => panic!(
            "expected a dictionary page, got {:?}",
            other.map(|p| p.page_type())
        ),
    }
}

// ---------------------------------------------------------------- manifest + results

#[derive(Deserialize)]
struct Manifest2 {
    files: Vec<File2>,
}

#[derive(Deserialize)]
struct File2 {
    path: String,
    writer: String,
    dataset: String,
    rows: u64,
    columns: BTreeMap<String, Truth2>,
}

#[derive(Deserialize, Clone, Default)]
struct Truth2 {
    #[serde(rename = "type")]
    ty: Option<Pii>,
    embedded_rate: Option<f64>,
}

#[derive(Serialize)]
struct Col2 {
    column: String,
    truth: Option<Pii>,
    embedded_rate: Option<f64>,
    samples: usize,
    cleaned: usize,
    avg_bytes: f64,
    free_text: bool,
    flag: Option<Pii>,
    conf: Option<Conf>,
    embedded: bool,
    /// Post-hoc diagnostic, added after the first run: the embedded rule
    /// applied to page values only, without the min/max statistics.
    embedded_pages_only: bool,
}

#[derive(Serialize)]
struct Level {
    level: Conf,
    recall: f64,
    hits: usize,
    flags: usize,
    correct: usize,
    precision: Option<f64>,
}

#[derive(Serialize)]
struct StatJunk {
    values: usize,
    cleaned_away: usize,
    invalid_after_cleaning: usize,
}

#[derive(Serialize)]
struct Res2 {
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
    structured_pii: usize,
    levels: Vec<Level>,
    free_text_columns: Vec<String>,
    embedded_truth: usize,
    embedded_hits: usize,
    embedded_flags: usize,
    embedded_correct: usize,
    stat_junk: StatJunk,
    columns: Vec<Col2>,
}

fn avg_bytes(meta: &ParquetMetaData, i: usize) -> f64 {
    let (mut size, mut n) = (0i64, 0i64);
    for rg in meta.row_groups() {
        size += rg.column(i).uncompressed_size();
        n += rg.column(i).num_values();
    }
    if n == 0 { 0.0 } else { size as f64 / n as f64 }
}

fn measure(det: &Detectors, data: &Path, f: &File2, strategy: u8) -> Res2 {
    let counted = Counted::open(&data.join(&f.path));
    let src = Src(counted.clone());
    let started = Instant::now();

    let meta = read_footer(&counted);
    let schema = meta.file_metadata().schema_descr();
    let ncols = schema.num_columns();
    let avg: Vec<f64> = (0..ncols).map(|i| avg_bytes(&meta, i)).collect();
    let free: Vec<bool> = (0..ncols)
        .map(|i| {
            schema.column(i).physical_type() == PhysicalType::BYTE_ARRAY
                && avg[i] > FREE_TEXT_AVG_BYTES
        })
        .collect();
    let mut samples: Vec<Vec<String>> = vec![Vec::new(); ncols];

    // S1: min/max statistics of every row group.
    let mut stat_samples: Vec<Vec<String>> = vec![Vec::new(); ncols];
    for rg in meta.row_groups() {
        for (i, col) in rg.columns().iter().enumerate() {
            if let Some(stats) = col.statistics() {
                for b in [stats.min_bytes_opt(), stats.max_bytes_opt()]
                    .into_iter()
                    .flatten()
                {
                    if let Some(v) = stat_value(col.column_type(), b) {
                        stat_samples[i].push(v);
                    }
                }
            }
        }
    }
    for i in 0..ncols {
        samples[i].extend(stat_samples[i].iter().cloned());
    }

    // S3: row group 0's dictionary pages, else its first data page.
    if strategy >= 3 {
        let rg0 = meta.row_group(0);
        let rows0 = rg0.num_rows() as usize;
        for (i, col) in rg0.columns().iter().enumerate() {
            if strategy >= 4 && free[i] {
                continue; // read whole below
            }
            if col.dictionary_page_offset().is_some() {
                samples[i].extend(dictionary_values(&src, col, rows0));
            } else {
                samples[i].extend(first_data_page_values(&src, col, rows0));
            }
        }
    }
    // S4: every page of the free-text columns.
    if strategy >= 4 {
        for rg in meta.row_groups() {
            for (i, col) in rg.columns().iter().enumerate() {
                if free[i] {
                    samples[i].extend(all_values(&counted, col, rg.num_rows() as usize));
                }
            }
        }
    }
    let wall_ms = started.elapsed().as_secs_f64() * 1000.0;

    let mut columns = Vec::new();
    let mut junk = StatJunk {
        values: 0,
        cleaned_away: 0,
        invalid_after_cleaning: 0,
    };
    for i in 0..ncols {
        let name = schema.column(i).name().to_string();
        let t = f.columns.get(&name).cloned().unwrap_or_default();
        let cleaned = clean(&samples[i]);
        let (flag, conf) = classify(det, &cleaned, name_hint(&name)).unzip();
        if let Some(ty) = t.ty.filter(|ty| STRUCTURED.contains(ty)) {
            let stat_clean = clean(&stat_samples[i]);
            junk.values += stat_samples[i].len();
            junk.cleaned_away += stat_samples[i].len() - stat_clean.len();
            junk.invalid_after_cleaning +=
                stat_clean.iter().filter(|v| !det.validates(ty, v)).count();
        }
        columns.push(Col2 {
            column: name,
            truth: t.ty,
            embedded_rate: t.embedded_rate,
            samples: samples[i].len(),
            cleaned: cleaned.len(),
            avg_bytes: avg[i],
            free_text: free[i],
            flag,
            conf,
            embedded: free[i] && cleaned.iter().any(|v| det.email_anywhere.is_match(v)),
            embedded_pages_only: free[i]
                && clean(&samples[i][stat_samples[i].len()..])
                    .iter()
                    .any(|v| det.email_anywhere.is_match(v)),
        });
    }

    let structured: Vec<&Col2> = columns
        .iter()
        .filter(|c| c.truth.is_some_and(|t| STRUCTURED.contains(&t)))
        .collect();
    let levels = LEVELS
        .into_iter()
        .map(|level| {
            let at = |c: &&Col2| c.conf.is_some_and(|x| x >= level);
            let hits = structured
                .iter()
                .filter(|c| at(c) && c.flag == c.truth)
                .count();
            let flagged: Vec<&Col2> = columns.iter().filter(at).collect();
            let correct = flagged.iter().filter(|c| c.flag == c.truth).count();
            Level {
                level,
                recall: crate::pct(hits, structured.len()),
                hits,
                flags: flagged.len(),
                correct,
                precision: (!flagged.is_empty()).then(|| crate::pct(correct, flagged.len())),
            }
        })
        .collect();
    let is_embedded = |c: &&Col2| c.truth == Some(Pii::EmailEmbedded);
    let bytes_read = counted.bytes.load(Ordering::Relaxed);
    let uncompressed: i64 = meta
        .row_groups()
        .iter()
        .flat_map(|rg| rg.columns())
        .map(|c| c.uncompressed_size())
        .sum();
    Res2 {
        file: f.path.clone(),
        writer: f.writer.clone(),
        dataset: f.dataset.clone(),
        rows: f.rows,
        row_groups: meta.num_row_groups(),
        strategy: format!("S{strategy}"),
        file_bytes: counted.len,
        uncompressed_bytes: uncompressed,
        bytes_read,
        ranges: counted.ranges.load(Ordering::Relaxed),
        wall_ms,
        pct_of_file: 100.0 * bytes_read as f64 / counted.len as f64,
        pct_of_uncompressed: 100.0 * bytes_read as f64 / uncompressed as f64,
        structured_pii: structured.len(),
        levels,
        free_text_columns: columns
            .iter()
            .filter(|c| c.free_text)
            .map(|c| c.column.clone())
            .collect(),
        embedded_truth: columns.iter().filter(is_embedded).count(),
        embedded_hits: columns
            .iter()
            .filter(|c| is_embedded(c) && c.embedded)
            .count(),
        embedded_flags: columns.iter().filter(|c| c.embedded).count(),
        embedded_correct: columns
            .iter()
            .filter(|c| c.embedded && is_embedded(c))
            .count(),
        stat_junk: junk,
        columns,
    }
}

pub fn run(data: &Path) {
    let text = std::fs::read_to_string(data.join("manifest.json")).unwrap();
    let manifest: Manifest2 = serde_json::from_str(&text).unwrap();
    let manifest1: Manifest = serde_json::from_str(&text).unwrap();
    let det = Detectors::new();

    let mut enc: Vec<EncodingRow> = Vec::new();
    for f in &manifest1.files {
        if f.dataset != "customers_lake" || f.path.ends_with("_000.parquet") {
            enc.extend(encodings(data, f));
        }
    }
    let mut results = Vec::new();
    for f in &manifest.files {
        for s in [1, 3, 4] {
            let r = measure(&det, data, f, s);
            if f.dataset != "customers_lake" {
                eprintln!(
                    "{:8} {:10} {} read={:>11} ({:7.3}% uncompr) ranges={:>4} confirmed={:5.1}%/{:?} embedded={}/{} of {} {:8.1}ms",
                    r.writer,
                    r.dataset,
                    r.strategy,
                    r.bytes_read,
                    r.pct_of_uncompressed,
                    r.ranges,
                    r.levels[0].recall,
                    r.levels[0].precision,
                    r.embedded_correct,
                    r.embedded_flags,
                    r.embedded_truth,
                    r.wall_ms
                );
            }
            results.push(r);
        }
    }
    let out = serde_json::json!({
        "versions": manifest1.versions, "probe_bytes": crate::PROBE, "encodings": enc, "results": results,
    });
    let out_dir = data.parent().unwrap().join("results");
    std::fs::create_dir_all(&out_dir).unwrap();
    let path = out_dir.join("round2.json");
    std::fs::write(&path, serde_json::to_string(&out).unwrap()).unwrap();
    eprintln!("wrote {}", path.display());
}
