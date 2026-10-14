//! Test doubles for content scanning: an in-memory [`ObjectReader`] and a
//! small Parquet builder on top of the `parquet` crate's own writer, so
//! unit tests build exactly the files they need.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use aws_sdk_s3::primitives::{AggregatedBytes, ByteStream};
use parquet::data_type::{ByteArray, ByteArrayType, DoubleType, Int32Type, Int64Type};
use parquet::errors::ParquetError;
use parquet::file::properties::{EnabledStatistics, WriterProperties, WriterVersion};
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;

use super::fetch::{FetchError, ObjectReader};

/// Objects held in memory, by key. Keys in `denied` answer every read with
/// [`FetchError::AccessDenied`].
#[derive(Debug, Default, Clone)]
pub(crate) struct MemoryReader {
    pub(crate) objects: BTreeMap<String, Vec<u8>>,
    pub(crate) denied: BTreeSet<String>,
    /// Every `(key, start, end)` read, in order.
    pub(crate) reads: Vec<(String, u64, u64)>,
}

impl MemoryReader {
    pub(crate) fn with(mut self, key: &str, body: Vec<u8>) -> Self {
        self.objects.insert(key.to_owned(), body);
        self
    }
}

impl ObjectReader for MemoryReader {
    async fn read_range(
        &mut self,
        key: &str,
        start: u64,
        end: u64,
    ) -> Result<AggregatedBytes, FetchError> {
        self.reads.push((key.to_owned(), start, end));
        if self.denied.contains(key) {
            return Err(FetchError::AccessDenied);
        }
        let body = self.objects.get(key).ok_or(FetchError::Failed)?;
        let from = usize::try_from(start).map_err(|_| FetchError::Failed)?;
        let to = usize::try_from(end).map_err(|_| FetchError::Failed)?;
        let slice = body
            .get(from..to.min(body.len()))
            .ok_or(FetchError::Failed)?;
        ByteStream::from(slice.to_vec())
            .collect()
            .await
            .map_err(|_| FetchError::Failed)
    }
}

/// One column of a test file.
pub(crate) enum Values {
    /// `optional binary (STRING)`.
    Text(Vec<Option<String>>),
    /// `optional int64`.
    Int64(Vec<Option<i64>>),
    /// `optional int32 (DATE)`.
    Date(Vec<Option<i32>>),
    /// `required double`.
    Double(Vec<f64>),
    /// `repeated binary (STRING)`, one element per row.
    RepeatedText(Vec<String>),
}

impl Values {
    fn schema_line(&self, name: &str) -> String {
        match self {
            Self::Text(_) => format!("optional binary {name} (STRING);"),
            Self::Int64(_) => format!("optional int64 {name};"),
            Self::Date(_) => format!("optional int32 {name} (DATE);"),
            Self::Double(_) => format!("required double {name};"),
            Self::RepeatedText(_) => format!("repeated binary {name} (STRING);"),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Text(v) => v.len(),
            Self::Int64(v) => v.len(),
            Self::Date(v) => v.len(),
            Self::Double(v) => v.len(),
            Self::RepeatedText(v) => v.len(),
        }
    }
}

/// How the test file is written.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Layout {
    pub(crate) row_group_rows: usize,
    pub(crate) offset_index: bool,
    pub(crate) dictionary: bool,
    /// The writer's data page size limit, in bytes.
    pub(crate) page_bytes: usize,
    /// The compression codec.
    pub(crate) compression: parquet::basic::Compression,
    /// Data page v2 (Parquet 2.0) instead of v1.
    pub(crate) v2: bool,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            row_group_rows: 1_000_000,
            offset_index: true,
            dictionary: true,
            page_bytes: 1024 * 1024,
            compression: parquet::basic::Compression::UNCOMPRESSED,
            v2: false,
        }
    }
}

fn split<T: Clone>(values: &[T], from: usize, to: usize) -> Vec<T> {
    values.get(from..to).map(<[T]>::to_vec).unwrap_or_default()
}

fn optional<T: Clone>(values: &[Option<T>]) -> (Vec<T>, Vec<i16>) {
    let present = values.iter().flatten().cloned().collect();
    let levels = values.iter().map(|v| i16::from(v.is_some())).collect();
    (present, levels)
}

/// Writes `columns` (all the same length, at least one row) as a Parquet
/// file.
pub(crate) fn parquet_file(
    columns: &[(&str, Values)],
    layout: Layout,
) -> parquet::errors::Result<Vec<u8>> {
    let rows = columns.first().map_or(0, |(_, values)| values.len());
    let schema = format!(
        "message test {{ {} }}",
        columns
            .iter()
            .map(|(name, values)| values.schema_line(name))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let schema = Arc::new(parse_message_type(&schema)?);
    let mut props = WriterProperties::builder()
        .set_dictionary_enabled(layout.dictionary)
        .set_data_page_row_count_limit(usize::MAX)
        .set_data_page_size_limit(layout.page_bytes)
        .set_compression(layout.compression)
        .set_writer_version(if layout.v2 {
            WriterVersion::PARQUET_2_0
        } else {
            WriterVersion::PARQUET_1_0
        });
    if !layout.offset_index {
        props = props
            .set_statistics_enabled(EnabledStatistics::Chunk)
            .set_offset_index_disabled(true);
    }
    let mut writer = SerializedFileWriter::new(Vec::new(), schema, Arc::new(props.build()))?;

    let mut from = 0;
    while from < rows {
        let to = (from + layout.row_group_rows).min(rows);
        let mut group = writer.next_row_group()?;
        for (_, values) in columns {
            let Some(mut column) = group.next_column()? else {
                return Err(ParquetError::General("missing column".to_owned()));
            };
            match values {
                Values::Text(all) => {
                    let (present, levels) = optional(&split(all, from, to));
                    let present: Vec<ByteArray> = present
                        .into_iter()
                        .map(|s| ByteArray::from(s.as_str()))
                        .collect();
                    column
                        .typed::<ByteArrayType>()
                        .write_batch(&present, Some(&levels), None)?;
                }
                Values::Int64(all) => {
                    let (present, levels) = optional(&split(all, from, to));
                    column
                        .typed::<Int64Type>()
                        .write_batch(&present, Some(&levels), None)?;
                }
                Values::Date(all) => {
                    let (present, levels) = optional(&split(all, from, to));
                    column
                        .typed::<Int32Type>()
                        .write_batch(&present, Some(&levels), None)?;
                }
                Values::Double(all) => {
                    column
                        .typed::<DoubleType>()
                        .write_batch(&split(all, from, to), None, None)?;
                }
                Values::RepeatedText(all) => {
                    let part = split(all, from, to);
                    let present: Vec<ByteArray> =
                        part.iter().map(|s| ByteArray::from(s.as_str())).collect();
                    let ones = vec![1_i16; present.len()];
                    let zeros = vec![0_i16; present.len()];
                    column.typed::<ByteArrayType>().write_batch(
                        &present,
                        Some(&ones),
                        Some(&zeros),
                    )?;
                }
            }
            column.close()?;
        }
        group.close()?;
        from = to;
    }
    if rows == 0 {
        return Err(ParquetError::General("a test file needs a row".to_owned()));
    }
    writer.into_inner()
}

/// `n` distinct, valid email addresses.
pub(crate) fn emails(n: usize) -> Vec<Option<String>> {
    (0..n)
        .map(|i| Some(format!("person.{i}@example{}.com", i % 7)))
        .collect()
}

/// `n` distinct Indian mobile numbers, as integers.
pub(crate) fn mobiles(n: usize) -> Vec<Option<i64>> {
    (0..n)
        .map(|i| i64::try_from(i).ok().map(|i| 9_876_000_000 + i))
        .collect()
}

/// `n` Verhoeff-valid Aadhaar numbers, as integers.
pub(crate) fn aadhaars(n: usize) -> Vec<Option<i64>> {
    let mut out = Vec::with_capacity(n);
    let mut base: i64 = 23_456_789_000;
    while out.len() < n {
        for check in 0..10 {
            let candidate = base * 10 + check;
            if super::detect::validates(crate::model::PiiType::InAadhaar, &candidate.to_string()) {
                out.push(Some(candidate));
                break;
            }
        }
        base += 1;
    }
    out
}

/// `n` lowercase hex digests: the `email_sha256` decoy.
pub(crate) fn digests(n: usize) -> Vec<Option<String>> {
    (0..n)
        .map(|i| {
            Some(format!(
                "{:064x}",
                u128::try_from(i).unwrap_or(0) * 0x9e37_79b9_7f4a_7c15
            ))
        })
        .collect()
}
