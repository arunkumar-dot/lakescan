//! Test doubles for content scanning: an in-memory [`ObjectReader`] and a
//! small Parquet builder on top of the `parquet` crate's own writer, so
//! unit tests build exactly the files they need.

use parquet::basic::{LogicalType, Repetition, Type as Physical};
use parquet::data_type::{BoolType, ByteArray, ByteArrayType, DoubleType, Int32Type, Int64Type};
use parquet::errors::ParquetError;
use parquet::file::properties::{EnabledStatistics, WriterProperties, WriterVersion};
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::types::Type;
use std::sync::Arc;

/// The in-memory reader the tests use: [`SimStore`](super::SimStore)
/// with no latency.
pub(crate) type MemoryReader = super::SimStore;

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
    /// `required boolean`.
    Bool(Vec<bool>),
    /// A standard three-level `LIST` of `optional binary (STRING)`
    /// (`<name>.list.element`), one list per row.
    List(Vec<Vec<String>>),
    /// A standard three-level `LIST` of structs with one `optional binary
    /// (STRING)` field (`<name>.list.element.<field>`), one list per row.
    ListOfStruct(&'static str, Vec<Vec<String>>),
}

/// A string leaf.
fn string_leaf(name: &str, repetition: Repetition) -> parquet::errors::Result<Arc<Type>> {
    Ok(Arc::new(
        Type::primitive_type_builder(name, Physical::BYTE_ARRAY)
            .with_repetition(repetition)
            .with_logical_type(Some(LogicalType::String))
            .build()?,
    ))
}

/// `optional group <name> (LIST) { repeated group list { <element> } }`.
fn list_of(name: &str, element: Arc<Type>) -> parquet::errors::Result<Arc<Type>> {
    let list = Type::group_type_builder("list")
        .with_repetition(Repetition::REPEATED)
        .with_fields(vec![element])
        .build()?;
    Ok(Arc::new(
        Type::group_type_builder(name)
            .with_repetition(Repetition::OPTIONAL)
            .with_logical_type(Some(LogicalType::List))
            .with_fields(vec![Arc::new(list)])
            .build()?,
    ))
}

impl Values {
    /// The column's schema type, built rather than parsed from text, so a
    /// name may hold any character (hostile-name tests rely on that).
    fn schema_type(&self, name: &str) -> parquet::errors::Result<Arc<Type>> {
        match self {
            Self::List(_) => {
                return list_of(name, string_leaf("element", Repetition::OPTIONAL)?);
            }
            Self::ListOfStruct(field, _) => {
                let element = Type::group_type_builder("element")
                    .with_repetition(Repetition::OPTIONAL)
                    .with_fields(vec![string_leaf(field, Repetition::OPTIONAL)?])
                    .build()?;
                return list_of(name, Arc::new(element));
            }
            _ => {}
        }
        let (physical, repetition, logical) = match self {
            Self::Text(_) => (
                Physical::BYTE_ARRAY,
                Repetition::OPTIONAL,
                Some(LogicalType::String),
            ),
            Self::Int64(_) => (Physical::INT64, Repetition::OPTIONAL, None),
            Self::Date(_) => (
                Physical::INT32,
                Repetition::OPTIONAL,
                Some(LogicalType::Date),
            ),
            Self::Double(_) => (Physical::DOUBLE, Repetition::REQUIRED, None),
            Self::RepeatedText(_) => (
                Physical::BYTE_ARRAY,
                Repetition::REPEATED,
                Some(LogicalType::String),
            ),
            Self::Bool(_) => (Physical::BOOLEAN, Repetition::REQUIRED, None),
            Self::List(_) | Self::ListOfStruct(..) => {
                return Err(ParquetError::General("built above".to_owned()));
            }
        };
        Ok(Arc::new(
            Type::primitive_type_builder(name, physical)
                .with_repetition(repetition)
                .with_logical_type(logical)
                .build()?,
        ))
    }

    fn len(&self) -> usize {
        match self {
            Self::Text(v) => v.len(),
            Self::Int64(v) => v.len(),
            Self::Date(v) => v.len(),
            Self::Double(v) => v.len(),
            Self::RepeatedText(v) => v.len(),
            Self::Bool(v) => v.len(),
            Self::List(v) | Self::ListOfStruct(_, v) => v.len(),
        }
    }
}

/// The values and levels of lists of strings whose element is defined at
/// `defined` (3 for a list of strings, 4 for a list of one-field structs):
/// an empty list is defined at 1 (the list, no element), each element
/// repeats at 1 after the first.
fn list_levels(lists: &[Vec<String>], defined: i16) -> (Vec<ByteArray>, Vec<i16>, Vec<i16>) {
    let (mut values, mut definitions, mut repetitions) = (Vec::new(), Vec::new(), Vec::new());
    for list in lists {
        if list.is_empty() {
            definitions.push(1);
            repetitions.push(0);
        }
        for (at, value) in list.iter().enumerate() {
            values.push(ByteArray::from(value.as_str()));
            definitions.push(defined);
            repetitions.push(i16::from(at > 0));
        }
    }
    (values, definitions, repetitions)
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

/// Writes rows `from..to` of `values` to `column`.
fn write_column(
    column: &mut parquet::file::writer::SerializedColumnWriter<'_>,
    values: &Values,
    from: usize,
    to: usize,
) -> parquet::errors::Result<()> {
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
        Values::Bool(all) => {
            column
                .typed::<BoolType>()
                .write_batch(&split(all, from, to), None, None)?;
        }
        Values::List(all) | Values::ListOfStruct(_, all) => {
            let defined = if matches!(values, Values::List(_)) {
                3
            } else {
                4
            };
            let (present, definitions, repetitions) = list_levels(&split(all, from, to), defined);
            column.typed::<ByteArrayType>().write_batch(
                &present,
                Some(&definitions),
                Some(&repetitions),
            )?;
        }
        Values::RepeatedText(all) => {
            let part = split(all, from, to);
            let present: Vec<ByteArray> =
                part.iter().map(|s| ByteArray::from(s.as_str())).collect();
            let ones = vec![1_i16; present.len()];
            let zeros = vec![0_i16; present.len()];
            column
                .typed::<ByteArrayType>()
                .write_batch(&present, Some(&ones), Some(&zeros))?;
        }
    }
    Ok(())
}

/// Writes `columns` (all the same length, at least one row) as a Parquet
/// file.
pub(crate) fn parquet_file(
    columns: &[(&str, Values)],
    layout: Layout,
) -> parquet::errors::Result<Vec<u8>> {
    let rows = columns.first().map_or(0, |(_, values)| values.len());
    let fields = columns
        .iter()
        .map(|(name, values)| values.schema_type(name))
        .collect::<parquet::errors::Result<Vec<_>>>()?;
    let schema = Arc::new(
        Type::group_type_builder("test")
            .with_fields(fields)
            .build()?,
    );
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
            write_column(&mut column, values, from, to)?;
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

/// Domains under the reserved `.example` top-level domain (RFC 2606): no
/// test address can belong to anyone, and `clean` keeps them (it drops
/// `example.com`, `.org`, `.net` and `.test` as test accounts).
const EMAIL_DOMAINS: [&str; 7] = [
    "mail.example",
    "acme.example",
    "fintech.example",
    "shop.example",
    "corp.example",
    "bank.example",
    "post.example",
];

/// `n` distinct, valid email addresses, on reserved domains only.
pub(crate) fn emails(n: usize) -> Vec<Option<String>> {
    (0..n)
        .map(|i| {
            let domain = EMAIL_DOMAINS.get(i % EMAIL_DOMAINS.len()).copied();
            Some(format!("person.{i}@{}", domain.unwrap_or("mail.example")))
        })
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
