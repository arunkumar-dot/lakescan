//! The read plan for one Parquet file, and decoding with the `parquet`
//! crate's own page and column readers.
//!
//! **Opening.** A file at or below the whole-file maximum is read in one
//! request and parsed in memory. A larger one is opened with one tail read
//! of [`TAIL_BYTES`] for the footer (plus one more if the footer is longer
//! than that). The `PAR1` magic is checked first: `PARE` means Parquet
//! modular encryption, and any other trailer is not Parquet, unless the
//! file *starts* with `PAR1`, in which case it is a truncated Parquet file.
//!
//! **Sampling a column.** For each candidate column, the first data page
//! of row group 0 is read, together with the dictionary page before it, if
//! any: one exact range when an offset index gives the page's end, else a
//! window grown until the pages fit. Before `parquet` sees any page, on
//! both the whole-file and the partial path, [`plan_pages`] reads its
//! header (see `header`) and checks what it *declares*: a compressed or
//! uncompressed size over [`PAGE_CAP`], or a dictionary of more than
//! [`MAX_DICTIONARY_VALUES`] values, skips the column as page-too-large
//! with nothing allocated for it. Values are then decoded by
//! `SerializedPageReader` and the typed column reader from exactly the
//! checked pages, with the chunk's metadata rebased onto the fetched range,
//! and every synchronous `parquet` call runs inside [`contain`], so a
//! parser panic costs one file, not the scan.
//!
//! **Codecs.** `parquet` decompresses Snappy, LZ4, `LZ4_RAW` and ZSTD pages
//! into a buffer of the declared size. Its GZIP and BROTLI decoders read to
//! the end of the stream, however large, so `LakeScan` decompresses those
//! pages itself (see [`inflate`]): at most the declared size plus one byte
//! is read, and a page whose output differs from its declared size is
//! unreadable. The decompressed pages, with their headers re-encoded, are
//! then handed to `parquet` as an uncompressed chunk. LZO is skipped as an
//! unsupported codec.
//!
//! **Files with nothing examined.** A file whose value-bearing candidate
//! columns (strings and integers) were all skipped is `no-column-examined`:
//! not scanned, so a lake of such files cannot pass silently.
//!
//! **Escalation.** A column whose cleaned sample is too small or ambiguous
//! after row group 0 (see `classify::Evidence::needs_more`) is sampled
//! again in the middle row group, then the last: never more than
//! [`MAX_ROW_GROUPS`] per column.

use std::io::Read as _;
use std::ops::Deref;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use aws_sdk_s3::primitives::AggregatedBytes;
use parquet::basic::{Compression, ConvertedType, LogicalType, Type as Physical};
use parquet::column::page::{Page, PageMetadata, PageReader};
use parquet::column::reader::{ColumnReader, get_column_reader};
use parquet::data_type::{ByteArray, FixedLenByteArray};
use parquet::errors::Result as ParquetResult;
use parquet::file::metadata::{ColumnChunkMetaData, ParquetMetaData, ParquetMetaDataReader};
use parquet::file::page_index::index_reader::decode_offset_index;
use parquet::file::page_index::offset_index::PageLocation;
use parquet::file::properties::ReaderProperties;
use parquet::file::reader::ChunkReader;
use parquet::file::serialized_reader::SerializedPageReader;
use parquet::schema::types::{ColumnDescPtr, ColumnDescriptor};

use super::classify::{Evidence, Kind, classify};
use super::clean::{clean, drop_dominant};
use super::fetch::{FetchError, ObjectReader};
use super::header;
use super::names;
use super::{ColumnFinding, FileStats};
use crate::model::{ColumnDetail, NotScannedReason};

/// The tail read that opens a partially read file.
pub const TAIL_BYTES: u64 = 64 * 1024;
/// The largest footer read; a larger one is `footer-too-large`.
pub const FOOTER_CAP: u64 = 16 * 1024 * 1024;
/// The largest single page read; a column whose dictionary or first data
/// page is larger is skipped.
pub const PAGE_CAP: u64 = 8 * 1024 * 1024;
/// The most cleaned values kept per column per row group.
pub const MAX_VALUES_PER_ROW_GROUP: usize = 2000;
/// The most row groups sampled per column.
pub const MAX_ROW_GROUPS: usize = 3;
/// The first window read for a column chunk without an offset index.
const WINDOW_START: u64 = 64 * 1024;
/// The longest page header accepted. Headers are normally tens of bytes;
/// page statistics can make them longer.
const MAX_HEADER: u64 = 1024 * 1024;
/// The largest window: a dictionary page and a first data page at the
/// cap, each with the longest header.
const WINDOW_LIMIT: u64 = 2 * (PAGE_CAP + MAX_HEADER);
/// The most values a dictionary page may declare. `parquet` allocates one
/// slot per declared value up front, so this bounds that allocation (one
/// slot is at most 32 bytes: 32 MiB).
const MAX_DICTIONARY_VALUES: u64 = 1024 * 1024;
/// The largest offset index read for one column chunk.
const OFFSET_INDEX_CAP: u64 = 1024 * 1024;
/// Values read from a page per call.
const BATCH: usize = 1024;

const MAGIC: &[u8] = b"PAR1";
const ENCRYPTED_MAGIC: &[u8] = b"PARE";

/// What a fetched byte range must offer: `parquet`'s in-memory
/// [`ChunkReader`], plus slicing and building from a `Vec`. The one
/// implementation is the buffer type `AggregatedBytes::into_bytes` returns;
/// it is never named here, only inferred (see [`session`]).
pub(super) trait Window:
    ChunkReader + Deref<Target = [u8]> + Clone + From<Vec<u8>> + 'static
{
}

impl<T> Window for T where T: ChunkReader + Deref<Target = [u8]> + Clone + From<Vec<u8>> + 'static {}

/// How a file was opened.
pub(super) enum Opened<B> {
    /// Read whole; every column chunk is in memory.
    Whole(B),
    /// Only the tail is in memory, starting at byte `start`.
    Partial { tail: B, start: u64 },
}

/// What sampling one column in one row group produced.
enum ColumnRead {
    /// Cleaned values, at most [`MAX_VALUES_PER_ROW_GROUP`].
    Values(Vec<String>),
    /// The dictionary or first data page is over [`PAGE_CAP`].
    PageTooLarge,
    /// The pages could not be decoded.
    Unreadable,
    /// The chunk's codec cannot be decoded safely.
    UnsupportedCodec,
}

/// Who decompresses a column chunk's pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Codec {
    /// `parquet`, whose decoder for it is bounded by the declared size
    /// (or there is nothing to decompress).
    Parquet,
    /// `LakeScan`, with [`inflate`].
    Gzip,
    /// `LakeScan`, with [`inflate`].
    Brotli,
}

/// A column chunk's checked pages, ready to decode.
struct Checked<B> {
    /// The buffer holding them, which starts at file offset `buffer_start`.
    data: B,
    buffer_start: u64,
    /// The chunk's first byte, as a file offset.
    chunk_start: u64,
    /// The chunk length the rebased metadata declares.
    chunk_len: u64,
    /// The first data page (header and body): its offset from the chunk's
    /// start, and its length. Anything before it is the dictionary page.
    page_offset: u64,
    page_len: u64,
}

/// What [`Session::scan`] found in an opened file.
pub(super) struct Scanned {
    /// One verdict per column found to hold PII.
    pub(super) findings: Vec<ColumnFinding>,
    /// Whether the file had string or integer columns to read, and none of
    /// them could be read.
    pub(super) nothing_examined: bool,
}

/// One file's reads: the reader, the object, and the running counts.
pub(super) struct Session<'a, R, B> {
    reader: &'a mut R,
    key: &'a str,
    size: u64,
    stats: &'a mut FileStats,
    convert: fn(AggregatedBytes) -> B,
}

/// A session reading `key` (`size` bytes) through `reader`, counting into
/// `stats`. The buffer type is whatever `AggregatedBytes::into_bytes`
/// returns, inferred rather than named.
pub(super) fn session<'a, R: ObjectReader>(
    reader: &'a mut R,
    key: &'a str,
    size: u64,
    stats: &'a mut FileStats,
) -> Session<'a, R, impl Window> {
    Session {
        reader,
        key,
        size,
        stats,
        convert: AggregatedBytes::into_bytes,
    }
}

impl<R: ObjectReader, B: Window> Session<'_, R, B> {
    /// Reads `start..end`, counting the request and the bytes returned. A
    /// short read (the object changed since it was listed) is unreadable.
    async fn get(&mut self, start: u64, end: u64) -> Result<B, NotScannedReason> {
        self.stats.get_requests = self.stats.get_requests.saturating_add(1);
        let data = match self.reader.read_range(self.key, start, end).await {
            Ok(data) => (self.convert)(data),
            Err(FetchError::AccessDenied) => return Err(NotScannedReason::AccessDenied),
            Err(FetchError::Failed) => return Err(NotScannedReason::Unreadable),
        };
        let len = u64::try_from(as_slice(&data).len()).unwrap_or(u64::MAX);
        self.stats.bytes_read = self.stats.bytes_read.saturating_add(len);
        if Some(len) == end.checked_sub(start) {
            Ok(data)
        } else {
            Err(NotScannedReason::Unreadable)
        }
    }

    /// Opens the file: reads it whole or reads its tail, checks the magic,
    /// and decodes the footer.
    pub(super) async fn open(
        &mut self,
        whole_file_max: u64,
    ) -> Result<(ParquetMetaData, Opened<B>), NotScannedReason> {
        if self.size == 0 {
            return Err(NotScannedReason::NotParquet);
        }
        let whole = self.size <= whole_file_max;
        let start = if whole {
            0
        } else {
            self.size.saturating_sub(TAIL_BYTES)
        };
        let buffer = self.get(start, self.size).await?;
        let bytes = as_slice(&buffer);

        let tail_magic = bytes.len().checked_sub(4).and_then(|at| bytes.get(at..));
        if tail_magic == Some(ENCRYPTED_MAGIC) {
            return Err(NotScannedReason::Encrypted);
        }
        if self.size < 12 || tail_magic != Some(MAGIC) {
            let head = if start == 0 {
                bytes.get(..4).map(<[u8]>::to_vec)
            } else {
                Some(self.get(0, 4).await?.to_vec())
            };
            return Err(match head.as_deref() {
                Some(MAGIC) => NotScannedReason::Unreadable,
                Some(ENCRYPTED_MAGIC) => NotScannedReason::Encrypted,
                _ => NotScannedReason::NotParquet,
            });
        }

        let length_at = bytes.len().checked_sub(8);
        let footer_len = length_at
            .and_then(|at| bytes.get(at..at + 4))
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(|bytes| u64::from(u32::from_le_bytes(bytes)))
            .ok_or(NotScannedReason::Unreadable)?;
        if footer_len > FOOTER_CAP {
            return Err(NotScannedReason::FooterTooLarge);
        }
        let footer_start = self
            .size
            .checked_sub(8 + footer_len)
            .filter(|&at| at >= 4)
            .ok_or(NotScannedReason::Unreadable)?;

        let decode = |bytes: Option<&[u8]>| {
            let bytes = bytes.ok_or(NotScannedReason::Unreadable)?;
            contain(|| ParquetMetaDataReader::decode_metadata(bytes).ok())?
                .ok_or(NotScannedReason::Unreadable)
        };
        let metadata = if footer_start >= start {
            let from = usize::try_from(footer_start - start).ok();
            decode(from.and_then(|from| bytes.get(from..bytes.len().saturating_sub(8))))?
        } else {
            let footer = self.get(footer_start, self.size - 8).await?;
            decode(Some(&footer))?
        };

        let opened = if whole {
            Opened::Whole(buffer)
        } else {
            Opened::Partial {
                tail: buffer,
                start,
            }
        };
        Ok((metadata, opened))
    }

    /// Samples every candidate column of an opened file and classifies
    /// it. Fails only if a read is refused or fails outright; a column
    /// that cannot be decoded is skipped and counted.
    pub(super) async fn scan(
        &mut self,
        metadata: &ParquetMetaData,
        opened: &Opened<B>,
    ) -> Result<Scanned, NotScannedReason> {
        let schema = metadata.file_metadata().schema_descr();
        let order = row_group_order(metadata.num_row_groups());
        let mut findings = Vec::new();
        // String and integer columns: those whose values are read.
        let (mut to_read, mut read) = (0_u64, 0_u64);

        for index in 0..schema.num_columns() {
            let descr = schema.column(index);
            if descr.max_rep_level() > 0 {
                self.stats.skipped_repeated = self.stats.skipped_repeated.saturating_add(1);
                continue;
            }
            let Some(kind) = kind_of(&descr) else {
                self.stats.skipped_unsupported_type =
                    self.stats.skipped_unsupported_type.saturating_add(1);
                continue;
            };

            let mut values: Vec<String> = Vec::new();
            let mut evidence = Evidence::default();
            let mut skipped = None;
            if kind != Kind::Temporal {
                to_read += 1;
                for &row_group in &order {
                    match self
                        .sample(metadata, opened, row_group, index, &descr)
                        .await?
                    {
                        ColumnRead::Values(sample) => values.extend(sample),
                        other => {
                            skipped = Some(other);
                            break;
                        }
                    }
                    let mut cleaned = values.clone();
                    drop_dominant(&mut cleaned);
                    evidence = Evidence::of(&cleaned);
                    if !evidence.needs_more() {
                        break;
                    }
                }
            }

            let count = match skipped {
                Some(ColumnRead::PageTooLarge) => &mut self.stats.skipped_page_too_large,
                Some(ColumnRead::UnsupportedCodec) => &mut self.stats.skipped_unsupported_codec,
                Some(ColumnRead::Unreadable | ColumnRead::Values(_)) => {
                    &mut self.stats.skipped_unreadable
                }
                None => &mut self.stats.columns_examined,
            };
            *count = count.saturating_add(1);
            if skipped.is_some() {
                continue;
            }
            if kind != Kind::Temporal {
                read += 1;
            }
            if let Some(verdict) = classify(&evidence, names::hint(descr.name()), kind) {
                findings.push(ColumnFinding {
                    pii: verdict.pii,
                    detail: ColumnDetail::new(
                        &descr.path().string(),
                        verdict.confidence,
                        verdict.evidence,
                    ),
                });
            }
        }
        Ok(Scanned {
            findings,
            nothing_examined: to_read > 0 && read == 0,
        })
    }

    /// Reads and decodes the first data page (and the dictionary page, if
    /// any) of column `index` in `row_group`. Every page header is checked
    /// (see [`plan_pages`]) before `parquet` sees it, on both paths; a
    /// panic inside `parquet` fails the file as unreadable.
    async fn sample(
        &mut self,
        metadata: &ParquetMetaData,
        opened: &Opened<B>,
        row_group: usize,
        index: usize,
        descr: &ColumnDescPtr,
    ) -> Result<ColumnRead, NotScannedReason> {
        let Some(group) = metadata.row_groups().get(row_group) else {
            return Ok(ColumnRead::Unreadable);
        };
        let Some(chunk) = group.columns().get(index) else {
            return Ok(ColumnRead::Unreadable);
        };
        let Some(codec) = codec(chunk.compression()) else {
            return Ok(ColumnRead::UnsupportedCodec);
        };
        let rows = usize::try_from(group.num_rows()).unwrap_or(0);
        let Some((start, len)) = chunk_range(chunk)
            .filter(|&(start, len)| start.checked_add(len).is_some_and(|end| end <= self.size))
        else {
            return Ok(ColumnRead::Unreadable);
        };
        let min_value_bytes = min_value_bytes(descr);

        let (tail, tail_start) = match opened {
            Opened::Whole(data) => {
                let from = usize::try_from(start).ok();
                let to = usize::try_from(start + len).ok();
                let Some(bytes) = from
                    .zip(to)
                    .and_then(|(from, to)| as_slice(data).get(from..to))
                else {
                    return Ok(ColumnRead::Unreadable);
                };
                return match plan_pages(bytes, len, min_value_bytes) {
                    Plan::Ready {
                        offset,
                        len: page_len,
                    } => {
                        let checked = Checked {
                            data: data.clone(),
                            buffer_start: 0,
                            chunk_start: start,
                            chunk_len: len,
                            page_offset: offset,
                            page_len,
                        };
                        decode_contained(checked, chunk, codec, rows, descr)
                    }
                    Plan::TooLarge => Ok(ColumnRead::PageTooLarge),
                    Plan::NeedMore(_) | Plan::Invalid => Ok(ColumnRead::Unreadable),
                };
            }
            Opened::Partial { tail, start } => (tail, *start),
        };

        // The offset index, when present, says where the first data page
        // ends, so the first read usually covers everything needed.
        let first_end = match self.first_page_location(chunk, tail, tail_start).await? {
            Some(first) => {
                let end = u64::try_from(first.offset)
                    .ok()
                    .zip(u64::try_from(first.compressed_page_size).ok())
                    .and_then(|(offset, size)| offset.checked_add(size))
                    .filter(|&end| end > start && end <= start + len);
                match end {
                    Some(end) if end - start > WINDOW_LIMIT => return Ok(ColumnRead::PageTooLarge),
                    Some(end) => end - start,
                    None => len.min(WINDOW_START),
                }
            }
            None => len.min(WINDOW_START),
        };

        let mut window = self.get(start, start + first_end).await?;
        loop {
            let held = u64::try_from(as_slice(&window).len()).unwrap_or(u64::MAX);
            match plan_pages(as_slice(&window), len, min_value_bytes) {
                Plan::Ready {
                    offset,
                    len: page_len,
                } => {
                    let checked = Checked {
                        data: window,
                        buffer_start: start,
                        chunk_start: start,
                        chunk_len: held,
                        page_offset: offset,
                        page_len,
                    };
                    return decode_contained(checked, chunk, codec, rows, descr);
                }
                Plan::TooLarge => return Ok(ColumnRead::PageTooLarge),
                Plan::Invalid => return Ok(ColumnRead::Unreadable),
                Plan::NeedMore(needed) => {
                    let wanted = needed.min(len);
                    if wanted <= held {
                        return Ok(ColumnRead::Unreadable);
                    }
                    let more = self.get(start + held, start + wanted).await?;
                    let (window_bytes, more_bytes) = (as_slice(&window), as_slice(&more));
                    let mut combined = Vec::with_capacity(window_bytes.len() + more_bytes.len());
                    combined.extend_from_slice(window_bytes);
                    combined.extend_from_slice(more_bytes);
                    window = B::from(combined);
                }
            }
        }
    }

    /// The first page's location from the chunk's offset index, if it has
    /// one that can be read and decoded. Taken from the tail read when it
    /// lies there; otherwise fetched.
    async fn first_page_location(
        &mut self,
        chunk: &ColumnChunkMetaData,
        tail: &B,
        tail_start: u64,
    ) -> Result<Option<PageLocation>, NotScannedReason> {
        let offset = chunk
            .offset_index_offset()
            .and_then(|o| u64::try_from(o).ok());
        let length = chunk
            .offset_index_length()
            .and_then(|l| u64::try_from(l).ok());
        let (Some(offset), Some(length)) = (offset, length) else {
            return Ok(None);
        };
        let end = offset.saturating_add(length);
        if length == 0 || length > OFFSET_INDEX_CAP || end > self.size {
            return Ok(None);
        }
        let decoded = if offset >= tail_start {
            let from = usize::try_from(offset - tail_start).ok();
            let to = usize::try_from(end - tail_start).ok();
            match from.zip(to).and_then(|(from, to)| tail.get(from..to)) {
                Some(bytes) => contain(|| decode_offset_index(bytes).ok())?,
                None => None,
            }
        } else {
            let bytes = self.get(offset, end).await?;
            contain(|| decode_offset_index(&bytes).ok())?
        };
        Ok(decoded.and_then(|index| index.page_locations().first().cloned()))
    }
}

/// `window`'s bytes. Spelled out because `ChunkReader` brings its own
/// `len` (a `u64`) into scope, which would shadow the slice's.
fn as_slice<B: Window>(window: &B) -> &[u8] {
    window
}

/// Runs a synchronous `parquet` step, containing any panic: the parser is
/// third-party code reading attacker-controlled bytes, and a panic in it
/// must cost one file, never the scan. Every value the closure touches is
/// discarded with the file on a panic, so no broken state is observed
/// afterwards (hence `AssertUnwindSafe`).
fn contain<T>(step: impl FnOnce() -> T) -> Result<T, NotScannedReason> {
    std::panic::catch_unwind(AssertUnwindSafe(step)).map_err(|_| NotScannedReason::Unreadable)
}

/// Who decompresses pages of `compression`, or `None` if nobody can do it
/// safely. `parquet`'s Snappy, LZ4 (with the frame fallback off), `LZ4_RAW`
/// and ZSTD decoders write into a buffer of the declared size; its GZIP and
/// BROTLI decoders read to the end of the stream, however large, so those
/// are decompressed here. LZO is not built in.
fn codec(compression: Compression) -> Option<Codec> {
    match compression {
        Compression::UNCOMPRESSED
        | Compression::SNAPPY
        | Compression::LZ4
        | Compression::LZ4_RAW
        | Compression::ZSTD(_) => Some(Codec::Parquet),
        Compression::GZIP(_) => Some(Codec::Gzip),
        Compression::BROTLI(_) => Some(Codec::Brotli),
        Compression::LZO => None,
    }
}

/// `body`, one page's stored bytes, decompressed with `codec`: the v2
/// level bytes copied as they are, then the values decompressed, reading
/// at most the declared size plus one byte. `None` if the output is not
/// exactly the declared size (an extra byte means the stream would have
/// gone on) or the stream is invalid.
fn inflate(codec: Codec, body: &[u8], page: &header::PageHeader) -> Option<Vec<u8>> {
    let declared = usize::try_from(page.uncompressed).ok()?;
    if !page.values_compressed {
        return (body.len() == declared).then(|| body.to_vec());
    }
    let levels = usize::try_from(page.levels).ok()?;
    let expected = declared.checked_sub(levels)?;
    let (level_bytes, values) = (body.get(..levels)?, body.get(levels..)?);
    let mut out = Vec::with_capacity(declared);
    out.extend_from_slice(level_bytes);
    // As in `parquet`: a page of nothing but nulls may have no values to
    // decompress at all.
    if expected > 0 {
        let limit = u64::try_from(expected).ok()?.checked_add(1)?;
        let read = match codec {
            Codec::Gzip => flate2::read::MultiGzDecoder::new(values)
                .take(limit)
                .read_to_end(&mut out),
            Codec::Brotli if brotli_window_is_standard(values) => {
                brotli::Decompressor::new(values, BROTLI_BUFFER)
                    .take(limit)
                    .read_to_end(&mut out)
            }
            Codec::Brotli | Codec::Parquet => return None,
        };
        read.ok()?;
    }
    (out.len() == declared).then_some(out)
}

/// The Brotli decoder's read buffer, as `parquet` sizes it.
const BROTLI_BUFFER: usize = 4096;

/// Whether a Brotli stream's window is a standard one (at most 2^24
/// bytes, RFC 7932 section 9.1), not "large window" Brotli. The decoder
/// accepts large windows of up to 2^30 bytes and allocates the whole
/// window up front, so such streams are refused before it sees them.
fn brotli_window_is_standard(stream: &[u8]) -> bool {
    // WBITS is read least significant bit first: 1 bit, then 3, then 3.
    // Large-window streams start 1, 000, 001.
    stream.first().is_none_or(|&first| first & 0x7f != 0x11)
}

/// The first data page (and dictionary page) of `checked`, decompressed
/// with `codec` and re-encoded as an uncompressed chunk: the buffer, and
/// where its data page starts. Every header was already checked by
/// [`plan_pages`]; this reads them again from the same bytes.
fn decompress_pages<B: Window>(checked: &Checked<B>, codec: Codec) -> Option<(Vec<u8>, u64)> {
    let base = usize::try_from(checked.chunk_start.checked_sub(checked.buffer_start)?).ok()?;
    let page_offset = usize::try_from(checked.page_offset).ok()?;
    let end = base
        .checked_add(page_offset)?
        .checked_add(usize::try_from(checked.page_len).ok()?)?;
    let pages = as_slice(&checked.data).get(base..end)?;
    let mut out = Vec::new();
    let convert = |out: &mut Vec<u8>, bytes: &[u8]| {
        let header::Read::Header(page) = header::read(bytes) else {
            return None;
        };
        let body_end = page
            .len
            .checked_add(usize::try_from(page.compressed).ok()?)?;
        (body_end == bytes.len()).then_some(())?;
        let plain = inflate(codec, bytes.get(page.len..)?, &page)?;
        out.extend(header::with_body_len(bytes.get(..page.len)?, plain.len())?);
        out.extend(plain);
        Some(())
    };
    let (dictionary, data) = (pages.get(..page_offset)?, pages.get(page_offset..)?);
    if !dictionary.is_empty() {
        convert(&mut out, dictionary)?;
    }
    let dictionary_len = u64::try_from(out.len()).ok()?;
    convert(&mut out, data)?;
    Some((out, dictionary_len))
}

/// The smallest a PLAIN-encoded dictionary value of this column can be.
fn min_value_bytes(descr: &ColumnDescriptor) -> u64 {
    match descr.physical_type() {
        Physical::INT64 | Physical::DOUBLE => 8,
        Physical::FIXED_LEN_BYTE_ARRAY => u64::try_from(descr.type_length()).unwrap_or(1).max(1),
        // BYTE_ARRAY values carry a 4-byte length; INT32 and FLOAT are 4.
        _ => 4,
    }
}

/// The page location `parquet` reads one data page from: its header and
/// body, `len` bytes from `offset`.
fn page_location(offset: u64, len: u64) -> PageLocation {
    PageLocation {
        offset: i64::try_from(offset).unwrap_or(i64::MAX),
        compressed_page_size: i32::try_from(len).unwrap_or(i32::MAX),
        first_row_index: 0,
    }
}

/// What the page headers at the start of a column chunk allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plan {
    /// The first data page is `len` bytes (header and body) at `offset`
    /// from the chunk's start, wholly in hand, and every page up to it
    /// passed the checks.
    Ready { offset: u64, len: u64 },
    /// More bytes are needed: the chunk's first `n`.
    NeedMore(u64),
    /// A page declares more than [`PAGE_CAP`], or a dictionary more than
    /// [`MAX_DICTIONARY_VALUES`].
    TooLarge,
    /// Not a valid page sequence.
    Invalid,
}

/// Walks the page headers at the start of a column chunk (`bytes`, the
/// chunk's first bytes; `chunk_len`, its full length) up to the first data
/// page, checking every declared size before anything is allocated for
/// it: an optional dictionary page, then a data page.
fn plan_pages(bytes: &[u8], chunk_len: u64, min_value_bytes: u64) -> Plan {
    let held = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let mut pos: u64 = 0;
    let mut first = true;
    loop {
        let rest = usize::try_from(pos).ok().and_then(|pos| bytes.get(pos..));
        let read = rest.map_or(header::Read::Incomplete, header::read);
        let page = match read {
            header::Read::Header(page) => page,
            header::Read::Invalid => return Plan::Invalid,
            header::Read::Incomplete => {
                let have = held.saturating_sub(pos);
                if have >= MAX_HEADER || held >= chunk_len {
                    return Plan::Invalid;
                }
                return Plan::NeedMore(pos + (have * 2).max(WINDOW_START));
            }
        };
        if page.uncompressed > PAGE_CAP || page.compressed > PAGE_CAP {
            return Plan::TooLarge;
        }
        let header_len = u64::try_from(page.len).unwrap_or(u64::MAX);
        let end = pos + header_len + page.compressed;
        if end > chunk_len {
            return Plan::Invalid;
        }
        match page.kind {
            header::DICTIONARY_PAGE if first => {
                if page.dictionary_values > MAX_DICTIONARY_VALUES {
                    return Plan::TooLarge;
                }
                if page.dictionary_values.saturating_mul(min_value_bytes) > page.uncompressed {
                    return Plan::Invalid;
                }
                pos = end;
                first = false;
            }
            header::DATA_PAGE | header::DATA_PAGE_V2 => {
                return if end > held {
                    Plan::NeedMore(end)
                } else {
                    Plan::Ready {
                        offset: pos,
                        len: end - pos,
                    }
                };
            }
            _ => return Plan::Invalid,
        }
    }
}

/// Decodes one checked data page with [`decode`], decompressing it first
/// if `codec` says `LakeScan` must, all inside [`contain`]: a decoding
/// error skips the column; a panic fails the file.
fn decode_contained<B: Window>(
    checked: Checked<B>,
    chunk: &ColumnChunkMetaData,
    codec: Codec,
    rows: usize,
    descr: &ColumnDescPtr,
) -> Result<ColumnRead, NotScannedReason> {
    let decoded = contain(|| {
        if codec == Codec::Parquet {
            let meta = rebase(chunk, checked.buffer_start, checked.chunk_len)?;
            let at = checked.chunk_start.checked_sub(checked.buffer_start)? + checked.page_offset;
            let location = page_location(at, checked.page_len);
            return decode(checked.data, &meta, rows, location, descr).ok();
        }
        let (plain, data_at) = decompress_pages(&checked, codec)?;
        let total = u64::try_from(plain.len()).ok()?;
        let meta = uncompressed(chunk, data_at, total)?;
        let location = page_location(data_at, total - data_at);
        decode(B::from(plain), &meta, rows, location, descr).ok()
    })?;
    Ok(decoded.map_or(ColumnRead::Unreadable, ColumnRead::Values))
}

/// Row groups to sample, in order: the first, then the middle, then the
/// last, without repeats.
pub(super) fn row_group_order(count: usize) -> Vec<usize> {
    let mut order = Vec::with_capacity(MAX_ROW_GROUPS);
    for candidate in [0, count / 2, count.saturating_sub(1)] {
        if candidate < count && !order.contains(&candidate) {
            order.push(candidate);
        }
    }
    order
}

/// What detection makes of a leaf column's type, or `None` if it is not a
/// candidate at all (booleans, floats, decimals, times, intervals).
pub(super) fn kind_of(descr: &ColumnDescriptor) -> Option<Kind> {
    let logical = descr.logical_type_ref();
    let converted = descr.converted_type();
    let numeric_or_time = matches!(
        logical,
        Some(
            LogicalType::Decimal { .. }
                | LogicalType::Time { .. }
                | LogicalType::Float16
                | LogicalType::Unknown
        )
    ) || matches!(
        converted,
        ConvertedType::DECIMAL
            | ConvertedType::TIME_MILLIS
            | ConvertedType::TIME_MICROS
            | ConvertedType::INTERVAL
    );
    let temporal = matches!(
        logical,
        Some(LogicalType::Date | LogicalType::Timestamp { .. })
    ) || matches!(
        converted,
        ConvertedType::DATE | ConvertedType::TIMESTAMP_MILLIS | ConvertedType::TIMESTAMP_MICROS
    );
    match descr.physical_type() {
        Physical::BYTE_ARRAY | Physical::FIXED_LEN_BYTE_ARRAY if !numeric_or_time => {
            Some(Kind::Text)
        }
        Physical::INT32 | Physical::INT64 if temporal => Some(Kind::Temporal),
        Physical::INT32 | Physical::INT64 if !numeric_or_time => Some(Kind::Integer),
        Physical::INT96 => Some(Kind::Temporal),
        _ => None,
    }
}

/// Where a column chunk starts and how long it is, checked: the dictionary
/// page if there is a plausible one, else the first data page. Never
/// calls `ColumnChunkMetaData::byte_range`, which asserts on negative
/// offsets.
fn chunk_range(chunk: &ColumnChunkMetaData) -> Option<(u64, u64)> {
    let start = chunk_start(chunk)?;
    let len = u64::try_from(chunk.compressed_size()).ok()?;
    Some((start, len))
}

fn chunk_start(chunk: &ColumnChunkMetaData) -> Option<u64> {
    let data = chunk.data_page_offset();
    let start = dictionary_offset(chunk).unwrap_or(data);
    u64::try_from(start).ok()
}

/// The dictionary page offset, when it is set and lies before the first
/// data page; some writers set it to 0 when there is no dictionary.
fn dictionary_offset(chunk: &ColumnChunkMetaData) -> Option<i64> {
    chunk
        .dictionary_page_offset()
        .filter(|&offset| offset > 0 && offset < chunk.data_page_offset())
}

/// `chunk`'s metadata moved onto a buffer that starts at file offset
/// `start` and holds `held` bytes of the chunk.
fn rebase(chunk: &ColumnChunkMetaData, start: u64, held: u64) -> Option<ColumnChunkMetaData> {
    let shift = |offset: i64| {
        u64::try_from(offset)
            .ok()
            .and_then(|offset| offset.checked_sub(start))
            .and_then(|offset| i64::try_from(offset).ok())
    };
    let data = shift(chunk.data_page_offset())?;
    let dictionary = match dictionary_offset(chunk) {
        Some(offset) => Some(shift(offset)?),
        None => None,
    };
    chunk
        .clone()
        .into_builder()
        .set_data_page_offset(data)
        .set_dictionary_page_offset(dictionary)
        .set_total_compressed_size(i64::try_from(held).ok()?)
        .build()
        .ok()
}

/// `chunk`'s metadata for a buffer of `total` bytes holding its pages
/// decompressed by [`decompress_pages`]: uncompressed, with the data page
/// at `data_at` and the dictionary page, if any, at 0.
fn uncompressed(
    chunk: &ColumnChunkMetaData,
    data_at: u64,
    total: u64,
) -> Option<ColumnChunkMetaData> {
    chunk
        .clone()
        .into_builder()
        .set_compression(Compression::UNCOMPRESSED)
        .set_data_page_offset(i64::try_from(data_at).ok()?)
        .set_dictionary_page_offset((data_at > 0).then_some(0))
        .set_total_compressed_size(i64::try_from(total).ok()?)
        .set_total_uncompressed_size(i64::try_from(total).ok()?)
        .build()
        .ok()
}

/// Decodes the first data page of `meta`'s chunk from `data`, keeping at
/// most [`MAX_VALUES_PER_ROW_GROUP`] cleaned values. Integers are rendered
/// as decimal digits; strings and binary as UTF-8 (lossily).
fn decode<B: Window>(
    data: B,
    meta: &ColumnChunkMetaData,
    rows: usize,
    location: PageLocation,
    descr: &ColumnDescPtr,
) -> ParquetResult<Vec<String>> {
    #[cfg(test)]
    fault::maybe_panic();
    // No LZ4 frame fallback: it decompresses without a size limit.
    let properties = ReaderProperties::builder()
        .set_backward_compatible_lz4(false)
        .build();
    let pages = SerializedPageReader::new_with_properties(
        Arc::new(data),
        meta,
        rows,
        Some(vec![location]),
        Arc::new(properties),
    )?;
    let pages = FirstPageOnly {
        inner: pages,
        done: false,
    };
    let mut out = Vec::new();
    let keep = |out: &mut Vec<String>, raw: &str| {
        if let Some(value) = clean(raw) {
            out.push(value.to_owned());
        }
    };
    let mut definitions: Vec<i16> = Vec::new();
    match get_column_reader(Arc::clone(descr), Box::new(pages)) {
        ColumnReader::ByteArrayColumnReader(mut reader) => loop {
            let mut batch: Vec<ByteArray> = Vec::new();
            definitions.clear();
            let (records, _, _) =
                reader.read_records(BATCH, Some(&mut definitions), None, &mut batch)?;
            for value in &batch {
                keep(&mut out, &String::from_utf8_lossy(value.data()));
            }
            if records == 0 || full(&out) {
                break;
            }
        },
        ColumnReader::FixedLenByteArrayColumnReader(mut reader) => loop {
            let mut batch: Vec<FixedLenByteArray> = Vec::new();
            definitions.clear();
            let (records, _, _) =
                reader.read_records(BATCH, Some(&mut definitions), None, &mut batch)?;
            for value in &batch {
                keep(&mut out, &String::from_utf8_lossy(value.data()));
            }
            if records == 0 || full(&out) {
                break;
            }
        },
        ColumnReader::Int32ColumnReader(mut reader) => loop {
            let mut batch: Vec<i32> = Vec::new();
            definitions.clear();
            let (records, _, _) =
                reader.read_records(BATCH, Some(&mut definitions), None, &mut batch)?;
            for value in &batch {
                keep(&mut out, &value.to_string());
            }
            if records == 0 || full(&out) {
                break;
            }
        },
        ColumnReader::Int64ColumnReader(mut reader) => loop {
            let mut batch: Vec<i64> = Vec::new();
            definitions.clear();
            let (records, _, _) =
                reader.read_records(BATCH, Some(&mut definitions), None, &mut batch)?;
            for value in &batch {
                keep(&mut out, &value.to_string());
            }
            if records == 0 || full(&out) {
                break;
            }
        },
        _ => {}
    }
    out.truncate(MAX_VALUES_PER_ROW_GROUP);
    Ok(out)
}

fn full(values: &[String]) -> bool {
    values.len() >= MAX_VALUES_PER_ROW_GROUP
}

/// Yields only the first data page of a column chunk (and the dictionary
/// page before it), then reports the chunk exhausted, so decoding never
/// reaches past the bytes that were fetched.
struct FirstPageOnly<P: PageReader> {
    inner: P,
    done: bool,
}

impl<P: PageReader> Iterator for FirstPageOnly<P> {
    type Item = ParquetResult<Page>;

    fn next(&mut self) -> Option<Self::Item> {
        self.get_next_page().transpose()
    }
}

impl<P: PageReader> PageReader for FirstPageOnly<P> {
    fn get_next_page(&mut self) -> ParquetResult<Option<Page>> {
        if self.done {
            return Ok(None);
        }
        let page = self.inner.get_next_page()?;
        if matches!(page, Some(Page::DataPage { .. } | Page::DataPageV2 { .. })) {
            self.done = true;
        }
        Ok(page)
    }

    fn peek_next_page(&mut self) -> ParquetResult<Option<PageMetadata>> {
        if self.done {
            Ok(None)
        } else {
            self.inner.peek_next_page()
        }
    }

    fn skip_next_page(&mut self) -> ParquetResult<()> {
        self.done = true;
        Ok(())
    }
}

/// Test-only fault injection: makes the next decode panic, to prove a
/// panic inside `parquet` is contained. Not compiled into the binary.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;

    thread_local! {
        static ARMED: Cell<bool> = const { Cell::new(false) };
        static DECODES: Cell<u64> = const { Cell::new(0) };
    }

    /// How many decodes this thread has started.
    pub(crate) fn decodes() -> u64 {
        DECODES.with(Cell::get)
    }

    /// Makes every decode on this thread panic until [`disarm`].
    pub(crate) fn arm() {
        ARMED.with(|armed| armed.set(true));
    }

    pub(crate) fn disarm() {
        ARMED.with(|armed| armed.set(false));
    }

    pub(super) fn maybe_panic() {
        DECODES.with(|count| count.set(count.get() + 1));
        if ARMED.with(Cell::get) {
            std::panic::resume_unwind(Box::new("injected decode fault"));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::header::PageHeader;
    use super::{Codec, brotli_window_is_standard, inflate, row_group_order};

    fn page(uncompressed: usize, levels: u64, values_compressed: bool) -> PageHeader {
        PageHeader {
            kind: super::header::DATA_PAGE_V2,
            uncompressed: u64::try_from(uncompressed).unwrap_or(u64::MAX),
            compressed: 0,
            dictionary_values: 0,
            levels,
            values_compressed,
            len: 0,
        }
    }

    fn gzip(data: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data)?;
        encoder.finish()
    }

    fn brotli(data: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            writer.write_all(data)?;
        }
        Ok(out)
    }

    #[test]
    fn a_decompression_bomb_stops_one_byte_past_the_declared_size() -> std::io::Result<()> {
        // 16 MiB of zeros compress to kilobytes; declared as 1 KiB,
        // decompression stops at 1 KiB + 1 byte and the page is refused.
        let zeros = vec![0_u8; 16 * 1024 * 1024];
        for (codec, body) in [
            (Codec::Gzip, gzip(&zeros)?),
            (Codec::Brotli, brotli(&zeros)?),
        ] {
            assert!(body.len() < 1024 * 1024, "{codec:?}");
            let started = std::time::Instant::now();
            assert_eq!(inflate(codec, &body, &page(1024, 0, true)), None);
            assert!(started.elapsed().as_secs() < 5, "{codec:?}");
            let exact = inflate(codec, &body, &page(zeros.len(), 0, true));
            assert_eq!(exact.map(|out| out.len()), Some(zeros.len()), "{codec:?}");
        }
        Ok(())
    }

    #[test]
    fn v2_levels_are_copied_and_only_the_values_decompressed() -> std::io::Result<()> {
        let values = b"person.1@example.com".repeat(10);
        let mut body = vec![1, 2, 3];
        body.extend(gzip(&values)?);
        let out = inflate(Codec::Gzip, &body, &page(3 + values.len(), 3, true));
        let mut expected = vec![1, 2, 3];
        expected.extend(&values);
        assert_eq!(out, Some(expected));
        // Values stored uncompressed are passed through, if the size fits.
        let plain = inflate(Codec::Gzip, &values, &page(values.len(), 0, false));
        assert_eq!(plain.as_deref(), Some(&values[..]));
        assert_eq!(inflate(Codec::Gzip, &values, &page(1, 0, false)), None);
        // Levels longer than the page are refused.
        assert_eq!(inflate(Codec::Gzip, &body, &page(2, 3, true)), None);
        Ok(())
    }

    #[test]
    fn large_window_brotli_is_refused_before_decoding() -> std::io::Result<()> {
        // WBITS bits 1, 000, 001: "large window" Brotli, which the decoder
        // would accept with a window of up to 1 GiB, allocated up front.
        for first in [0x11, 0x91] {
            assert!(!brotli_window_is_standard(&[first, 0xff]));
            assert_eq!(
                inflate(Codec::Brotli, &[first, 0xff, 0xff], &page(10, 0, true)),
                None
            );
        }
        for lgwin in [10, 16, 22, 24] {
            let mut out = Vec::new();
            {
                let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 5, lgwin);
                writer.write_all(b"standard window")?;
            }
            assert!(brotli_window_is_standard(&out), "lgwin {lgwin}");
            assert!(inflate(Codec::Brotli, &out, &page(15, 0, true)).is_some());
        }
        Ok(())
    }

    #[test]
    fn row_groups_are_sampled_first_middle_last_without_repeats() {
        assert_eq!(row_group_order(0), Vec::<usize>::new());
        assert_eq!(row_group_order(1), [0]);
        assert_eq!(row_group_order(2), [0, 1]);
        assert_eq!(row_group_order(3), [0, 1, 2]);
        assert_eq!(row_group_order(10), [0, 5, 9]);
    }
}
