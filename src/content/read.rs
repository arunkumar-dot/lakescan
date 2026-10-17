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
//! **Repeated columns.** The leaves of lists and maps (`tags`, a list of
//! strings; `telecom.list.element.value`, a field of a list of structs)
//! are read like any other column, with their repetition levels, and named
//! for their hint by the last path segment that is not a list or map
//! wrapper (see [`hint_name`]). For one, a level and a value slot are held
//! per declared value, not per row, so its first data page may declare at
//! most [`MAX_REPEATED_VALUES`] values; a larger one is page-too-large.
//!
//! **Columns not examined.** A string or integer column that was skipped
//! (page too large, unreadable, unsupported codec), and a column of a type
//! detection does not read (a float, a decimal, a time; not a boolean)
//! whose name hints personal data, are recorded as *not examined*, so a
//! table whose personal-data columns could not be checked never reads as
//! clean.
//!
//! **Files with nothing examined.** A file whose value-bearing candidate
//! columns (strings and integers) were all skipped is `no-column-examined`:
//! not scanned, so a lake of such files cannot pass silently.
//!
//! **Escalation.** A column whose cleaned sample is too small or ambiguous
//! after row group 0 (see `classify::Evidence::needs_more`) is sampled
//! again in the middle row group, then the last: never more than
//! [`MAX_ROW_GROUPS`] per column.

use std::collections::{HashMap, VecDeque};
use std::io::Read as _;
use std::ops::Deref;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use aws_sdk_s3::primitives::AggregatedBytes;
use parquet::basic::{Compression, ConvertedType, LogicalType, Type as Physical};
use parquet::column::page::{Page, PageMetadata, PageReader};
use parquet::column::reader::{ColumnReader, ColumnReaderImpl, get_column_reader};
use parquet::data_type::{ByteArray, DataType, FixedLenByteArray};
use parquet::errors::Result as ParquetResult;
use parquet::file::metadata::{
    ColumnChunkMetaData, ParquetMetaData, ParquetMetaDataReader, RowGroupMetaData,
};
use parquet::file::page_index::index_reader::decode_offset_index;
use parquet::file::page_index::offset_index::PageLocation;
use parquet::file::properties::ReaderProperties;
use parquet::file::reader::ChunkReader;
use parquet::file::serialized_reader::SerializedPageReader;
use parquet::schema::types::{ColumnDescPtr, ColumnDescriptor, Type as SchemaType};

use super::budget::{FileBudget, Permit, Refused};
use super::classify::{Evidence, Kind, Named, classify};
use super::clean::{clean, drop_dominant};
use super::fetch::{FetchError, ObjectReader};
use super::header;
use super::names::{self, Hint};
use super::{ColumnFinding, FileStats};
use crate::model::{
    ColumnDetail, NotExamined, NotExaminedReason, NotScannedReason, offer_not_examined,
};

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
/// The largest read covering every sampled offset index at once; above
/// it, pages are found by reading headers instead.
const INDEX_REGION_CAP: u64 = 8 * 1024 * 1024;
/// The most first-page locations kept per file (3 row groups × 4,096
/// columns, ~0.8 MiB); columns past it are found by reading headers.
const MAX_LOCATIONS: usize = 3 * 4096;
/// The most leaf columns a file may have; a wider one is
/// `too-many-columns`.
pub const MAX_COLUMNS: usize = 16_384;
/// The bytes one column's scan record takes, counted against the budget
/// for every leaf column (see [`Candidate`]).
const CANDIDATE_BYTES: u64 = size_of::<Candidate>() as u64;
/// Values read from a page per call.
const BATCH: usize = 1024;
/// The largest read that coalescing builds from several requests.
pub const COALESCE_MAX: u64 = 8 * 1024 * 1024;
/// The default `--coalesce-gap`: requests this close are read together.
pub const DEFAULT_COALESCE_GAP: u64 = 1024 * 1024;
/// Ranges of one file fetched at once.
const RANGE_CONCURRENCY: usize = 4;
/// The most bytes one file has in flight between fetches (a single range
/// may be as large as [`WINDOW_LIMIT`], which this equals).
const PREFETCH_CAP: u64 = WINDOW_LIMIT;
/// Columns of a partially read file sampled together: their samples are
/// held until the batch is classified.
const COLUMN_BATCH: usize = 8;
/// The most bytes one dictionary slot takes in `parquet`.
const DICTIONARY_SLOT_BYTES: u64 = 32;
/// The most values the first data page of a repeated column may declare.
/// A flat column's levels and values are decoded [`BATCH`] at a time, but a
/// repeated column's whole page of levels is decoded at once, so this
/// bounds the levels and value slots one decode holds.
pub const MAX_REPEATED_VALUES: u64 = 128 * 1024;
/// What one declared value of a repeated column's page holds while
/// decoding: a value slot (at most a `ByteArray`) and a definition and a
/// repetition level.
const REPEATED_SLOT_BYTES: u64 = size_of::<ByteArray>() as u64 + 2 * size_of::<i16>() as u64;
/// The most a decode can allocate under the caps: two pages at the page
/// cap, a dictionary's slots, and a repeated page's levels and slots.
const DECODE_MAX: u64 = 2 * PAGE_CAP
    + MAX_DICTIONARY_VALUES * DICTIONARY_SLOT_BYTES
    + MAX_REPEATED_VALUES * REPEATED_SLOT_BYTES;
/// The most one column's sample from one row group takes: up to
/// `MAX_VALUES_PER_ROW_GROUP + BATCH` (3,024) values before the cut, each
/// at most `clean::MAX_VALUE_BYTES` (257) plus a `String` (24 bytes).
const SAMPLE_BYTES: u64 = 3024 * 281;

/// The most bytes one file's scan can hold at once under the caps, for a
/// whole-file maximum of `whole_file_max` (see `budget`): the larger of a
/// whole read (the file, its metadata, one decode, one column's samples)
/// and a partial one (the metadata, plus the larger of opening, with the
/// tail, footer and offset-index reads, and sampling, with the prefetched
/// ranges, one decode and a column batch's samples), plus a scan record
/// for each of up to [`MAX_COLUMNS`] columns.
#[must_use]
pub const fn file_need(whole_file_max: u64) -> u64 {
    let rows = MAX_ROW_GROUPS as u64;
    let metadata = if whole_file_max < FOOTER_CAP {
        whole_file_max
    } else {
        FOOTER_CAP
    };
    let whole = whole_file_max + metadata + DECODE_MAX + rows * SAMPLE_BYTES;
    let open = TAIL_BYTES + FOOTER_CAP + INDEX_REGION_CAP;
    let sampling = PREFETCH_CAP + DECODE_MAX + COLUMN_BATCH as u64 * rows * SAMPLE_BYTES;
    let partial = FOOTER_CAP + if open > sampling { open } else { sampling };
    let records = MAX_COLUMNS as u64 * CANDIDATE_BYTES;
    records + if whole > partial { whole } else { partial }
}

const MAGIC: &[u8] = b"PAR1";
const ENCRYPTED_MAGIC: &[u8] = b"PARE";

/// What a fetched byte range must offer: `parquet`'s in-memory
/// [`ChunkReader`], plus slicing, building from a `Vec`, and crossing
/// threads (fetches and decodes run as tasks). The one implementation is
/// the buffer type `AggregatedBytes::into_bytes` returns; it is never named
/// here, only inferred (see [`session`]).
pub(super) trait Window:
    ChunkReader + Deref<Target = [u8]> + Clone + From<Vec<u8>> + Send + Sync + 'static
{
}

impl<T> Window for T where
    T: ChunkReader + Deref<Target = [u8]> + Clone + From<Vec<u8>> + Send + Sync + 'static
{
}

/// Bytes in memory, with the permits that cover them.
pub(super) struct Held<B> {
    data: B,
    _permit: Permit,
}

/// How a file was opened.
pub(super) enum Opened<B> {
    /// Read whole; every column chunk is in memory.
    Whole(Held<B>),
    /// Read partially: the first data page an offset index located, per
    /// `(row group, column)`.
    Partial {
        first_pages: HashMap<(usize, usize), PageLocation>,
    },
}

/// What sampling one column in one row group produced.
enum ColumnRead {
    /// Cleaned values, at most [`MAX_VALUES_PER_ROW_GROUP`], and the
    /// permits that cover them.
    Values(Vec<String>, Permit),
    /// The dictionary or first data page is over [`PAGE_CAP`].
    PageTooLarge,
    /// The pages could not be decoded.
    Unreadable,
    /// The chunk's codec cannot be decoded safely.
    UnsupportedCodec,
}

/// Why a column was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Skip {
    PageTooLarge,
    Unreadable,
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
    /// The smallest columns not examined (see [`FileStats::not_examined`]).
    pub(super) not_examined: Vec<NotExamined>,
    /// Whether the file had string or integer columns to read, and none of
    /// them could be read.
    pub(super) nothing_examined: bool,
}

/// One candidate column, sampled row group by row group.
struct Candidate {
    index: usize,
    descr: ColumnDescPtr,
    kind: Kind,
    /// What its name hints, and what else it says (see [`hint_name`]).
    hint: Option<Hint>,
    named: Named,
    values: Vec<String>,
    permits: Vec<Permit>,
    evidence: Evidence,
    skipped: Option<Skip>,
    done: bool,
}

impl Candidate {
    fn new(index: usize, descr: ColumnDescPtr, kind: Kind, name: &str) -> Self {
        Self {
            index,
            descr,
            kind,
            hint: names::hint(name),
            named: Named {
                person: names::about_person(name),
                phone: names::phone_named(name),
            },
            values: Vec::new(),
            permits: Vec::new(),
            evidence: Evidence::default(),
            skipped: None,
            done: false,
        }
    }

    /// Takes one row group's read. Done once a skip happens or the sample
    /// no longer needs more (see `classify::Evidence::needs_more`).
    fn apply(&mut self, read: ColumnRead) {
        let skip = match read {
            ColumnRead::Values(sample, permit) => {
                self.values.extend(sample);
                self.permits.push(permit);
                let mut cleaned = self.values.clone();
                drop_dominant(&mut cleaned);
                self.evidence = Evidence::of(&cleaned);
                self.done = !self.evidence.needs_more();
                return;
            }
            ColumnRead::PageTooLarge => Skip::PageTooLarge,
            ColumnRead::Unreadable => Skip::Unreadable,
            ColumnRead::UnsupportedCodec => Skip::UnsupportedCodec,
        };
        self.skipped = Some(skip);
        self.done = true;
    }
}

/// One planned read of a column chunk's first pages in one row group: its
/// first `end - start` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Request {
    /// The column's position among the round's columns.
    pub(super) slot: usize,
    /// The chunk's first byte (a file offset) and full length.
    pub(super) start: u64,
    pub(super) chunk_len: u64,
    /// Where this read ends.
    pub(super) end: u64,
}

/// Requests coalesced into one read of `start..end`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Merged {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) members: Vec<Request>,
}

/// Sorts `requests` and merges neighbours whose gap is at most `gap`, as
/// long as a merged read stays within [`COALESCE_MAX`]. A `gap` of 0
/// merges nothing; a single request over the cap is read alone.
pub(super) fn coalesce(mut requests: Vec<Request>, gap: u64) -> Vec<Merged> {
    requests.sort_by_key(|request| (request.start, request.end, request.slot));
    let mut out: Vec<Merged> = Vec::new();
    for request in requests {
        if let Some(last) = out.last_mut() {
            let end = last.end.max(request.end);
            if gap > 0
                && request.start <= last.end.saturating_add(gap)
                && end - last.start <= COALESCE_MAX
            {
                last.end = end;
                last.members.push(request);
                continue;
            }
        }
        out.push(Merged {
            start: request.start,
            end: request.end,
            members: vec![request],
        });
    }
    out
}

/// One row group being sampled: its metadata, row count and columns.
struct Round<'a> {
    group: &'a RowGroupMetaData,
    rows: usize,
    columns: &'a [(usize, ColumnDescPtr)],
}

/// What processing one request gave: a column's read, or a longer request
/// for the next phase.
enum Step {
    Done(ColumnRead),
    More(Request),
}

/// A spawned task, aborted if dropped before it finishes, so a failed file
/// leaves nothing running (and no permits held) behind it.
struct Task<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// One ranged read, as a task runs it: the bytes returned, and the buffer.
/// A short read (the object changed since it was listed) is unreadable; a
/// read that failed after the SDK's retries is `fetch-failed`.
async fn fetch_range<R: ObjectReader, B: Window>(
    reader: R,
    key: Arc<str>,
    start: u64,
    end: u64,
    convert: fn(AggregatedBytes) -> B,
) -> (u64, Result<B, NotScannedReason>) {
    match reader.read_range(&key, start, end).await {
        Ok(data) => {
            let data = convert(data);
            let len = u64::try_from(as_slice(&data).len()).unwrap_or(u64::MAX);
            if Some(len) == end.checked_sub(start) {
                (len, Ok(data))
            } else {
                (len, Err(NotScannedReason::Unreadable))
            }
        }
        Err(FetchError::AccessDenied) => (0, Err(NotScannedReason::AccessDenied)),
        Err(FetchError::Failed) => (0, Err(NotScannedReason::FetchFailed)),
    }
}

/// Why a file is not scanned when the budget refuses it permits.
fn not_scanned(refused: Refused) -> NotScannedReason {
    match refused {
        Refused::OverNeed => NotScannedReason::Unreadable,
        Refused::TimedOut => NotScannedReason::BudgetTimeout,
    }
}

/// One file's reads: the reader, the object, its budget account, and the
/// running counts.
pub(super) struct Session<R, B> {
    reader: R,
    key: Arc<str>,
    size: u64,
    pub(super) stats: FileStats,
    convert: fn(AggregatedBytes) -> B,
    budget: FileBudget,
    coalesce_gap: u64,
}

/// A session reading `key` (`size` bytes) through `reader`, holding
/// buffers only under permits from `budget`. The buffer type is whatever
/// `AggregatedBytes::into_bytes` returns, inferred rather than named.
pub(super) fn session<R: ObjectReader>(
    reader: R,
    key: &str,
    size: u64,
    budget: FileBudget,
    coalesce_gap: u64,
) -> Session<R, impl Window> {
    Session {
        reader,
        key: Arc::from(key),
        size,
        stats: FileStats::default(),
        convert: AggregatedBytes::into_bytes,
        budget,
        coalesce_gap,
    }
}

impl<R: ObjectReader, B: Window> Session<R, B> {
    fn count(&mut self, returned: u64) {
        self.stats.get_requests = self.stats.get_requests.saturating_add(1);
        self.stats.bytes_read = self.stats.bytes_read.saturating_add(returned);
    }

    /// Permits for `bytes`. Refused past the largest single-file need,
    /// which the caps rule out (the file is then unreadable), or after
    /// waiting too long (`budget-timeout`).
    async fn permit(&mut self, bytes: u64) -> Result<Permit, NotScannedReason> {
        self.budget.acquire(bytes).await.map_err(not_scanned)
    }

    /// Reads `start..end` under permits for its length, counting the
    /// request and the bytes returned.
    async fn get(&mut self, start: u64, end: u64) -> Result<Held<B>, NotScannedReason> {
        let permit = self.permit(end.saturating_sub(start)).await?;
        let (returned, data) = fetch_range(
            self.reader.clone(),
            Arc::clone(&self.key),
            start,
            end,
            self.convert,
        )
        .await;
        self.count(returned);
        Ok(Held {
            data: data?,
            _permit: permit,
        })
    }

    /// Opens the file: reads it whole or reads its tail, checks the magic,
    /// and decodes the footer (on the blocking pool). Returns the metadata
    /// with the permits that cover it, held for the file's lifetime.
    pub(super) async fn open(
        &mut self,
        whole_file_max: u64,
    ) -> Result<(ParquetMetaData, Permit, Opened<B>), NotScannedReason> {
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
        let bytes = as_slice(&buffer.data);

        let tail_magic = bytes.len().checked_sub(4).and_then(|at| bytes.get(at..));
        if tail_magic == Some(ENCRYPTED_MAGIC) {
            return Err(NotScannedReason::Encrypted);
        }
        if self.size < 12 || tail_magic != Some(MAGIC) {
            let head = if start == 0 {
                bytes.get(..4).map(<[u8]>::to_vec)
            } else {
                let head = self.get(0, 4).await?;
                Some(as_slice(&head.data).to_vec())
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

        // The parsed metadata is about as large as the footer it came from.
        let mut metadata_permit = self.permit(footer_len).await?;
        let metadata = if footer_start >= start {
            let from = usize::try_from(footer_start - start).ok();
            let to = bytes.len().saturating_sub(8);
            let from = from.ok_or(NotScannedReason::Unreadable)?;
            decode_metadata(buffer.data.clone(), from, to).await?
        } else {
            let footer = self.get(footer_start, self.size - 8).await?;
            let len = as_slice(&footer.data).len();
            decode_metadata(footer.data.clone(), 0, len).await?
        };
        // Wider files are refused before anything is built per column; the
        // records for the rest are counted against the budget, held with
        // the metadata.
        let columns = metadata.file_metadata().schema_descr().num_columns();
        if columns > MAX_COLUMNS {
            return Err(NotScannedReason::TooManyColumns);
        }
        let records = u64::try_from(columns).unwrap_or(u64::MAX) * CANDIDATE_BYTES;
        let records = self.permit(records).await?;
        metadata_permit = metadata_permit.join(records);

        let opened = if whole {
            Opened::Whole(buffer)
        } else {
            let first_pages = self.locate_first_pages(&metadata, &buffer, start).await?;
            Opened::Partial { first_pages }
        };
        Ok((metadata, metadata_permit, opened))
    }

    /// Where the first data page of each sampled `(row group, column)`
    /// ends, from the offset indexes. Writers put those together near the
    /// footer: if they are in the tail read, they cost nothing more; else
    /// one read covers them all (if within [`INDEX_REGION_CAP`]), never one
    /// per column. Without them, pages are found by reading headers.
    async fn locate_first_pages(
        &mut self,
        metadata: &ParquetMetaData,
        tail: &Held<B>,
        tail_start: u64,
    ) -> Result<HashMap<(usize, usize), PageLocation>, NotScannedReason> {
        let mut wanted = Vec::new();
        for row_group in row_group_order(metadata.num_row_groups()) {
            let Some(group) = metadata.row_groups().get(row_group) else {
                continue;
            };
            for (column, chunk) in group.columns().iter().enumerate() {
                let offset = chunk
                    .offset_index_offset()
                    .and_then(|o| u64::try_from(o).ok());
                let length = chunk
                    .offset_index_length()
                    .and_then(|l| u64::try_from(l).ok());
                if let (Some(offset), Some(length)) = (offset, length)
                    && wanted.len() < MAX_LOCATIONS
                    && length > 0
                    && length <= OFFSET_INDEX_CAP
                    && offset
                        .checked_add(length)
                        .is_some_and(|end| end <= self.size)
                {
                    wanted.push(((row_group, column), offset, offset + length));
                }
            }
        }
        let Some(region_start) = wanted.iter().map(|&(_, start, _)| start).min() else {
            return Ok(HashMap::new());
        };
        let region_end = wanted
            .iter()
            .map(|&(_, _, end)| end)
            .max()
            .unwrap_or(region_start);
        let fetched;
        let (data, data_start) = if region_start >= tail_start {
            (as_slice(&tail.data), tail_start)
        } else if region_end - region_start <= INDEX_REGION_CAP {
            fetched = self.get(region_start, region_end).await?;
            (as_slice(&fetched.data), region_start)
        } else {
            return Ok(HashMap::new());
        };
        let mut out = HashMap::new();
        for (slot, start, end) in wanted {
            let from = usize::try_from(start - data_start).ok();
            let to = usize::try_from(end - data_start).ok();
            let Some(bytes) = from.zip(to).and_then(|(from, to)| data.get(from..to)) else {
                continue;
            };
            let first = contain(|| decode_offset_index(bytes).ok())?
                .and_then(|index| index.page_locations().first().cloned());
            if let Some(first) = first {
                out.insert(slot, first);
            }
        }
        Ok(out)
    }

    /// Samples every candidate column of an opened file and classifies
    /// it. Columns go in batches (one at a time for a whole file, else
    /// [`COLUMN_BATCH`]), each batch row group by row group: the first,
    /// then for columns that need more, the middle, then the last. Fails
    /// only if a read is refused or fails outright, or a task panics; a
    /// column that cannot be decoded is skipped and counted.
    pub(super) async fn scan(
        &mut self,
        metadata: &ParquetMetaData,
        opened: &Opened<B>,
    ) -> Result<Scanned, NotScannedReason> {
        let order = row_group_order(metadata.num_row_groups());
        let mut not_examined = Vec::new();
        let mut candidates = self.candidates(metadata, &mut not_examined);

        let batch = match opened {
            Opened::Whole(_) => 1,
            Opened::Partial { .. } => COLUMN_BATCH,
        };
        let mut findings = Vec::new();
        // String and integer columns: those whose values are read.
        let (mut to_read, mut read) = (0_u64, 0_u64);
        for group in candidates.chunks_mut(batch) {
            for &row_group in &order {
                let active: Vec<usize> = group
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| !c.done && c.kind != Kind::Temporal)
                    .map(|(position, _)| position)
                    .collect();
                if active.is_empty() {
                    break;
                }
                let columns: Vec<(usize, ColumnDescPtr)> = active
                    .iter()
                    .filter_map(|&position| group.get(position))
                    .map(|c| (c.index, Arc::clone(&c.descr)))
                    .collect();
                let reads = match opened {
                    Opened::Whole(data) => {
                        let mut reads = Vec::with_capacity(columns.len());
                        for (index, descr) in &columns {
                            reads.push(
                                self.sample_whole(metadata, data, row_group, *index, descr)
                                    .await?,
                            );
                        }
                        reads
                    }
                    Opened::Partial { first_pages } => {
                        self.sample_round(metadata, first_pages, row_group, &columns)
                            .await?
                    }
                };
                for (&position, read) in active.iter().zip(reads) {
                    if let Some(candidate) = group.get_mut(position) {
                        candidate.apply(read);
                    }
                }
            }

            for candidate in group.iter_mut() {
                let count = match candidate.skipped {
                    Some(Skip::PageTooLarge) => &mut self.stats.skipped_page_too_large,
                    Some(Skip::UnsupportedCodec) => &mut self.stats.skipped_unsupported_codec,
                    Some(Skip::Unreadable) => &mut self.stats.skipped_unreadable,
                    None => &mut self.stats.columns_examined,
                };
                *count = count.saturating_add(1);
                if let Some(skip) = candidate.skipped {
                    let reason = match skip {
                        Skip::PageTooLarge => NotExaminedReason::PageTooLarge,
                        Skip::UnsupportedCodec => NotExaminedReason::UnsupportedCodec,
                        Skip::Unreadable => NotExaminedReason::Unreadable,
                    };
                    self.not_examined(&mut not_examined, &candidate.descr, reason);
                }
                if candidate.kind != Kind::Temporal {
                    to_read += 1;
                }
                // The sample is no longer needed: free it, and its permits.
                candidate.values = Vec::new();
                candidate.permits.clear();
                if candidate.skipped.is_some() {
                    continue;
                }
                if candidate.kind != Kind::Temporal {
                    read += 1;
                } else if all_null(metadata, &order, candidate.index) {
                    // A date column whose statistics say every sampled row
                    // group is null: nothing to report, as for a read
                    // column with no value left after cleaning.
                    continue;
                }
                if let Some(verdict) = classify(
                    &candidate.evidence,
                    candidate.hint,
                    candidate.kind,
                    candidate.named,
                ) {
                    findings.push(ColumnFinding {
                        pii: verdict.pii,
                        detail: ColumnDetail::new(
                            &candidate.descr.path().string(),
                            verdict.confidence,
                            verdict.evidence,
                        ),
                    });
                }
            }
        }
        Ok(Scanned {
            findings,
            not_examined,
            nothing_examined: to_read > 0 && read == 0,
        })
    }

    /// The columns of `metadata`'s schema whose values (or, for dates,
    /// names) are checked, each named for its hint (see [`hint_name`]).
    /// The rest are skipped as of an unsupported type, and those whose
    /// name hints personal data are recorded in `not_examined`.
    fn candidates(
        &mut self,
        metadata: &ParquetMetaData,
        not_examined: &mut Vec<NotExamined>,
    ) -> Vec<Candidate> {
        let schema = metadata.file_metadata().schema_descr();
        let mut candidates = Vec::new();
        for index in 0..schema.num_columns() {
            let descr = schema.column(index);
            let name = hint_name(schema.root_schema(), &descr);
            let Some(kind) = kind_of(&descr) else {
                self.stats.skipped_unsupported_type =
                    self.stats.skipped_unsupported_type.saturating_add(1);
                // A float or decimal can hold a phone or card number, and a
                // time a birth date: not a boolean.
                if descr.physical_type() != Physical::BOOLEAN && names::hint(name).is_some() {
                    self.not_examined(not_examined, &descr, NotExaminedReason::UnsupportedType);
                }
                continue;
            };
            candidates.push(Candidate::new(index, descr, kind, name));
        }
        candidates
    }

    /// Counts column `descr` as not examined for `reason`, and offers it to
    /// the file's examples.
    fn not_examined(
        &mut self,
        examples: &mut Vec<NotExamined>,
        descr: &ColumnDescriptor,
        reason: NotExaminedReason,
    ) {
        if let Some(count) = self.stats.not_examined.get_mut(reason.index()) {
            *count = count.saturating_add(1);
        }
        offer_not_examined(examples, &NotExamined::new(&descr.path().string(), reason));
    }

    /// Samples column `index` of `row_group` from a file read whole: its
    /// pages are checked (see [`plan_pages`]), then decoded.
    async fn sample_whole(
        &mut self,
        metadata: &ParquetMetaData,
        data: &Held<B>,
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
        let from = usize::try_from(start).ok();
        let to = usize::try_from(start + len).ok();
        let Some(bytes) = from
            .zip(to)
            .and_then(|(from, to)| as_slice(&data.data).get(from..to))
        else {
            return Ok(ColumnRead::Unreadable);
        };
        match plan_pages(bytes, len, min_value_bytes(descr), repeated(descr)) {
            Plan::Ready {
                offset,
                len: page_len,
                decode_bytes,
            } => {
                let checked = Checked {
                    data: data.data.clone(),
                    buffer_start: 0,
                    chunk_start: start,
                    chunk_len: len,
                    page_offset: offset,
                    page_len,
                };
                self.decode(checked, chunk, codec, rows, descr, decode_bytes)
                    .await
            }
            Plan::TooLarge => Ok(ColumnRead::PageTooLarge),
            Plan::NeedMore(_) | Plan::Invalid => Ok(ColumnRead::Unreadable),
        }
    }

    /// The first read for column `index` of `row_group`: one exact range
    /// when an offset index located the first data page, else the chunk's
    /// first [`WINDOW_START`] bytes. Or the column's read already, if it
    /// can be decided without reading.
    fn plan_request(
        &self,
        group: &RowGroupMetaData,
        row_group: usize,
        index: usize,
        first_pages: &HashMap<(usize, usize), PageLocation>,
    ) -> Result<Request, ColumnRead> {
        let chunk = group.columns().get(index).ok_or(ColumnRead::Unreadable)?;
        if codec(chunk.compression()).is_none() {
            return Err(ColumnRead::UnsupportedCodec);
        }
        let (start, len) = chunk_range(chunk)
            .filter(|&(start, len)| start.checked_add(len).is_some_and(|end| end <= self.size))
            .ok_or(ColumnRead::Unreadable)?;
        let first_end = match first_pages.get(&(row_group, index)) {
            Some(first) => {
                let end = u64::try_from(first.offset)
                    .ok()
                    .zip(u64::try_from(first.compressed_page_size).ok())
                    .and_then(|(offset, size)| offset.checked_add(size))
                    .filter(|&end| end > start && end <= start + len);
                match end {
                    Some(end) if end - start > WINDOW_LIMIT => {
                        return Err(ColumnRead::PageTooLarge);
                    }
                    Some(end) => end - start,
                    None => len.min(WINDOW_START),
                }
            }
            None => len.min(WINDOW_START),
        };
        if first_end == 0 {
            return Err(ColumnRead::Unreadable);
        }
        Ok(Request {
            slot: 0,
            start,
            chunk_len: len,
            end: start + first_end,
        })
    }

    /// Samples `columns` (`(index, descriptor)`) in `row_group` of a file
    /// read partially. Each phase coalesces its requests (see
    /// [`coalesce`]) and fetches the merged ranges in order, up to
    /// [`RANGE_CONCURRENCY`] at once and [`PREFETCH_CAP`] bytes in flight,
    /// under permits; each column is decoded as its range arrives. A column
    /// whose pages run past its range asks for more in the next phase.
    async fn sample_round(
        &mut self,
        metadata: &ParquetMetaData,
        first_pages: &HashMap<(usize, usize), PageLocation>,
        row_group: usize,
        columns: &[(usize, ColumnDescPtr)],
    ) -> Result<Vec<ColumnRead>, NotScannedReason> {
        let mut results: Vec<Option<ColumnRead>> = std::iter::repeat_with(|| None)
            .take(columns.len())
            .collect();
        let Some(group) = metadata.row_groups().get(row_group) else {
            return Ok(columns.iter().map(|_| ColumnRead::Unreadable).collect());
        };
        let round = Round {
            group,
            rows: usize::try_from(group.num_rows()).unwrap_or(0),
            columns,
        };
        let mut pending = Vec::new();
        for (slot, (index, _)) in columns.iter().enumerate() {
            match self.plan_request(group, row_group, *index, first_pages) {
                Ok(request) => pending.push(Request { slot, ..request }),
                Err(read) => {
                    if let Some(result) = results.get_mut(slot) {
                        *result = Some(read);
                    }
                }
            }
        }

        while !pending.is_empty() {
            let mut ranges = coalesce(std::mem::take(&mut pending), self.coalesce_gap).into_iter();
            let mut next = ranges.next();
            let mut queue = VecDeque::new();
            let mut in_flight: u64 = 0;
            loop {
                while queue.len() < RANGE_CONCURRENCY {
                    let Some(merged) = next.take() else {
                        break;
                    };
                    let len = merged.end - merged.start;
                    if !queue.is_empty() && in_flight + len > PREFETCH_CAP {
                        next = Some(merged);
                        break;
                    }
                    let permit = self.permit(len).await?;
                    let fetch = fetch_range(
                        self.reader.clone(),
                        Arc::clone(&self.key),
                        merged.start,
                        merged.end,
                        self.convert,
                    );
                    let task = tokio::spawn(async move {
                        let (returned, data) = fetch.await;
                        (returned, data, permit)
                    });
                    in_flight += len;
                    queue.push_back((merged, Task(task), len));
                    next = ranges.next();
                }
                let Some((merged, mut task, len)) = queue.pop_front() else {
                    break;
                };
                let (returned, data, permit) = (&mut task.0)
                    .await
                    .map_err(|_| NotScannedReason::Unreadable)?;
                self.count(returned);
                let held = Held {
                    data: data?,
                    _permit: permit,
                };
                for request in &merged.members {
                    match self
                        .sample_request(&held, merged.start, request, &round)
                        .await?
                    {
                        Step::Done(read) => {
                            if let Some(result) = results.get_mut(request.slot) {
                                *result = Some(read);
                            }
                        }
                        Step::More(longer) => pending.push(longer),
                    }
                }
                in_flight -= len;
            }
        }
        Ok(results
            .into_iter()
            .map(|result| result.unwrap_or(ColumnRead::Unreadable))
            .collect())
    }

    /// Checks one column's pages in a fetched range starting at file
    /// offset `held_start`, then decodes them, or asks for more.
    async fn sample_request(
        &mut self,
        held: &Held<B>,
        held_start: u64,
        request: &Request,
        round: &Round<'_>,
    ) -> Result<Step, NotScannedReason> {
        let Some((index, descr)) = round.columns.get(request.slot) else {
            return Ok(Step::Done(ColumnRead::Unreadable));
        };
        let Some(chunk) = round.group.columns().get(*index) else {
            return Ok(Step::Done(ColumnRead::Unreadable));
        };
        let Some(codec) = codec(chunk.compression()) else {
            return Ok(Step::Done(ColumnRead::UnsupportedCodec));
        };
        let from = usize::try_from(request.start - held_start).ok();
        let to = usize::try_from(request.end - held_start).ok();
        let Some(bytes) = from
            .zip(to)
            .and_then(|(from, to)| as_slice(&held.data).get(from..to))
        else {
            return Ok(Step::Done(ColumnRead::Unreadable));
        };
        let window = request.end - request.start;
        Ok(
            match plan_pages(
                bytes,
                request.chunk_len,
                min_value_bytes(descr),
                repeated(descr),
            ) {
                Plan::Ready {
                    offset,
                    len,
                    decode_bytes,
                } => {
                    let checked = Checked {
                        data: held.data.clone(),
                        buffer_start: held_start,
                        chunk_start: request.start,
                        chunk_len: window,
                        page_offset: offset,
                        page_len: len,
                    };
                    Step::Done(
                        self.decode(checked, chunk, codec, round.rows, descr, decode_bytes)
                            .await?,
                    )
                }
                Plan::TooLarge => Step::Done(ColumnRead::PageTooLarge),
                Plan::Invalid => Step::Done(ColumnRead::Unreadable),
                Plan::NeedMore(needed) => {
                    let wanted = needed.min(request.chunk_len);
                    if wanted <= window {
                        Step::Done(ColumnRead::Unreadable)
                    } else {
                        Step::More(Request {
                            end: request.start + wanted,
                            ..*request
                        })
                    }
                }
            },
        )
    }

    /// Decodes checked pages on the blocking pool, inside [`contain`],
    /// under permits for their declared sizes (`decode_bytes`) and for the
    /// sample, which stays with the values.
    async fn decode(
        &mut self,
        checked: Checked<B>,
        chunk: &ColumnChunkMetaData,
        codec: Codec,
        rows: usize,
        descr: &ColumnDescPtr,
        decode_bytes: u64,
    ) -> Result<ColumnRead, NotScannedReason> {
        // A column over the single-file need is skipped as unreadable; a
        // wait past the limit gives up on the whole file.
        let work = match self.budget.acquire(decode_bytes).await {
            Ok(permit) => permit,
            Err(Refused::OverNeed) => return Ok(ColumnRead::Unreadable),
            Err(refused @ Refused::TimedOut) => return Err(not_scanned(refused)),
        };
        let sample = match self.budget.acquire(SAMPLE_BYTES).await {
            Ok(permit) => permit,
            Err(Refused::OverNeed) => return Ok(ColumnRead::Unreadable),
            Err(refused @ Refused::TimedOut) => return Err(not_scanned(refused)),
        };
        let chunk = chunk.clone();
        let descr = Arc::clone(descr);
        let decoded = tokio::task::spawn_blocking(move || {
            decode_contained(checked, &chunk, codec, rows, &descr)
        })
        .await
        .map_err(|_| NotScannedReason::Unreadable)??;
        drop(work);
        Ok(match decoded {
            Some(values) => ColumnRead::Values(values, sample),
            None => ColumnRead::Unreadable,
        })
    }
}

/// Decodes a footer on the blocking pool, inside [`contain`].
async fn decode_metadata<B: Window>(
    data: B,
    from: usize,
    to: usize,
) -> Result<ParquetMetaData, NotScannedReason> {
    tokio::task::spawn_blocking(move || {
        contain(|| {
            as_slice(&data)
                .get(from..to)
                .and_then(|bytes| ParquetMetaDataReader::decode_metadata(bytes).ok())
        })
    })
    .await
    .map_err(|_| NotScannedReason::Unreadable)??
    .ok_or(NotScannedReason::Unreadable)
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
    Ready {
        offset: u64,
        len: u64,
        /// What decoding allocates for the pages: their declared
        /// uncompressed sizes, a dictionary's slots, and for a repeated
        /// column, its levels and value slots.
        decode_bytes: u64,
    },
    /// More bytes are needed: the chunk's first `n`.
    NeedMore(u64),
    /// A page declares more than [`PAGE_CAP`], a dictionary more than
    /// [`MAX_DICTIONARY_VALUES`], or a repeated column's data page more
    /// than [`MAX_REPEATED_VALUES`].
    TooLarge,
    /// Not a valid page sequence.
    Invalid,
}

/// Walks the page headers at the start of a column chunk (`bytes`, the
/// chunk's first bytes; `chunk_len`, its full length) up to the first data
/// page, checking every declared size before anything is allocated for
/// it: an optional dictionary page, then a data page, which for a
/// `repeated` column must declare at most [`MAX_REPEATED_VALUES`] values.
fn plan_pages(bytes: &[u8], chunk_len: u64, min_value_bytes: u64, repeated: bool) -> Plan {
    let held = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let mut pos: u64 = 0;
    let mut first = true;
    let mut dictionary_bytes: u64 = 0;
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
                dictionary_bytes =
                    page.uncompressed + page.dictionary_values * DICTIONARY_SLOT_BYTES;
                pos = end;
                first = false;
            }
            header::DATA_PAGE | header::DATA_PAGE_V2 => {
                if repeated && page.data_values > MAX_REPEATED_VALUES {
                    return Plan::TooLarge;
                }
                let levels = if repeated {
                    page.data_values * REPEATED_SLOT_BYTES
                } else {
                    0
                };
                return if end > held {
                    Plan::NeedMore(end)
                } else {
                    Plan::Ready {
                        offset: pos,
                        len: end - pos,
                        decode_bytes: dictionary_bytes + page.uncompressed + levels,
                    }
                };
            }
            _ => return Plan::Invalid,
        }
    }
}

/// Decodes one checked data page with [`decode`], decompressing it first
/// if `codec` says `LakeScan` must, all inside [`contain`]: the values, or
/// `None` (a decoding error skips the column); a panic fails the file.
fn decode_contained<B: Window>(
    checked: Checked<B>,
    chunk: &ColumnChunkMetaData,
    codec: Codec,
    rows: usize,
    descr: &ColumnDescPtr,
) -> Result<Option<Vec<String>>, NotScannedReason> {
    contain(|| {
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
    })
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
    fault::maybe_panic(descr.name());
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
    let repeated = repeated(descr);
    let text = |value: &[u8]| String::from_utf8_lossy(value).into_owned();
    match get_column_reader(Arc::clone(descr), Box::new(pages)) {
        ColumnReader::ByteArrayColumnReader(reader) => {
            read_values(reader, repeated, &mut out, |v: &ByteArray| text(v.data()))?;
        }
        ColumnReader::FixedLenByteArrayColumnReader(reader) => {
            read_values(reader, repeated, &mut out, |v: &FixedLenByteArray| {
                text(v.data())
            })?;
        }
        ColumnReader::Int32ColumnReader(reader) => {
            read_values(reader, repeated, &mut out, i32::to_string)?;
        }
        ColumnReader::Int64ColumnReader(reader) => {
            read_values(reader, repeated, &mut out, i64::to_string)?;
        }
        _ => {}
    }
    out.truncate(MAX_VALUES_PER_ROW_GROUP);
    Ok(out)
}

/// Reads the page `column` was given, [`BATCH`] rows at a time, adding
/// each value `render`ed and cleaned to `out` until it holds
/// [`MAX_VALUES_PER_ROW_GROUP`]. A `repeated` column's levels are read too:
/// `parquet` needs them to find rows.
fn read_values<T: DataType>(
    mut column: ColumnReaderImpl<T>,
    repeated: bool,
    out: &mut Vec<String>,
    render: impl Fn(&T::T) -> String,
) -> ParquetResult<()> {
    let mut definitions: Vec<i16> = Vec::new();
    let mut repetitions: Option<Vec<i16>> = repeated.then(Vec::new);
    loop {
        let mut batch: Vec<T::T> = Vec::new();
        definitions.clear();
        if let Some(levels) = repetitions.as_mut() {
            levels.clear();
        }
        let (records, _, _) = column.read_records(
            BATCH,
            Some(&mut definitions),
            repetitions.as_mut(),
            &mut batch,
        )?;
        for value in batch
            .iter()
            .take(MAX_VALUES_PER_ROW_GROUP.saturating_sub(out.len()))
        {
            if let Some(value) = clean(&render(value)) {
                out.push(value.to_owned());
            }
        }
        if records == 0 || full(out) {
            return Ok(());
        }
    }
}

fn full(values: &[String]) -> bool {
    values.len() >= MAX_VALUES_PER_ROW_GROUP
}

/// Whether `descr` is a repeated column: a leaf of a list or a map.
fn repeated(descr: &ColumnDescriptor) -> bool {
    descr.max_rep_level() > 0
}

/// The name column `descr`'s hint is read from: the last segment of its
/// path that is not a list or map wrapper. `tags.list.element` is `tags`,
/// `name.list.element.given.list.element` is `given`, and
/// `attrs.key_value.value` is `attrs`. Walks `root` (the file's schema)
/// along the path: under a `LIST` group, its repeated child is a wrapper,
/// and so is that child's only field in the standard three-level form
/// (`list`, `element`; not the legacy `array` or `<name>_tuple`); under a
/// `MAP` group, its `key_value` group and the `key` and `value` in it are.
/// A plain column's name is its own (`descr.name()`).
fn hint_name<'a>(root: &'a SchemaType, descr: &ColumnDescriptor) -> &'a str {
    let mut node = root;
    let mut name = "";
    let mut wrappers = 0_usize;
    for part in descr.path().parts() {
        if !node.is_group() {
            break;
        }
        let Some(child) = node.get_fields().iter().find(|field| field.name() == part) else {
            break;
        };
        node = child;
        if wrappers > 0 {
            wrappers -= 1;
        } else {
            name = node.name();
        }
        if node.is_group() {
            let info = node.get_basic_info();
            let list = matches!(info.logical_type_ref(), Some(LogicalType::List))
                || info.converted_type() == ConvertedType::LIST;
            let map = matches!(info.logical_type_ref(), Some(LogicalType::Map))
                || matches!(
                    info.converted_type(),
                    ConvertedType::MAP | ConvertedType::MAP_KEY_VALUE
                );
            if map {
                wrappers = 2;
            } else if list {
                let three_level = match node.get_fields() {
                    [child] => {
                        child.is_group()
                            && child.get_fields().len() == 1
                            && child.name() != "array"
                            && !child.name().ends_with("_tuple")
                    }
                    _ => false,
                };
                wrappers = if three_level { 2 } else { 1 };
            }
        }
    }
    name
}

/// Whether column `index` is all null in every row group of `order`, by
/// its chunks' statistics: `false` when any is missing.
fn all_null(metadata: &ParquetMetaData, order: &[usize], index: usize) -> bool {
    !order.is_empty()
        && order.iter().all(|&row_group| {
            metadata
                .row_groups()
                .get(row_group)
                .and_then(|group| group.columns().get(index))
                .is_some_and(|chunk| {
                    let values = u64::try_from(chunk.num_values()).unwrap_or(u64::MAX);
                    chunk
                        .statistics()
                        .and_then(parquet::file::statistics::Statistics::null_count_opt)
                        .is_some_and(|nulls| values > 0 && nulls >= values)
                })
        })
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

/// Test-only fault injection: makes decodes of a named column panic, to
/// prove a panic inside `parquet` is contained, and counts decodes per
/// column name. Keyed by column, not thread, because decodes run on the
/// blocking pool. Not compiled into the binary.
#[cfg(test)]
pub(crate) mod fault {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Mutex;

    static ARMED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
    static DECODES: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());

    /// How many decodes of columns named `column` have started.
    pub(crate) fn decodes(column: &str) -> u64 {
        DECODES
            .lock()
            .ok()
            .and_then(|counts| counts.get(column).copied())
            .unwrap_or(0)
    }

    /// Makes every decode of a column named `column` panic until
    /// [`disarm`].
    pub(crate) fn arm(column: &str) {
        if let Ok(mut armed) = ARMED.lock() {
            armed.insert(column.to_owned());
        }
    }

    pub(crate) fn disarm(column: &str) {
        if let Ok(mut armed) = ARMED.lock() {
            armed.remove(column);
        }
    }

    pub(super) fn maybe_panic(column: &str) {
        if let Ok(mut counts) = DECODES.lock() {
            *counts.entry(column.to_owned()).or_default() += 1;
        }
        if ARMED.lock().is_ok_and(|armed| armed.contains(column)) {
            std::panic::resume_unwind(Box::new("injected decode fault"));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::header::PageHeader;
    use super::{
        COALESCE_MAX, Codec, Request, brotli_window_is_standard, coalesce, file_need, hint_name,
        inflate, row_group_order,
    };

    /// Every leaf of `schema` (a message type) with the name its hint is
    /// read from.
    fn hint_names(schema: &str) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
        let root = std::sync::Arc::new(parquet::schema::parser::parse_message_type(schema)?);
        let descriptor = parquet::schema::types::SchemaDescriptor::new(root);
        Ok((0..descriptor.num_columns())
            .map(|index| {
                let column = descriptor.column(index);
                (
                    column.path().string(),
                    hint_name(descriptor.root_schema(), &column).to_owned(),
                )
            })
            .collect())
    }

    /// FHIR as `DuckDB` writes it (the experiment's Synthea patients), the
    /// legacy list forms, and maps.
    #[test]
    fn a_hint_is_read_from_the_leaf_behind_list_and_map_wrappers()
    -> Result<(), Box<dyn std::error::Error>> {
        let schema = "
            message patient {
                optional binary id (STRING);
                optional group billing { optional binary email (STRING); }
                optional group name (LIST) {
                    repeated group list {
                        optional group element {
                            optional binary family (STRING);
                            optional group given (LIST) {
                                repeated group list { optional binary element (STRING); }
                            }
                        }
                    }
                }
                optional group telecom (LIST) {
                    repeated group list {
                        optional group element {
                            optional binary system (STRING);
                            optional binary value (STRING);
                        }
                    }
                }
                optional group emails (LIST) { repeated binary array (STRING); }
                optional group phones (LIST) {
                    repeated group phones_tuple { optional binary number (STRING); }
                }
                optional group contacts (LIST) {
                    repeated group array { optional binary mobile (STRING); }
                }
                optional group attrs (MAP) {
                    repeated group key_value {
                        required binary key (STRING);
                        optional binary value (STRING);
                    }
                }
                optional group people (MAP) {
                    repeated group key_value {
                        required binary key (STRING);
                        optional group value { optional binary surname (STRING); }
                    }
                }
                repeated binary tags (STRING);
            }";
        let expected = [
            ("id", "id"),
            ("billing.email", "email"),
            ("name.list.element.family", "family"),
            ("name.list.element.given.list.element", "given"),
            ("telecom.list.element.system", "system"),
            ("telecom.list.element.value", "value"),
            ("emails.array", "emails"),
            ("phones.phones_tuple.number", "number"),
            ("contacts.array.mobile", "mobile"),
            ("attrs.key_value.key", "attrs"),
            ("attrs.key_value.value", "attrs"),
            ("people.key_value.key", "people"),
            ("people.key_value.value.surname", "surname"),
            ("tags", "tags"),
        ];
        let got = hint_names(schema)?;
        let want: Vec<(String, String)> = expected
            .iter()
            .map(|&(path, name)| (path.to_owned(), name.to_owned()))
            .collect();
        assert_eq!(got, want);
        Ok(())
    }

    fn request(slot: usize, start: u64, end: u64) -> Request {
        Request {
            slot,
            start,
            chunk_len: end - start,
            end,
        }
    }

    #[test]
    fn coalescing_merges_close_ranges_in_order_and_never_past_the_cap() {
        const MIB: u64 = 1024 * 1024;
        let requests = vec![
            request(2, 10 * MIB, 10 * MIB + 100),
            request(0, 0, 1000),
            request(1, 1000 + MIB, 2 * MIB),
            request(3, 30 * MIB, 40 * MIB),
            request(4, 40 * MIB + 1, 40 * MIB + 2),
        ];
        // Gap 0: nothing merges, but the order is sorted.
        let apart = coalesce(requests.clone(), 0);
        assert_eq!(
            apart.iter().map(|m| m.members.len()).collect::<Vec<_>>(),
            [1, 1, 1, 1, 1]
        );
        assert_eq!(apart.first().map(|m| m.start), Some(0));
        // 1 MiB: the first two merge; 10 MiB is too far; the 10 MiB range
        // stands alone (over the cap), so its 1-byte neighbour does too.
        let merged = coalesce(requests, MIB);
        let shape: Vec<(u64, u64, Vec<usize>)> = merged
            .iter()
            .map(|m| (m.start, m.end, m.members.iter().map(|r| r.slot).collect()))
            .collect();
        assert_eq!(
            shape,
            [
                (0, 2 * MIB, vec![0, 1]),
                (10 * MIB, 10 * MIB + 100, vec![2]),
                (30 * MIB, 40 * MIB, vec![3]),
                (40 * MIB + 1, 40 * MIB + 2, vec![4]),
            ]
        );
        // Many small ranges a byte apart: merged reads never pass 8 MiB.
        let many: Vec<Request> = (0..10_000)
            .map(|i| {
                request(
                    i,
                    u64::try_from(i).unwrap_or(0) * 4097,
                    u64::try_from(i).unwrap_or(0) * 4097 + 4096,
                )
            })
            .collect();
        let merged = coalesce(many, MIB);
        assert!(merged.len() > 1);
        assert!(merged.iter().all(|m| m.end - m.start <= COALESCE_MAX));
        assert_eq!(
            merged.iter().map(|m| m.members.len()).sum::<usize>(),
            10_000
        );
    }

    #[test]
    fn one_file_s_need_covers_both_read_paths() {
        // ~108 MiB at the default whole-file maximum: partial reads
        // dominate; at 64 MiB, whole reads do.
        assert!(file_need(8 << 20) < 110 << 20);
        assert!(file_need(8 << 20) > 90 << 20);
        assert!(file_need(64 << 20) > file_need(8 << 20));
        assert!(super::super::DEFAULT_MEMORY_BUDGET >= file_need(super::super::MAX_WHOLE_FILE_MAX));
        // The sample bound matches its parts.
        let parts = (super::MAX_VALUES_PER_ROW_GROUP + super::BATCH)
            * (super::super::clean::MAX_VALUE_BYTES + size_of::<String>());
        assert_eq!(u64::try_from(parts).ok(), Some(super::SAMPLE_BYTES));
    }

    fn page(uncompressed: usize, levels: u64, values_compressed: bool) -> PageHeader {
        PageHeader {
            kind: super::header::DATA_PAGE_V2,
            uncompressed: u64::try_from(uncompressed).unwrap_or(u64::MAX),
            compressed: 0,
            dictionary_values: 0,
            data_values: 0,
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
        let values = b"person.1@mail.example".repeat(10);
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
