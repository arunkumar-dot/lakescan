//! A Parquet page header pre-check: the sizes a page header *declares*,
//! read before the `parquet` crate is allowed to act on them.
//!
//! The `parquet` crate allocates a page's declared uncompressed size, and a
//! dictionary's declared value count, before checking either against the
//! bytes it was given. A crafted header declaring 2 GiB would therefore
//! allocate 2 GiB, and an allocation failure aborts the process, which no
//! `catch_unwind` can contain. So `LakeScan` reads every header it is about
//! to hand to `parquet` first, and refuses any page over the page cap.
//!
//! This reads only the Thrift compact protocol (the format of every Parquet
//! header) far enough to get four numbers: the page type, the uncompressed
//! and compressed sizes, and, for a dictionary page, its value count. It
//! also returns the header's length, so the next page can be located. Every
//! other field is skipped generically. It decodes no values: that remains
//! the `parquet` crate's job.

/// What a page header declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PageHeader {
    /// The `PageType`: 0 data page, 1 index page, 2 dictionary page, 3
    /// data page v2.
    pub(super) kind: i32,
    /// The page's size once decompressed.
    pub(super) uncompressed: u64,
    /// The page body's size as stored, after the header.
    pub(super) compressed: u64,
    /// A dictionary page's value count; 0 for any other page.
    pub(super) dictionary_values: u64,
    /// The header's own length in bytes.
    pub(super) len: usize,
}

pub(super) const DATA_PAGE: i32 = 0;
pub(super) const DICTIONARY_PAGE: i32 = 2;
pub(super) const DATA_PAGE_V2: i32 = 3;

/// The result of reading a header from the bytes at hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Read {
    /// A whole, valid header.
    Header(PageHeader),
    /// The bytes ended before the header did.
    Incomplete,
    /// Not a valid page header.
    Invalid,
}

/// Nesting deeper than this is not a page header.
const MAX_DEPTH: u32 = 16;

// Thrift compact protocol type ids.
const BOOL_TRUE: u8 = 1;
const BOOL_FALSE: u8 = 2;
const BYTE: u8 = 3;
const I16: u8 = 4;
const I32: u8 = 5;
const I64: u8 = 6;
const DOUBLE: u8 = 7;
const BINARY: u8 = 8;
const LIST: u8 = 9;
const SET: u8 = 10;
const MAP: u8 = 11;
const STRUCT: u8 = 12;
const UUID: u8 = 13;

enum Stop {
    Incomplete,
    Invalid,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn byte(&mut self) -> Result<u8, Stop> {
        let byte = self.bytes.get(self.pos).copied().ok_or(Stop::Incomplete)?;
        self.pos += 1;
        Ok(byte)
    }

    fn skip(&mut self, n: usize) -> Result<(), Stop> {
        let end = self.pos.checked_add(n).ok_or(Stop::Invalid)?;
        if end > self.bytes.len() {
            return Err(Stop::Incomplete);
        }
        self.pos = end;
        Ok(())
    }

    /// An unsigned LEB128 varint of at most `max_bytes` bytes.
    fn varint(&mut self, max_bytes: u32) -> Result<u64, Stop> {
        let mut value: u64 = 0;
        for index in 0..max_bytes {
            let byte = self.byte()?;
            value |= u64::from(byte & 0x7f) << (7 * index);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Stop::Invalid)
    }

    fn zigzag(&mut self, max_bytes: u32) -> Result<i64, Stop> {
        let raw = self.varint(max_bytes)?;
        let magnitude = i64::try_from(raw >> 1).map_err(|_| Stop::Invalid)?;
        Ok(if raw & 1 == 0 {
            magnitude
        } else {
            -magnitude - 1
        })
    }

    fn i32(&mut self) -> Result<i32, Stop> {
        i32::try_from(self.zigzag(5)?).map_err(|_| Stop::Invalid)
    }

    /// A field header: `(field id, type)`, or `None` at the struct's end.
    fn field(&mut self, last_id: i16) -> Result<Option<(i16, u8)>, Stop> {
        let byte = self.byte()?;
        if byte == 0 {
            return Ok(None);
        }
        let kind = byte & 0x0f;
        let delta = i16::from(byte >> 4);
        let id = if delta == 0 {
            i16::try_from(self.zigzag(3)?).map_err(|_| Stop::Invalid)?
        } else {
            last_id.checked_add(delta).ok_or(Stop::Invalid)?
        };
        Ok(Some((id, kind)))
    }

    /// Skips one value of compact type `kind`.
    fn skip_value(&mut self, kind: u8, depth: u32) -> Result<(), Stop> {
        if depth > MAX_DEPTH {
            return Err(Stop::Invalid);
        }
        match kind {
            BOOL_TRUE | BOOL_FALSE => Ok(()),
            BYTE => self.skip(1),
            I16 | I32 | I64 => self.varint(10).map(|_| ()),
            DOUBLE => self.skip(8),
            BINARY => {
                let len = usize::try_from(self.varint(5)?).map_err(|_| Stop::Invalid)?;
                self.skip(len)
            }
            UUID => self.skip(16),
            LIST | SET => {
                let header = self.byte()?;
                let size = match header >> 4 {
                    15 => usize::try_from(self.varint(5)?).map_err(|_| Stop::Invalid)?,
                    short => usize::from(short),
                };
                self.skip_elements(size, &[header & 0x0f], depth)
            }
            MAP => {
                let size = usize::try_from(self.varint(5)?).map_err(|_| Stop::Invalid)?;
                if size == 0 {
                    return Ok(());
                }
                let types = self.byte()?;
                self.skip_elements(size, &[types >> 4, types & 0x0f], depth)
            }
            STRUCT => self.skip_struct(depth + 1),
            _ => Err(Stop::Invalid),
        }
    }

    /// Skips `size` collection entries, each one value per type in
    /// `kinds`. Booleans inside a collection take one byte each.
    fn skip_elements(&mut self, size: usize, kinds: &[u8], depth: u32) -> Result<(), Stop> {
        // Every element takes at least one byte, so a count beyond the
        // bytes left can only be satisfied by more bytes.
        if size > self.bytes.len().saturating_sub(self.pos) {
            return Err(Stop::Incomplete);
        }
        for _ in 0..size {
            for &kind in kinds {
                if matches!(kind, BOOL_TRUE | BOOL_FALSE) {
                    self.skip(1)?;
                } else {
                    self.skip_value(kind, depth + 1)?;
                }
            }
        }
        Ok(())
    }

    fn skip_struct(&mut self, depth: u32) -> Result<(), Stop> {
        let mut last = 0;
        while let Some((id, kind)) = self.field(last)? {
            self.skip_value(kind, depth)?;
            last = id;
        }
        Ok(())
    }

    /// A `DictionaryPageHeader`'s `num_values` (field 1); the rest skipped.
    fn dictionary_values(&mut self) -> Result<u64, Stop> {
        let mut values = None;
        let mut last = 0;
        while let Some((id, kind)) = self.field(last)? {
            if id == 1 && kind == I32 && values.is_none() {
                values = Some(u64::try_from(self.i32()?).map_err(|_| Stop::Invalid)?);
            } else if id == 1 {
                return Err(Stop::Invalid);
            } else {
                self.skip_value(kind, 1)?;
            }
            last = id;
        }
        values.ok_or(Stop::Invalid)
    }
}

/// Reads the page header at the start of `bytes`.
pub(super) fn read(bytes: &[u8]) -> Read {
    let mut cursor = Cursor { bytes, pos: 0 };
    match header(&mut cursor) {
        Ok(header) => Read::Header(header),
        Err(Stop::Incomplete) => Read::Incomplete,
        Err(Stop::Invalid) => Read::Invalid,
    }
}

fn header(cursor: &mut Cursor<'_>) -> Result<PageHeader, Stop> {
    let mut kind = None;
    let mut uncompressed = None;
    let mut compressed = None;
    let mut dictionary_values = None;
    let mut last = 0;
    while let Some((id, field_kind)) = cursor.field(last)? {
        // A required field seen twice, or with the wrong type, is not a
        // header `parquet` and this reader could agree on.
        let slot = match (id, field_kind) {
            (1, I32) => Some(&mut kind),
            (2, I32) => Some(&mut uncompressed),
            (3, I32) => Some(&mut compressed),
            (1..=3, _) => return Err(Stop::Invalid),
            _ => None,
        };
        match slot {
            Some(slot) if slot.is_none() => *slot = Some(cursor.i32()?),
            Some(_) => return Err(Stop::Invalid),
            None if id == 7 && field_kind == STRUCT => {
                if dictionary_values.is_some() {
                    return Err(Stop::Invalid);
                }
                dictionary_values = Some(cursor.dictionary_values()?);
            }
            None => cursor.skip_value(field_kind, 1)?,
        }
        last = id;
    }
    let size = |value: Option<i32>| {
        value
            .and_then(|v| u64::try_from(v).ok())
            .ok_or(Stop::Invalid)
    };
    let kind = kind.ok_or(Stop::Invalid)?;
    if kind == DICTIONARY_PAGE && dictionary_values.is_none() {
        return Err(Stop::Invalid);
    }
    Ok(PageHeader {
        kind,
        uncompressed: size(uncompressed)?,
        compressed: size(compressed)?,
        dictionary_values: dictionary_values.unwrap_or(0),
        len: cursor.pos,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{DATA_PAGE, DICTIONARY_PAGE, PageHeader, Read, read};

    fn zigzag_varint(value: i64, out: &mut Vec<u8>) {
        let mut raw = u64::try_from((value << 1) ^ (value >> 63)).unwrap_or(0);
        loop {
            let byte = u8::try_from(raw & 0x7f).unwrap_or(0);
            raw >>= 7;
            if raw == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    /// A compact-protocol page header: type, sizes, and either a
    /// dictionary page header (`dictionary_values`) or a minimal data page
    /// header.
    pub(crate) fn encode(
        kind: i32,
        uncompressed: i32,
        compressed: i32,
        dictionary_values: Option<i32>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        for value in [kind, uncompressed, compressed] {
            out.push(0x15); // delta 1, i32
            zigzag_varint(i64::from(value), &mut out);
        }
        if let Some(values) = dictionary_values {
            out.push(0x4c); // delta 4 (field 7), struct
            out.push(0x15); // num_values: i32
            zigzag_varint(i64::from(values), &mut out);
            out.push(0x15); // encoding: PLAIN
            zigzag_varint(0, &mut out);
            out.push(0x00);
        } else {
            out.push(0x2c); // delta 2 (field 5), struct
            for value in [1, 0, 3, 3] {
                // num_values, encoding, def and rep level encodings
                out.push(0x15);
                zigzag_varint(value, &mut out);
            }
            out.push(0x00);
        }
        out.push(0x00);
        out
    }

    #[test]
    fn a_data_page_header_reads_back_with_its_length() {
        let bytes = encode(DATA_PAGE, 1000, 400, None);
        assert_eq!(
            read(&bytes),
            Read::Header(PageHeader {
                kind: DATA_PAGE,
                uncompressed: 1000,
                compressed: 400,
                dictionary_values: 0,
                len: bytes.len(),
            })
        );
    }

    #[test]
    fn a_dictionary_page_header_reports_its_value_count() {
        let bytes = encode(DICTIONARY_PAGE, i32::MAX, 10, Some(i32::MAX));
        let Read::Header(header) = read(&bytes) else {
            unreachable!("not a header: {:?}", read(&bytes));
        };
        assert_eq!(header.uncompressed, u64::try_from(i32::MAX).unwrap_or(0));
        assert_eq!(
            header.dictionary_values,
            u64::try_from(i32::MAX).unwrap_or(0)
        );
    }

    #[test]
    fn a_truncated_header_is_incomplete_and_garbage_is_invalid() {
        let bytes = encode(DATA_PAGE, 1000, 400, None);
        for cut in 0..bytes.len() {
            assert_eq!(
                read(bytes.get(..cut).unwrap_or(&[])),
                Read::Incomplete,
                "{cut}"
            );
        }
        assert_eq!(read(&[0x00]), Read::Invalid, "no fields");
        assert_eq!(read(&[0x1f, 0x00]), Read::Invalid, "unknown type");
        assert_eq!(
            read(&[0x15, 0x02, 0x15, 0x01, 0x15, 0x01, 0x00]),
            Read::Invalid,
            "negative size"
        );
        // Field 2 twice: the second with an explicit (long-form) id.
        let twice = [0x15, 0x00, 0x15, 0x02, 0x05, 0x04, 0x02, 0x00];
        assert_eq!(read(&twice), Read::Invalid, "duplicate field");
    }

    #[test]
    fn unknown_fields_of_every_type_are_skipped() {
        let mut bytes = Vec::new();
        bytes.extend([0x15, 0x00, 0x15, 0x04, 0x15, 0x04]); // type 0, sizes 2, 2
        bytes.extend([0x18, 0x02, b'h', b'i']); // field 4: binary "hi"
        bytes.extend([0x19, 0x25, 0x02, 0x04]); // field 5: list<i32> [1, 2]
        bytes.extend([0x1b, 0x01, 0x55, 0x02, 0x02]); // field 6: map<i32,i32> {1: 1}
        bytes.extend([0x11]); // field 7: bool true
        bytes.push(0x00);
        assert!(
            matches!(read(&bytes), Read::Header(h) if h.len == bytes.len() && h.uncompressed == 2)
        );
    }
}
