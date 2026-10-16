//! The PII inventory as CSV (`--inventory`): one row per `(table, column,
//! rule)`, under a header row.
//!
//! RFC 4180, written by hand: fields separated by commas, records ended by
//! CRLF, and a field quoted (with any `"` doubled) when it holds a comma,
//! a quote, a CR or an LF.
//!
//! Table names, column paths, example keys and suppression reasons are
//! attacker-controlled (anyone who can upload to the bucket names keys and
//! columns). This file is a human-facing report, so every cell is first
//! escaped like the text summary (see `escape`): control characters and
//! the bidi controls U+202A-U+202E and U+2066-U+2069 become `\u{XXXX}`, so
//! `--inventory -` cannot drive a terminal and a name cannot display as
//! another in a spreadsheet. Then, since spreadsheets run a cell that
//! starts with `=`, `+`, `-` or `@` as a formula, such a cell is prefixed
//! with a single quote, which spreadsheets show as text. The JSON summary
//! and the findings stream remain the exact-data channels. The inventory
//! holds no sampled values, so neither does this file.

use std::io::Write;

use super::escape::escaped;
use super::status_of;
use crate::aggregate::Aggregates;
use crate::error::LakeScanError;
use crate::suppress::Outcome;

/// The header row, in column order.
pub(super) const HEADER: [&str; 12] = [
    "table",
    "column",
    "rule",
    "highest_confidence",
    "evidence",
    "files_confirmed",
    "files_likely",
    "files_possible",
    "files_suppressed",
    "status",
    "reason",
    "example_key",
];

/// `field`, escaped and made safe to open in a spreadsheet (see this
/// module's doc), then quoted if RFC 4180 requires it.
fn write_field<W: Write>(out: &mut W, field: &str) -> std::io::Result<()> {
    let field = escaped(field);
    let field = field.as_str();
    // A tab or CR was escaped above, so only these can start a formula.
    let formula = field
        .chars()
        .next()
        .is_some_and(|first| matches!(first, '=' | '+' | '-' | '@'));
    let quote = field.contains([',', '"', '\r', '\n']);
    if quote {
        out.write_all(b"\"")?;
    }
    if formula {
        out.write_all(b"'")?;
    }
    if quote {
        out.write_all(field.replace('"', "\"\"").as_bytes())?;
        out.write_all(b"\"")
    } else {
        out.write_all(field.as_bytes())
    }
}

fn write_record<W: Write, S: AsRef<str>>(out: &mut W, fields: &[S]) -> std::io::Result<()> {
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            out.write_all(b",")?;
        }
        write_field(out, field.as_ref())?;
    }
    out.write_all(b"\r\n")
}

/// Writes the inventory in `aggregates` as CSV: the header row, then one
/// row per entry, tables in name order and entries in column, then rule,
/// order. Only the header without content scanning.
pub(super) fn write<W: Write>(
    out: &mut W,
    suppressions: &Outcome,
    aggregates: &Aggregates,
) -> Result<(), LakeScanError> {
    write_record(out, &HEADER).map_err(LakeScanError::Report)?;
    let Some(inventory) = aggregates.pii_inventory() else {
        return Ok(());
    };
    for table in inventory.tables() {
        for entry in table.entries() {
            let (status, reason) = status_of(entry.status(), suppressions);
            let record = [
                table.name().to_owned(),
                entry.column().to_owned(),
                entry.rule().code().to_owned(),
                entry.highest_confidence().code().to_owned(),
                entry.evidence().code().to_owned(),
                entry.files_confirmed.to_string(),
                entry.files_likely.to_string(),
                entry.files_possible.to_string(),
                entry.files_suppressed.to_string(),
                status.to_owned(),
                reason.unwrap_or_default().to_owned(),
                table.example_key().unwrap_or_default().to_owned(),
            ];
            write_record(out, &record).map_err(LakeScanError::Report)?;
        }
    }
    Ok(())
}

/// A strict RFC 4180 reader for the tests here and in `report`'s other
/// tests: records of fields, quotes undone.
#[cfg(test)]
pub(crate) fn parse(text: &str) -> Option<Vec<Vec<String>>> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut chars = text.chars().peekable();
    let mut quoted = false;
    let mut at_start = true;
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

#[cfg(test)]
mod tests {
    use super::{HEADER, parse, write_field, write_record};

    fn field(value: &str) -> String {
        let mut out = Vec::new();
        let _ = write_field(&mut out, value);
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn fields_are_quoted_only_when_rfc_4180_needs_it() {
        assert_eq!(field("lake/customers"), "lake/customers");
        assert_eq!(field(""), "");
        assert_eq!(field("a,b"), "\"a,b\"");
        assert_eq!(field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn control_and_bidi_characters_are_escaped_like_the_text_summary() {
        for (value, expected) in [
            // ESC: no terminal escape sequence survives `--inventory -`.
            ("lake/\u{1b}[31mred", "lake/\\u{001b}[31mred"),
            // A newline cannot forge a row, and needs no quoting.
            ("two\nlines", "two\\u{000a}lines"),
            ("cr\rhere", "cr\\u{000d}here"),
            // RIGHT-TO-LEFT OVERRIDE: a name cannot display as another.
            ("lake/\u{202e}lmth.exe", "lake/\\u{202e}lmth.exe"),
            ("\u{2066}iso\u{2069}", "\\u{2066}iso\\u{2069}"),
            // A backslash doubles, so a literal \u{001b} stays distinct
            // from an escaped ESC.
            ("lake/\\u{001b}", "lake/\\\\u{001b}"),
            // Other scripts and emoji pass through.
            ("lake/ünï/📦", "lake/ünï/📦"),
        ] {
            assert_eq!(field(value), expected, "{value:?}");
        }
    }

    #[test]
    fn formula_cells_are_neutralized_with_a_leading_quote() {
        for (value, expected) in [
            (
                "=HYPERLINK(\"http://x\")",
                "\"'=HYPERLINK(\"\"http://x\"\")\"",
            ),
            ("+1", "'+1"),
            ("-2+3", "'-2+3"),
            ("@SUM(A1)", "'@SUM(A1)"),
            // Escaped first, so a leading tab or CR no longer starts one.
            ("\tcmd", "\\u{0009}cmd"),
            ("\r=cmd", "\\u{000d}=cmd"),
            ("a=b", "a=b"),
            ("x-1", "x-1"),
        ] {
            assert_eq!(field(value), expected, "{value:?}");
        }
    }

    #[test]
    fn records_round_trip_through_a_strict_parser() {
        let rows = [
            HEADER.map(str::to_owned).to_vec(),
            vec![
                "lake/t,1".to_owned(),
                "a \"quoted\"\ncolumn".to_owned(),
                "=cmd".to_owned(),
                String::new(),
            ],
        ];
        let mut out = Vec::new();
        for row in &rows {
            let _ = write_record(&mut out, row);
        }
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("table,column,rule,highest_confidence,evidence,"));
        let parsed = parse(&text);
        let expected = vec![
            HEADER.map(str::to_owned).to_vec(),
            vec![
                "lake/t,1".to_owned(),
                "a \"quoted\"\\u{000a}column".to_owned(),
                "'=cmd".to_owned(),
                String::new(),
            ],
        ];
        assert_eq!(parsed, Some(expected));
        assert_eq!(parse("a\"b\r\n"), None, "a stray quote is rejected");
    }
}
