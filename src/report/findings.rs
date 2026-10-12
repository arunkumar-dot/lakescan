//! [`FindingsWriter`]: a JSON Lines stream of findings, written one record
//! at a time as the rule engine produces them.

use std::io::{self, Write};

use serde::Serialize;

use super::rfc3339::format_rfc3339;
use super::sink::Sink;
use crate::error::LakeScanError;
use crate::model::Finding;

/// One JSON Lines record: `{"key", "rule", "severity", "size",
/// "storage_class", "last_modified"}`, with the full, untruncated key —
/// unlike a summary [`crate::aggregate::Sample`], a findings-stream record
/// is written and forgotten immediately, so there is no bounded top-K
/// holding it in memory and therefore no reason to truncate it.
#[derive(Serialize)]
struct Record<'a> {
    key: &'a str,
    rule: &'static str,
    severity: &'static str,
    size: u64,
    storage_class: &'a str,
    last_modified: String,
}

impl<'a> Record<'a> {
    fn from_finding(finding: Finding<'a>) -> Self {
        Self {
            key: &finding.object.key,
            rule: finding.rule.code(),
            severity: finding.severity.code(),
            size: finding.object.size,
            storage_class: finding.object.storage_class.as_wire(),
            last_modified: format_rfc3339(finding.object.last_modified),
        }
    }
}

/// Writes one JSON Lines record per [`Finding`], as they arrive.
///
/// Buffered the same way [`super::write_summary`] is (a 64 KB
/// [`std::io::BufWriter`]) and subject to the same broken-pipe handling: once
/// the sink reports [`std::io::ErrorKind::BrokenPipe`], [`FindingsWriter::write`]
/// becomes a no-op that still returns `Ok`, and [`FindingsWriter::reader_closed`]
/// reports that it happened.
pub struct FindingsWriter<W: Write> {
    sink: Sink<W>,
}

impl<W: Write> FindingsWriter<W> {
    /// Wraps `out` in a 64 KB buffer.
    pub fn new(out: W) -> Self {
        Self {
            sink: Sink::new(out),
        }
    }

    /// Writes one JSON Lines record for `finding`.
    ///
    /// Does not flush: records accumulate in the 64 KB buffer until it
    /// fills or [`FindingsWriter::finish`] is called, so a long-running
    /// scan's findings stream does not do a syscall per finding.
    ///
    /// # Errors
    /// Returns [`LakeScanError::Report`] for any write error other than a
    /// broken pipe, which is swallowed (see [`FindingsWriter::reader_closed`]).
    pub fn write(&mut self, finding: Finding<'_>) -> Result<(), LakeScanError> {
        if self.sink.is_broken() {
            return Ok(());
        }
        let record = Record::from_finding(finding);
        serde_json::to_writer(&mut self.sink, &record).map_err(json_err_to_report)?;
        writeln!(self.sink).map_err(LakeScanError::Report)
    }

    /// `true` if the underlying sink has reported a broken pipe: the
    /// reader went away, and every write since has been a silent no-op.
    #[must_use]
    pub fn reader_closed(&self) -> bool {
        self.sink.is_broken()
    }

    /// Flushes the buffer and consumes this writer.
    ///
    /// Explicit, rather than relying on [`std::io::BufWriter`]'s `Drop`,
    /// which would discard a flush error silently.
    ///
    /// # Errors
    /// Returns [`LakeScanError::Report`] for any flush error other than a
    /// broken pipe.
    pub fn finish(mut self) -> Result<(), LakeScanError> {
        self.sink.flush().map_err(LakeScanError::Report)
    }
}

/// Converts a `serde_json` error into the I/O error [`LakeScanError::Report`]
/// wraps. Every field in [`Record`] is a plain string, integer, or an
/// already-escaped RFC 3339 string, so the only way `serde_json` can fail
/// to serialize one is if the underlying writer itself failed; this
/// recovers that underlying [`io::Error`] rather than losing it behind a
/// generic serialization error.
fn json_err_to_report(err: serde_json::Error) -> LakeScanError {
    LakeScanError::Report(io::Error::from(err))
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::FindingsWriter;
    use crate::model::{Finding, ObjectMeta, RuleId, Severity, StorageClass};

    fn object(key: &str) -> ObjectMeta {
        ObjectMeta {
            key: key.to_owned(),
            size: 42,
            last_modified: SystemTime::UNIX_EPOCH,
            etag: "etag".to_owned(),
            storage_class: StorageClass::Standard,
        }
    }

    #[test]
    fn every_line_parses_and_fields_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let obj = object("reports/summary.csv");
        let finding = Finding {
            rule: RuleId::SensitiveKey,
            severity: Severity::High,
            object: &obj,
        };

        let mut buf = Vec::new();
        {
            let mut writer = FindingsWriter::new(&mut buf);
            writer.write(finding)?;
            writer.finish()?;
        }

        let text = String::from_utf8(buf)?;
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1);

        let value: serde_json::Value = serde_json::from_str(lines.first().copied().unwrap_or(""))?;
        assert_eq!(
            value.get("key"),
            Some(&serde_json::json!("reports/summary.csv"))
        );
        assert_eq!(value.get("rule"), Some(&serde_json::json!("sensitive-key")));
        assert_eq!(value.get("severity"), Some(&serde_json::json!("high")));
        assert_eq!(value.get("size"), Some(&serde_json::json!(42)));
        assert_eq!(
            value.get("storage_class"),
            Some(&serde_json::json!("STANDARD"))
        );
        assert_eq!(
            value.get("last_modified"),
            Some(&serde_json::json!("1970-01-01T00:00:00Z"))
        );
        Ok(())
    }

    #[test]
    fn a_key_with_dangerous_characters_produces_exactly_one_line_and_round_trips()
    -> Result<(), Box<dyn std::error::Error>> {
        let tricky_key = "a\nb\"c\\d\x1be\0f";
        let obj = object(tricky_key);
        let finding = Finding {
            rule: RuleId::ZeroByteObject,
            severity: Severity::Info,
            object: &obj,
        };

        let mut buf = Vec::new();
        {
            let mut writer = FindingsWriter::new(&mut buf);
            writer.write(finding)?;
            writer.finish()?;
        }

        let text = String::from_utf8(buf)?;
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "a dangerous key must not split the record across lines"
        );

        let value: serde_json::Value = serde_json::from_str(lines.first().copied().unwrap_or(""))?;
        assert_eq!(value.get("key"), Some(&serde_json::json!(tricky_key)));
        Ok(())
    }

    #[test]
    fn multiple_findings_each_produce_their_own_line() -> Result<(), Box<dyn std::error::Error>> {
        let obj_a = object("a");
        let obj_b = object("b");

        let mut buf = Vec::new();
        {
            let mut writer = FindingsWriter::new(&mut buf);
            writer.write(Finding {
                rule: RuleId::SensitiveKey,
                severity: Severity::High,
                object: &obj_a,
            })?;
            writer.write(Finding {
                rule: RuleId::ZeroByteObject,
                severity: Severity::Info,
                object: &obj_b,
            })?;
            writer.finish()?;
        }

        let text = String::from_utf8(buf)?;
        assert_eq!(text.lines().count(), 2);
        Ok(())
    }
}
