//! Escapes attacker-controlled text (object keys) for the text report.
//!
//! An S3 key is whatever the uploader named it; this crate never assumes it
//! is well-behaved. Written raw, a key could contain a control character
//! that moves the cursor or clears the screen, a newline that forges an
//! extra report line, or a bidirectional-override character that makes one
//! key *display* as a different one. [`write_escaped`] renders every
//! [`char::is_control`] character and the bidi-override/isolate controls
//! (`U+202A`–`U+202E`, `U+2066`–`U+2069`) as `\u{XXXX}` instead of passing
//! them through, and a backslash as `\\`, so a key that literally contains
//! `\u{001b}` cannot pass for an escaped ESC. Everything else — including
//! other scripts and emoji — passes through untouched. JSON output needs none of this: `serde_json` already
//! escapes control characters on its own.

use std::io::{self, Write};

/// `true` for exactly the characters [`write_escaped`] renders as
/// `\u{XXXX}` instead of passing through.
pub(super) fn is_escaped(c: char) -> bool {
    c.is_control() || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Writes `s` to `out`, escaping every character [`is_escaped`] flags as
/// `\u{XXXX}` (lowercase hex, e.g. `\u{000a}` for a newline) and passing
/// everything else through unchanged. Streams character by character
/// rather than building an escaped copy of `s` first.
pub(super) fn write_escaped<W: Write>(out: &mut W, s: &str) -> io::Result<()> {
    for c in s.chars() {
        if c == '\\' {
            out.write_all(b"\\\\")?;
        } else if is_escaped(c) {
            write!(out, "\\u{{{:04x}}}", u32::from(c))?;
        } else {
            write!(out, "{c}")?;
        }
    }
    Ok(())
}

/// `s` with every character [`is_escaped`] flags written as `\u{XXXX}`,
/// as [`write_escaped`] writes it: for the CSV inventory, whose cells are
/// built before they are quoted.
pub(super) fn escaped(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    // Writing to a `Vec` cannot fail, and only whole UTF-8 characters and
    // ASCII escapes are written, so the result is valid UTF-8.
    let _ = write_escaped(&mut out, s);
    String::from_utf8(out).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::write_escaped;

    fn escaped(s: &str) -> Result<String, io::Error> {
        let mut buf = Vec::new();
        write_escaped(&mut buf, s)?;
        String::from_utf8(buf).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }

    #[test]
    fn plain_ascii_passes_through_unchanged() -> Result<(), io::Error> {
        assert_eq!(escaped("reports/summary.csv")?, "reports/summary.csv");
        Ok(())
    }

    #[test]
    fn control_characters_are_escaped() -> Result<(), io::Error> {
        assert_eq!(escaped("\x1b")?, "\\u{001b}"); // ESC
        assert_eq!(escaped("\n")?, "\\u{000a}");
        assert_eq!(escaped("\r")?, "\\u{000d}");
        assert_eq!(escaped("\t")?, "\\u{0009}");
        assert_eq!(escaped("\0")?, "\\u{0000}");
        Ok(())
    }

    #[test]
    fn bidi_override_is_escaped() -> Result<(), io::Error> {
        // U+202E RIGHT-TO-LEFT OVERRIDE.
        assert_eq!(escaped("\u{202E}")?, "\\u{202e}");
        Ok(())
    }

    #[test]
    fn bidi_isolate_is_escaped() -> Result<(), io::Error> {
        // U+2066 LEFT-TO-RIGHT ISOLATE.
        assert_eq!(escaped("\u{2066}")?, "\\u{2066}");
        Ok(())
    }

    #[test]
    fn a_backslash_is_doubled_so_an_escape_cannot_be_forged() -> Result<(), io::Error> {
        // A literal backslash-u sequence in a key, and a real ESC, render
        // differently.
        assert_eq!(escaped("a\\u{001b}b")?, "a\\\\u{001b}b");
        assert_eq!(escaped("a\x1bb")?, "a\\u{001b}b");
        assert_eq!(escaped("C:\\dir")?, "C:\\\\dir");
        Ok(())
    }

    #[test]
    fn an_emoji_passes_through_untouched() -> Result<(), io::Error> {
        assert_eq!(escaped("📦")?, "📦");
        Ok(())
    }

    #[test]
    fn a_mixed_key_escapes_only_the_dangerous_characters() -> Result<(), io::Error> {
        let input = "evil\x1b[31mred\n\u{202E}gnp.exe\u{2069}.png";
        let output = escaped(input)?;
        assert_eq!(
            output,
            "evil\\u{001b}[31mred\\u{000a}\\u{202e}gnp.exe\\u{2069}.png"
        );
        Ok(())
    }
}
