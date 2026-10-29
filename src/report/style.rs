//! ANSI styling for `LakeScan`'s own words.
//!
//! A [`Style`] wraps fixed text the program itself wrote (section headings,
//! severity words, the `UNDOCUMENTED` and `documented` labels) in SGR
//! codes, or returns it unchanged when styling is off. It is never applied
//! to text derived from a bucket (keys, table and column names, reasons):
//! those go through `escape` only, so a hostile name cannot carry a control
//! sequence into the output, coloured or not.
//!
//! The policy is deliberately sparse: red appears once in a summary (the
//! worst severity, when it is high or critical) and once in the result
//! block (the exit 6 verdict); headings and `UNDOCUMENTED` are bold;
//! `documented` is green.

use crate::model::Severity;

const RESET: &str = "\x1b[0m";

/// Whether to wrap `LakeScan`'s own words in ANSI colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    on: bool,
}

impl Style {
    /// No codes at all: the bytes every non-terminal output has.
    pub const PLAIN: Self = Self { on: false };

    /// Styling on or off.
    #[must_use]
    pub const fn new(on: bool) -> Self {
        Self { on }
    }

    /// Whether this style emits any codes.
    #[must_use]
    pub const fn is_on(self) -> bool {
        self.on
    }

    fn paint(self, sgr: &str, text: &str) -> String {
        if self.on {
            format!("\x1b[{sgr}m{text}{RESET}")
        } else {
            text.to_owned()
        }
    }

    /// A section heading: bold.
    #[must_use]
    pub fn heading(self, text: &str) -> String {
        self.paint("1", text)
    }

    /// The worst severity's code (`high`) in the VERDICT section: red when
    /// it is high or critical, plain otherwise. The one red in a summary.
    #[must_use]
    pub fn worst_severity(self, severity: Severity) -> String {
        match severity {
            Severity::Critical => self.paint("1;31", severity.code()),
            Severity::High => self.paint("31", severity.code()),
            _ => severity.code().to_owned(),
        }
    }

    /// A failing result: bold red. Used for the exit 6 verdict only.
    #[must_use]
    pub fn alert(self, text: &str) -> String {
        self.paint("1;31", text)
    }

    /// The `UNDOCUMENTED` label: bold, not coloured.
    #[must_use]
    pub fn undocumented(self, text: &str) -> String {
        self.paint("1", text)
    }

    /// The `documented` label: green.
    #[must_use]
    pub fn documented(self, text: &str) -> String {
        self.paint("32", text)
    }
}
