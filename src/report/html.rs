//! The HTML report (`--html`): one self-contained file a privacy officer
//! can open, print or send.
//!
//! **Offline.** Inline CSS and JS only, the system font stack, no images,
//! and a Content-Security-Policy that forbids loading anything
//! (`default-src 'none'`), so opening the file makes no network request.
//!
//! **No computing.** Like the other formats, it renders what
//! [`Aggregates`] holds and the exit code the driver decided; the banner
//! and cards only pick which of those counts to show.
//!
//! **Hostile input.** Every bucket-derived string (keys, table and column
//! names, reasons, the prefix) is written through [`write_text`]: control
//! characters, bidi controls and backslashes are escaped as in the text
//! summary (see `escape`), then `& < > " '` become entities. The script
//! reads its data from a `<script type="application/json">` block in which
//! every `<` is written `\u003c`, and only ever sets `textContent`.
//!
//! **Without JavaScript**, every row is visible and the filter buttons are
//! hidden. The print stylesheet hides the filters and shows every row.

use std::io::Write;

use super::escape::is_escaped;
use super::rfc3339::format_rfc3339;
use super::text::{
    counted, dates_line, files, grouped, no_pii_line, not_examined_heading, not_examined_reasons,
    not_examined_status_line, out_of_scope_line, undocumented_counts, undocumented_split,
};
use super::{SAMPLING_METHOD, ScanInfo, TOOL_NAME, TOOL_VERSION, expiry_of, status_of};
use crate::aggregate::{
    Aggregates, MAX_ENTRIES, MAX_TABLES, PiiInventory, SampleDetail, Status, Table, TableStatus,
};
use crate::error::{ExitCode, LakeScanError};
use crate::model::{MAX_NOT_EXAMINED_EXAMPLES, NotScannedReason, RuleId, Severity};

macro_rules! w {
    ($out:expr, $($arg:tt)*) => {
        write!($out, $($arg)*).map_err(LakeScanError::Report)
    };
}
macro_rules! wl {
    ($out:expr, $($arg:tt)*) => {
        writeln!($out, $($arg)*).map_err(LakeScanError::Report)
    };
}

/// Writes `text` for an HTML text node or attribute value: control and
/// bidi characters as `\u{XXXX}`, a backslash as `\\`, then `& < > " '` as
/// entities. Everything else passes through.
pub(super) fn write_text<W: Write>(out: &mut W, text: &str) -> Result<(), LakeScanError> {
    let mut utf8 = [0_u8; 4];
    for c in text.chars() {
        let written = match c {
            '\\' => out.write_all(b"\\\\"),
            '&' => out.write_all(b"&amp;"),
            '<' => out.write_all(b"&lt;"),
            '>' => out.write_all(b"&gt;"),
            '"' => out.write_all(b"&quot;"),
            '\'' => out.write_all(b"&#39;"),
            c if is_escaped(c) => write!(out, "\\u{{{:04x}}}", u32::from(c)),
            c => out.write_all(c.encode_utf8(&mut utf8).as_bytes()),
        };
        written.map_err(LakeScanError::Report)?;
    }
    Ok(())
}

/// `value` as JSON for a `<script type="application/json">` block: every
/// `<` written `\u003c`, so no `</script>` (or `<!--`) can end the block.
/// A `<` can only appear inside a JSON string, where `\u003c` means the
/// same thing.
pub(super) fn script_json(value: &serde_json::Value) -> String {
    value.to_string().replace('<', "\\u003c")
}

/// `text` as the text summary escapes it (control and bidi characters,
/// backslashes), for data the script shows with `textContent`.
fn escaped_plain(text: &str) -> String {
    let mut out = Vec::new();
    let _ = super::escape::write_escaped(&mut out, text);
    String::from_utf8(out).unwrap_or_default()
}

const STYLE: &str = r#"
:root { color-scheme: light; --ink: #1f2328; --muted: #59636e; --line: #d1d9e0;
  --bad: #b42318; --bad-bg: #fef3f2; --ok: #1a7f37; --ok-bg: #effaf3; --warn-bg: #fff8e5; }
* { box-sizing: border-box; }
body { margin: 0 auto; max-width: 72rem; padding: 1.5rem; color: var(--ink);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
h1 { font-size: 1.6rem; margin: 0 0 .5rem; }
h2 { font-size: 1.25rem; margin: 2rem 0 .75rem; border-bottom: 1px solid var(--line); padding-bottom: .25rem; }
h3 { font-size: 1.05rem; margin: 1.5rem 0 .25rem; word-break: break-all; }
dl.meta { display: grid; grid-template-columns: max-content 1fr; gap: .15rem 1rem; margin: 0; }
dl.meta dt { color: var(--muted); }
dl.meta dd { margin: 0; word-break: break-all; }
code, .key { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .9em; }
.banner { border-radius: .5rem; padding: .75rem 1rem; margin: 1.25rem 0; border: 1px solid; }
.banner h2 { border: 0; margin: 0 0 .25rem; padding: 0; }
.banner.action { background: var(--bad-bg); border-color: var(--bad); }
.banner.ok { background: var(--ok-bg); border-color: var(--ok); }
.banner.warn { background: var(--warn-bg); border-color: #9a6700; }
.banner ul { margin: .25rem 0 0; padding-left: 1.25rem; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr)); gap: .75rem; margin: 1rem 0; }
.card { border: 1px solid var(--line); border-radius: .5rem; padding: .75rem 1rem; }
.card .value { font-size: 1.6rem; font-weight: 600; display: block; }
.card .label { color: var(--muted); }
table { border-collapse: collapse; width: 100%; margin: .25rem 0 1rem; }
th, td { text-align: left; padding: .35rem .6rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-weight: 600; background: #f6f8fa; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
td { word-break: break-word; }
.badge { display: inline-block; border-radius: 1rem; padding: 0 .55rem; font-size: .8rem; font-weight: 600; border: 1px solid; }
.badge.undocumented { color: var(--bad); background: var(--bad-bg); border-color: var(--bad); }
.badge.documented { color: var(--ok); background: var(--ok-bg); border-color: var(--ok); }
.note { color: var(--muted); }
.unknown { background: var(--warn-bg); border-radius: .35rem; padding: .35rem .6rem; display: inline-block; }
.filters { margin: .5rem 0 1rem; display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; }
.filters button { font: inherit; padding: .3rem .8rem; border: 1px solid var(--line); border-radius: .4rem; background: #fff; cursor: pointer; }
.filters button[aria-pressed="true"] { background: var(--ink); color: #fff; border-color: var(--ink); }
footer { margin-top: 2.5rem; padding-top: .75rem; border-top: 1px solid var(--line); color: var(--muted); }
@media print {
  .filters, #shown { display: none !important; }
  tr[hidden] { display: table-row !important; }
  body { max-width: none; padding: 0; }
  .banner, .card { break-inside: avoid; }
}
"#;

const SCRIPT: &str = r"
(function () {
  var data = JSON.parse(document.getElementById('lakescan-data').textContent);
  var filters = document.querySelector('.filters');
  if (!filters) { return; }
  var buttons = Array.prototype.slice.call(filters.querySelectorAll('button'));
  var rows = Array.prototype.slice.call(document.querySelectorAll('tr[data-status]'));
  var shown = document.getElementById('shown');
  function apply(filter) {
    var visible = 0;
    rows.forEach(function (row) {
      var hide = filter !== 'all' && row.getAttribute('data-status') !== filter;
      row.hidden = hide;
      if (!hide) { visible += 1; }
    });
    buttons.forEach(function (button) {
      button.setAttribute('aria-pressed', String(button.getAttribute('data-filter') === filter));
    });
    shown.textContent = 'Showing ' + visible + ' of ' + rows.length + ' PII columns in ' + data.target;
  }
  buttons.forEach(function (button) {
    var filter = button.getAttribute('data-filter');
    button.textContent = button.textContent + ' (' + data.rows[filter] + ')';
    button.addEventListener('click', function () { apply(filter); });
  });
  filters.hidden = false;
  apply('all');
})();
";

fn target(info: &ScanInfo) -> String {
    match &info.prefix {
        Some(prefix) => format!("s3://{}/{prefix}", info.bucket),
        None => format!("s3://{}", info.bucket),
    }
}

fn write_head<W: Write>(out: &mut W, info: &ScanInfo) -> Result<(), LakeScanError> {
    wl!(out, "<!DOCTYPE html>")?;
    wl!(out, "<html lang=\"en\">")?;
    wl!(out, "<head>")?;
    wl!(out, "<meta charset=\"utf-8\">")?;
    wl!(
        out,
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; \
         style-src 'unsafe-inline'; script-src 'unsafe-inline'\">"
    )?;
    wl!(out, "<meta name=\"referrer\" content=\"no-referrer\">")?;
    wl!(
        out,
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
    )?;
    w!(out, "<title>LakeScan report: ")?;
    write_text(out, &target(info))?;
    wl!(out, "</title>")?;
    wl!(out, "<style>{STYLE}</style>")?;
    wl!(out, "</head>")?;
    wl!(out, "<body>")
}

fn write_header<W: Write>(
    out: &mut W,
    info: &ScanInfo,
    code: ExitCode,
) -> Result<(), LakeScanError> {
    wl!(out, "<header>")?;
    wl!(out, "<h1>LakeScan report</h1>")?;
    wl!(out, "<dl class=\"meta\">")?;
    w!(out, "<dt>Bucket</dt><dd class=\"key\">")?;
    write_text(out, &info.bucket)?;
    wl!(out, "</dd>")?;
    w!(out, "<dt>Prefix</dt><dd class=\"key\">")?;
    match &info.prefix {
        Some(prefix) => write_text(out, prefix)?,
        None => w!(out, "(whole bucket)")?,
    }
    wl!(out, "</dd>")?;
    wl!(out, "<dt>LakeScan</dt><dd>{TOOL_NAME} {TOOL_VERSION}</dd>")?;
    w!(out, "<dt>Settings</dt><dd class=\"key\">")?;
    write_text(out, &info.settings.line(info.prefix.as_deref()))?;
    wl!(out, "</dd>")?;
    wl!(
        out,
        "<dt>Started</dt><dd class=\"timing\">{}</dd>",
        format_rfc3339(info.started_at)
    )?;
    wl!(
        out,
        "<dt>Elapsed</dt><dd class=\"timing\">{}.{:03}s</dd>",
        info.elapsed.as_secs(),
        info.elapsed.subsec_millis()
    )?;
    wl!(
        out,
        "<dt>Exit code</dt><dd><strong>{} ({})</strong>: {}</dd>",
        code.as_i32(),
        code.name(),
        code.meaning()
    )?;
    wl!(out, "</dl>")?;
    wl!(out, "</header>")
}

/// The banner: what needs doing, from the exit code, the coverage and the
/// inventory headline; or that nothing does.
fn write_banner<W: Write>(
    out: &mut W,
    aggregates: &Aggregates,
    code: ExitCode,
) -> Result<(), LakeScanError> {
    let mut items: Vec<String> = Vec::new();
    if let Some(coverage) = aggregates.coverage()
        && coverage.not_scanned_unsuppressed > 0
    {
        items.push(format!(
            "{} could not be content-scanned and no suppression documents {}: fix the cause \
             (see Files not scanned) or document {} with a <code>content-not-scanned</code> \
             suppression (exit code 6).",
            counted(
                coverage.not_scanned_unsuppressed,
                "Parquet file",
                "Parquet files"
            ),
            if coverage.not_scanned_unsuppressed == 1 {
                "it"
            } else {
                "them"
            },
            if coverage.not_scanned_unsuppressed == 1 {
                "it"
            } else {
                "them"
            },
        ));
    }
    if let Some(inventory) = aggregates.pii_inventory() {
        let summary = inventory.summary();
        if summary.undocumented > 0 {
            items.push(format!(
                "{} undocumented: document each with a suppression and its reason, or remove \
                 the data.",
                counted(summary.undocumented, "PII column is", "PII columns are"),
            ));
        }
    }
    if code == ExitCode::FindingsExceedThreshold {
        let worst = aggregates.worst_severity().map_or("none", Severity::code);
        items.push(format!(
            "Unsuppressed findings reached the failing threshold (worst severity: {worst}; exit \
             code 1)."
        ));
    }
    if items.is_empty() {
        wl!(out, "<section class=\"banner ok\" role=\"status\">")?;
        wl!(out, "<h2>No action needed</h2>")?;
        wl!(
            out,
            "<p>No undocumented PII column, no undocumented unscanned file, and no finding at \
             the failing threshold.</p>"
        )?;
    } else {
        wl!(out, "<section class=\"banner action\" role=\"alert\">")?;
        wl!(out, "<h2>Action needed</h2>")?;
        wl!(out, "<ul>")?;
        for item in &items {
            // Every item is fixed text and numbers; nothing bucket-derived.
            wl!(out, "<li>{item}</li>")?;
        }
        wl!(out, "</ul>")?;
    }
    wl!(out, "</section>")
}

/// A banner of its own when the inventory's caps dropped anything: every
/// table list and count below is then incomplete.
fn write_truncation<W: Write>(out: &mut W, aggregates: &Aggregates) -> Result<(), LakeScanError> {
    let Some(inventory) = aggregates.pii_inventory() else {
        return Ok(());
    };
    if !inventory.truncated() {
        return Ok(());
    }
    wl!(out, "<section class=\"banner warn\" role=\"alert\">")?;
    wl!(out, "<h2>PII inventory truncated</h2>")?;
    wl!(
        out,
        "<p>{} and {} were left out over the inventory's caps ({MAX_TABLES} tables, \
         {MAX_ENTRIES} entries), so the tables and counts below are incomplete. Scan narrower \
         prefixes to see them.</p>",
        files(inventory.left_out_files()),
        counted(inventory.left_out_findings(), "finding", "findings")
    )?;
    wl!(out, "</section>")
}

/// What was read and how: coverage, sampled inspection, and what was out
/// of scope.
fn write_coverage<W: Write>(out: &mut W, aggregates: &Aggregates) -> Result<(), LakeScanError> {
    let (Some(coverage), Some(scope), Some(content), Some(inventory)) = (
        aggregates.coverage(),
        aggregates.out_of_scope(),
        aggregates.content(),
        aggregates.pii_inventory(),
    ) else {
        return Ok(());
    };
    wl!(out, "<section id=\"coverage\">")?;
    wl!(out, "<h2>Coverage</h2>")?;
    wl!(out, "<ul>")?;
    wl!(
        out,
        "<li>{} of {} scanned; {} not scanned ({} documented).</li>",
        grouped(coverage.files_scanned),
        counted(coverage.files_eligible, "Parquet file", "Parquet files"),
        grouped(coverage.not_scanned_unsuppressed + coverage.not_scanned_suppressed),
        grouped(coverage.not_scanned_suppressed)
    )?;
    wl!(
        out,
        "<li>Inspection is {SAMPLING_METHOD}. No result proves a column holds no personal \
         data.</li>"
    )?;
    let total = content.not_examined_total();
    w!(
        out,
        "<li>Columns not examined: {} in {} of {}",
        grouped(total),
        files(content.files_with_columns_not_examined),
        counted(
            inventory.summary().tables_with_columns_not_examined,
            "table",
            "tables"
        )
    )?;
    if total > 0 {
        w!(
            out,
            " (<code>{}</code>): <span class=\"unknown\">PII unknown in them</span>",
            not_examined_reasons(|reason| content.not_examined(reason))
        )?;
    }
    wl!(out, ".</li>")?;
    w!(out, "<li>")?;
    match out_of_scope_line(scope) {
        Some(line) => write_text(out, &line)?,
        None => w!(out, "Not in scope for --pii: none by extension")?,
    }
    wl!(out, ".</li>")?;
    wl!(
        out,
        "<li>Sniffed and not Parquet: {}. Empty objects and folder markers: {}.</li>",
        grouped(scope.sniffed_not_parquet()),
        grouped(scope.empty())
    )?;
    wl!(out, "</ul>")?;
    wl!(out, "</section>")
}

fn write_cards<W: Write>(out: &mut W, aggregates: &Aggregates) -> Result<(), LakeScanError> {
    let (Some(inventory), Some(coverage)) = (aggregates.pii_inventory(), aggregates.coverage())
    else {
        return Ok(());
    };
    let summary = inventory.summary();
    let card = |out: &mut W, value: String, label: &str| {
        wl!(
            out,
            "<div class=\"card\"><span class=\"value\">{value}</span><span class=\"label\">{label}</span></div>"
        )
    };
    wl!(out, "<section class=\"cards\" aria-label=\"Headline\">")?;
    card(
        out,
        summary.tables_with_pii.to_string(),
        if summary.tables_with_pii == 1 {
            "table with PII"
        } else {
            "tables with PII"
        },
    )?;
    card(
        out,
        format!("{} / {}", summary.undocumented, summary.documented),
        "PII columns undocumented / documented",
    )?;
    card(
        out,
        coverage
            .percent
            .map_or_else(|| "n/a".to_owned(), |percent| format!("{percent:.1}%")),
        &format!(
            "coverage: {} of {} scanned",
            coverage.files_scanned,
            counted(coverage.files_eligible, "Parquet file", "Parquet files")
        ),
    )?;
    card(
        out,
        (coverage.not_scanned_unsuppressed + coverage.not_scanned_suppressed).to_string(),
        &format!(
            "files not scanned: {} undocumented, {} documented",
            coverage.not_scanned_unsuppressed, coverage.not_scanned_suppressed
        ),
    )?;
    wl!(out, "</section>")
}

/// One table's heading and its file counts.
fn write_table_heading<W: Write>(out: &mut W, table: &Table) -> Result<(), LakeScanError> {
    w!(out, "<h3 class=\"key\">")?;
    if table.name().is_empty() {
        w!(out, "(bucket root)")?;
    } else {
        write_text(out, table.name())?;
    }
    wl!(out, "</h3>")?;
    w!(
        out,
        "<p class=\"note\">{} scanned, {} not scanned",
        files(table.files_scanned),
        table.files_not_scanned()
    )?;
    if let Some(dates) = dates_line(table) {
        w!(out, "; {dates}")?;
    }
    if let Some(key) = table.example_key() {
        w!(out, ". Example: <span class=\"key\">")?;
        write_text(out, key)?;
        w!(out, "</span>")?;
    }
    wl!(out, "</p>")
}

/// One table's PII locations, in review order (undocumented first).
fn write_entries<W: Write>(
    out: &mut W,
    info: &ScanInfo,
    table: &Table,
) -> Result<(), LakeScanError> {
    wl!(out, "<table>")?;
    wl!(
        out,
        "<thead><tr><th scope=\"col\">Column</th><th scope=\"col\">Rule</th>\
         <th scope=\"col\">Highest confidence</th><th scope=\"col\">Evidence</th>\
         <th scope=\"col\">Files</th><th scope=\"col\">Status</th></tr></thead>"
    )?;
    wl!(out, "<tbody>")?;
    for entry in table.entries_for_review() {
        let documented = matches!(entry.status(), Status::Documented { .. });
        let status = if documented {
            "documented"
        } else {
            "undocumented"
        };
        w!(out, "<tr data-status=\"{status}\"><td class=\"key\">")?;
        write_text(out, entry.column())?;
        w!(
            out,
            "</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>",
            entry.rule().code(),
            entry.highest_confidence().code(),
            entry.evidence().code(),
            if documented {
                files(entry.files())
            } else {
                undocumented_counts(entry)
            }
        )?;
        match status_of(entry.status(), &info.suppressions) {
            (_, Some(reason)) => {
                w!(out, "<span class=\"badge documented\">Documented</span> ")?;
                if let Some(expires) = expiry_of(entry.status(), &info.suppressions) {
                    w!(out, "until {expires}: ")?;
                }
                write_text(out, reason)?;
            }
            (_, None) => {
                w!(
                    out,
                    "<span class=\"badge undocumented\">Undocumented</span>"
                )?;
            }
        }
        wl!(out, "</td></tr>")?;
    }
    wl!(out, "</tbody>")?;
    wl!(out, "</table>")?;
    Ok(())
}

fn write_inventory<W: Write>(
    out: &mut W,
    info: &ScanInfo,
    aggregates: &Aggregates,
) -> Result<(), LakeScanError> {
    let Some(inventory) = aggregates.pii_inventory() else {
        return Ok(());
    };
    let summary = inventory.summary();
    wl!(out, "<section id=\"inventory\">")?;
    wl!(out, "<h2>PII inventory</h2>")?;
    let action = if summary.undocumented > 0 {
        " Action needed on the undocumented."
    } else {
        ""
    };
    let gaps = if summary.tables_not_fully_scanned > 0 {
        format!(
            " ({} documented)",
            summary.tables_not_fully_scanned_documented
        )
    } else {
        String::new()
    };
    wl!(
        out,
        "<p>{} with PII, {}: {}, {} documented.{action} {} with files not \
         scanned{gaps}, {} with columns not examined.</p>",
        counted(summary.tables_with_pii, "table", "tables"),
        counted(summary.pii_columns, "PII column", "PII columns"),
        undocumented_split(&summary),
        summary.documented,
        counted(summary.tables_not_fully_scanned, "table", "tables"),
        summary.tables_with_columns_not_examined,
    )?;
    wl!(
        out,
        "<p class=\"note\">Tables are inferred from object paths. Documented means your team \
         recorded a reason: an operational exception, not a compliance approval.</p>"
    )?;
    wl!(
        out,
        "<div class=\"filters\" role=\"group\" aria-label=\"Show PII columns\" hidden>"
    )?;
    for (filter, label, pressed) in [
        ("all", "All", true),
        ("undocumented", "Undocumented", false),
        ("documented", "Documented", false),
    ] {
        wl!(
            out,
            "<button type=\"button\" data-filter=\"{filter}\" aria-pressed=\"{pressed}\">{label}</button>"
        )?;
    }
    wl!(out, "<span id=\"shown\" aria-live=\"polite\"></span>")?;
    wl!(out, "</div>")?;
    if inventory.tables().is_empty() {
        wl!(out, "<p>No Parquet files.</p>")?;
    }
    for table in inventory.tables() {
        write_table_heading(out, table)?;
        match table.status() {
            TableStatus::PiiFound => write_entries(out, info, table)?,
            TableStatus::NoPiiInScannedFiles => wl!(out, "<p>{}.</p>", no_pii_line(table))?,
            TableStatus::ColumnsNotExamined => wl!(
                out,
                "<p><span class=\"unknown\">{}.</span></p>",
                not_examined_status_line(table)
            )?,
            TableStatus::NotScanned => {
                wl!(
                    out,
                    "<p><span class=\"unknown\">Not scanned: PII unknown</span></p>"
                )?;
            }
        }
        if let Some(heading) = not_examined_heading(table) {
            wl!(out, "<p class=\"not-examined\">{heading}:</p>")?;
            wl!(out, "<ul class=\"not-examined\">")?;
            for example in inventory.not_examined_in(table.name()) {
                w!(out, "<li><span class=\"key\">")?;
                write_text(out, &example.column)?;
                wl!(out, "</span> (<code>{}</code>)</li>", example.reason.code())?;
            }
            wl!(out, "</ul>")?;
        }
    }
    if inventory.not_examined_examples_truncated() {
        wl!(
            out,
            "<p class=\"note\">Columns not examined: only the first {MAX_NOT_EXAMINED_EXAMPLES} \
             are listed (by table, column and reason); the counts include every one.</p>"
        )?;
    }
    if inventory.truncated() {
        wl!(
            out,
            "<p class=\"note\"><strong>Truncated:</strong> {} files and {} findings left out \
             over the caps ({MAX_TABLES} tables, {MAX_ENTRIES} entries); scan a narrower prefix \
             to see them.</p>",
            inventory.left_out_files(),
            inventory.left_out_findings()
        )?;
    }
    wl!(out, "</section>")
}

fn write_not_scanned<W: Write>(out: &mut W, aggregates: &Aggregates) -> Result<(), LakeScanError> {
    let Some(inventory) = aggregates.pii_inventory() else {
        return Ok(());
    };
    wl!(out, "<section id=\"not-scanned\">")?;
    wl!(out, "<h2>Files not scanned</h2>")?;
    let mut rows = 0;
    for table in inventory.tables() {
        for reason in NotScannedReason::ALL {
            let (undocumented, documented) = (
                table.not_scanned_unsuppressed(reason),
                table.not_scanned_suppressed(reason),
            );
            if undocumented + documented == 0 {
                continue;
            }
            if rows == 0 {
                wl!(out, "<table>")?;
                wl!(
                    out,
                    "<thead><tr><th scope=\"col\">Table</th><th scope=\"col\">Reason</th>\
                     <th scope=\"col\" class=\"num\">Undocumented</th>\
                     <th scope=\"col\" class=\"num\">Documented</th></tr></thead>"
                )?;
                wl!(out, "<tbody>")?;
            }
            rows += 1;
            w!(out, "<tr><td class=\"key\">")?;
            if table.name().is_empty() {
                w!(out, "(bucket root)")?;
            } else {
                write_text(out, table.name())?;
            }
            wl!(
                out,
                "</td><td><code>{}</code></td><td class=\"num\">{undocumented}</td><td class=\"num\">{documented}</td></tr>",
                reason.code()
            )?;
        }
    }
    if rows == 0 {
        wl!(out, "<p>Every Parquet file was scanned.</p>")?;
    } else {
        wl!(out, "</tbody>")?;
        wl!(out, "</table>")?;
        let samples = aggregates.samples_for(RuleId::ContentNotScanned);
        if !samples.is_empty() {
            wl!(
                out,
                "<p class=\"note\">Example files (undocumented ones; documented files are \
                 not listed):</p>"
            )?;
            wl!(out, "<ul>")?;
            for sample in samples {
                w!(out, "<li><span class=\"key\">")?;
                write_text(out, &sample.key)?;
                if sample.key_truncated {
                    w!(out, "…")?;
                }
                w!(out, "</span>")?;
                if let SampleDetail::NotScanned(reason) = sample.detail {
                    w!(out, " (<code>{}</code>)", reason.code())?;
                }
                wl!(out, "</li>")?;
            }
            wl!(out, "</ul>")?;
        }
    }
    wl!(out, "</section>")
}

fn write_metadata_findings<W: Write>(
    out: &mut W,
    aggregates: &Aggregates,
) -> Result<(), LakeScanError> {
    wl!(out, "<section id=\"findings\">")?;
    wl!(out, "<h2>Metadata findings</h2>")?;
    let rules: Vec<RuleId> = RuleId::ALL
        .into_iter()
        .filter(|rule| !rule.is_content())
        .filter(|&rule| {
            aggregates.suppressed(rule).count > 0
                || Severity::ALL
                    .into_iter()
                    .any(|severity| aggregates.matrix_cell(rule, severity).count > 0)
        })
        .collect();
    if rules.is_empty() {
        wl!(out, "<p>No metadata findings.</p>")?;
        return wl!(out, "</section>");
    }
    wl!(out, "<table>")?;
    w!(out, "<thead><tr><th scope=\"col\">Rule</th>")?;
    for severity in Severity::ALL.into_iter().rev() {
        w!(
            out,
            "<th scope=\"col\" class=\"num\">{}</th>",
            severity.code()
        )?;
    }
    wl!(
        out,
        "<th scope=\"col\" class=\"num\">Bytes</th><th scope=\"col\" class=\"num\">Suppressed</th></tr></thead>"
    )?;
    wl!(out, "<tbody>")?;
    for &rule in &rules {
        w!(
            out,
            "<tr><td><code>{}</code><br><span class=\"note\">{}</span></td>",
            rule.code(),
            rule.title()
        )?;
        let mut bytes: u64 = 0;
        for severity in Severity::ALL.into_iter().rev() {
            let cell = aggregates.matrix_cell(rule, severity);
            bytes = bytes.saturating_add(cell.bytes);
            w!(out, "<td class=\"num\">{}</td>", cell.count)?;
        }
        wl!(
            out,
            "<td class=\"num\">{bytes}</td><td class=\"num\">{}</td></tr>",
            aggregates.suppressed(rule).count
        )?;
    }
    wl!(out, "</tbody>")?;
    wl!(out, "</table>")?;
    for &rule in &rules {
        let samples = aggregates.samples_for(rule);
        if samples.is_empty() {
            continue;
        }
        wl!(out, "<details>")?;
        wl!(
            out,
            "<summary>Examples: <code>{}</code></summary>",
            rule.code()
        )?;
        wl!(out, "<ul>")?;
        for sample in samples {
            w!(out, "<li><span class=\"key\">")?;
            write_text(out, &sample.key)?;
            if sample.key_truncated {
                w!(out, "…")?;
            }
            wl!(
                out,
                "</span> ({}, {} bytes)</li>",
                sample.severity.map_or("?", Severity::code),
                sample.size
            )?;
        }
        wl!(out, "</ul>")?;
        wl!(out, "</details>")?;
    }
    wl!(out, "</section>")
}

fn write_data_and_script<W: Write>(
    out: &mut W,
    info: &ScanInfo,
    aggregates: &Aggregates,
) -> Result<(), LakeScanError> {
    let summary = aggregates.pii_inventory().map(PiiInventory::summary);
    let (undocumented, documented) =
        summary.map_or((0, 0), |summary| (summary.undocumented, summary.documented));
    let data = serde_json::json!({
        "target": escaped_plain(&target(info)),
        "rows": {
            "all": undocumented + documented,
            "undocumented": undocumented,
            "documented": documented,
        },
    });
    wl!(
        out,
        "<script type=\"application/json\" id=\"lakescan-data\">{}</script>",
        script_json(&data)
    )?;
    wl!(out, "<script>{SCRIPT}</script>")
}

/// Writes the HTML report for one run that ended with `code`.
pub(super) fn write<W: Write>(
    out: &mut W,
    info: &ScanInfo,
    aggregates: &Aggregates,
    code: ExitCode,
) -> Result<(), LakeScanError> {
    write_head(out, info)?;
    write_header(out, info, code)?;
    wl!(out, "<main>")?;
    write_banner(out, aggregates, code)?;
    write_truncation(out, aggregates)?;
    write_cards(out, aggregates)?;
    write_coverage(out, aggregates)?;
    write_inventory(out, info, aggregates)?;
    write_not_scanned(out, aggregates)?;
    write_metadata_findings(out, aggregates)?;
    wl!(out, "</main>")?;
    wl!(
        out,
        "<footer><p>Contains object and column names but no personal-data values; share \
         within your organization. Documented means your team recorded a reason; it is an \
         operational exception, not a compliance approval. LakeScan is a discovery aid, not a \
         compliance assessment: no finding does not prove there is no personal data. This is a \
         single file that loads nothing from the network.</p></footer>"
    )?;
    write_data_and_script(out, info, aggregates)?;
    wl!(out, "</body>")?;
    wl!(out, "</html>")
}

#[cfg(test)]
mod tests {
    use super::{script_json, write, write_text};
    use crate::error::ExitCode;
    use crate::report::fixture;

    fn text(value: &str) -> String {
        let mut out = Vec::new();
        let _ = write_text(&mut out, value);
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn hostile_strings_render_as_inert_text() {
        for (hostile, expected) in [
            (
                "<script>alert(1)</script>",
                "&lt;script&gt;alert(1)&lt;/script&gt;",
            ),
            ("</script>", "&lt;/script&gt;"),
            (
                "\"><img src=x onerror=alert(1)>",
                "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;",
            ),
            ("it's & \"so\"", "it&#39;s &amp; &quot;so&quot;"),
            ("esc\u{1b}[31m", "esc\\u{001b}[31m"),
            ("rtl\u{202e}gnp.exe", "rtl\\u{202e}gnp.exe"),
            ("back\\slash", "back\\\\slash"),
            ("ünï 📦", "ünï 📦"),
        ] {
            let rendered = text(hostile);
            assert_eq!(rendered, expected, "{hostile:?}");
            assert!(!rendered.contains('<') && !rendered.contains('>'));
            assert!(!rendered.contains('\u{1b}') && !rendered.contains('\u{202e}'));
        }
    }

    #[test]
    fn script_json_cannot_close_its_script_block() {
        let value =
            serde_json::json!({ "target": "s3://b/</script><script>alert(1)</script><!--" });
        let json = script_json(&value);
        assert!(!json.contains('<'), "{json}");
        assert!(json.contains("\\u003c/script>"));
        // Still the same JSON.
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).ok(),
            Some(value)
        );
    }

    #[test]
    fn matches_the_golden_file() -> Result<(), crate::error::LakeScanError> {
        let golden = include_str!("../../tests/golden/summary.html");
        let mut buf = Vec::new();
        write(
            &mut buf,
            &fixture::scan_info(),
            &fixture::aggregates(),
            ExitCode::FindingsExceedThreshold,
        )?;
        assert_eq!(String::from_utf8(buf).unwrap_or_default(), golden);
        Ok(())
    }

    #[test]
    fn the_page_loads_nothing_and_works_without_script() -> Result<(), crate::error::LakeScanError>
    {
        let mut buf = Vec::new();
        write(
            &mut buf,
            &fixture::scan_info(),
            &fixture::aggregates(),
            ExitCode::FindingsExceedThreshold,
        )?;
        let page = String::from_utf8(buf).unwrap_or_default();
        assert!(page.contains("default-src 'none'"));
        for loader in [
            "src=",
            "href=",
            "url(",
            "@import",
            "http://",
            "https://",
            "innerHTML",
        ] {
            assert!(!page.contains(loader), "{loader}");
        }
        // Filters start hidden, rows never: without script, all show.
        assert!(page.contains(
            "<div class=\"filters\" role=\"group\" aria-label=\"Show PII columns\" hidden>"
        ));
        assert!(!page.contains("<tr data-status=\"undocumented\" hidden"));
        assert!(page.contains("aria-pressed=\"true\""));
        assert!(page.contains("@media print"));
        assert!(page.contains("Not scanned: PII unknown"));
        assert!(page.contains("Action needed"));
        Ok(())
    }
}
