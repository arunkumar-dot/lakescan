//! [`PiiInventory`]: where personal data lives, by table and column, with
//! whether each location is documented by a suppression. This is the
//! report a privacy team hands to an auditor.
//!
//! **Tables.** Every Parquet file belongs to a table, named by
//! [`table_of`]: a heuristic over the key, since a listing knows nothing
//! about catalogs. One entry is kept per `(table, column path, PII rule)`.
//!
//! **Bounded and mergeable.** At most [`MAX_TABLES`] tables and
//! [`MAX_ENTRIES`] entries (across all tables) are held. Over a cap, the
//! lexicographically smallest are kept: tables by name, entries by `(table,
//! column, rule)`. The kept set is therefore the same whatever order files
//! arrive in and however partial inventories are merged, and every kept
//! count is exact: a table or entry once dropped can never come back,
//! because something smaller is always held in its place. What is left out
//! is counted exactly too, as files and findings.
//!
//! **Columns not examined.** Each table counts, exactly and per reason, the
//! columns that could hold personal data but were not examined in its
//! scanned files (see [`crate::content::FileStats::not_examined`]), and
//! the files that had any. A table with no PII found and such columns is
//! [`TableStatus::ColumnsNotExamined`], never clean. Across the inventory,
//! the [`MAX_NOT_EXAMINED_EXAMPLES`] smallest `(table, column, reason)`
//! are kept as examples, the same whatever order files arrive in; whether
//! any was left out is recorded too.
//!
//! **Memory.** Table names and example keys are cut to 1 KiB, column paths
//! are at most [`MAX_COLUMN_BYTES`], and entries live inside their table,
//! so a table name is stored once. [`PiiInventory::MAX_BYTES`] bounds the
//! total, growth slack included: 17,849,440 bytes (~17.0 MiB) at the caps.

use std::time::SystemTime;

use crate::content::FileOutcome;
use crate::model::{
    ColumnDetail, Confidence, Evidence, MAX_COLUMN_BYTES, MAX_NOT_EXAMINED_EXAMPLES, NotExamined,
    NotExaminedReason, NotScannedReason, RuleId, offer_not_examined, truncate_str,
};

/// The most tables held. A power of two, so the table list's capacity
/// never exceeds it (see [`PiiInventory::MAX_BYTES`]).
pub const MAX_TABLES: usize = 4096;

/// The most `(table, column, rule)` entries held, across all tables.
pub const MAX_ENTRIES: usize = 16_384;

/// Table names and example keys longer than this are cut (at a `char`
/// boundary). S3 keys are at most 1,024 bytes, so this never bites there.
const MAX_NAME_BYTES: usize = 1024;

const NUM_REASONS: usize = NotScannedReason::ALL.len();

const NUM_NOT_EXAMINED: usize = NotExaminedReason::ALL.len();

const _: () = assert!(MAX_TABLES.is_power_of_two());

/// The table a Parquet object belongs to, from its key alone:
///
/// 1. take the directory part, up to the last `/` (none: the bucket root,
///    `""`);
/// 2. remove trailing Hive-style partition segments, `name=value` with a
///    non-empty name (`dt=2026-01-01`, then `region=in`, ...);
/// 3. then remove one trailing `data` segment (Iceberg keeps data files
///    under `<table>/data/`).
///
/// So `lake/customers/dt=2026-01-01/region=in/part-0.parquet`,
/// `lake/customers/data/part-0.parquet` and `lake/customers/part-0.parquet`
/// (a Delta table root) are all table `lake/customers`. A heuristic: a
/// directory named `data` that is not Iceberg's is folded into its parent
/// all the same.
#[must_use]
pub fn table_of(key: &str) -> &str {
    let mut table = split_last(key).0;
    loop {
        let (parent, last) = split_last(table);
        if table.is_empty() || !is_partition(last) {
            break;
        }
        table = parent;
    }
    let (parent, last) = split_last(table);
    if last == "data" { parent } else { table }
}

/// `(everything before the last '/', everything after it)`; with no `/`,
/// `("", path)`.
fn split_last(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(at) => (
            path.get(..at).unwrap_or_default(),
            path.get(at + 1..).unwrap_or_default(),
        ),
        None => ("", path),
    }
}

/// Whether `segment` is a Hive-style partition, `name=value`.
fn is_partition(segment: &str) -> bool {
    segment
        .split_once('=')
        .is_some_and(|(name, _)| !name.is_empty())
}

/// What an inventory entry's findings rest on: sampled values for at least
/// one file, or only ever the column's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceKind {
    /// At least one file's finding rests on validated values.
    Values,
    /// Every file's finding rests on the column name alone.
    ColumnName,
}

impl EvidenceKind {
    /// `"values"` or `"column-name"`, as a finding's `evidence` field.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Values => "values",
            Self::ColumnName => "column-name",
        }
    }
}

/// Whether an inventory entry is documented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// At least one file's finding was not suppressed.
    Undocumented,
    /// Every file's finding was suppressed; `entry` is the index (in
    /// `--config` file order) of the first suppression entry that matched
    /// any of them, whose reason documents the location.
    Documented {
        /// The suppression entry's index.
        entry: usize,
    },
}

/// What can be said about a table's personal data. Never more than was
/// read: a table none of whose files was scanned is
/// [`TableStatus::NotScanned`], not clean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableStatus {
    /// At least one PII location was found.
    PiiFound,
    /// Files were scanned and none held PII, and every column that could
    /// hold it was examined; other files may not have been scanned (see
    /// [`Table::files_not_scanned`]).
    NoPiiInScannedFiles,
    /// Files were scanned and no PII was found in the columns examined,
    /// but some columns that could hold it were not examined (see
    /// [`Table::not_examined`]): whether they hold PII is unknown.
    ColumnsNotExamined,
    /// No file was scanned: whether it holds PII is unknown.
    NotScanned,
}

impl TableStatus {
    /// `"pii_found"`, `"no_pii_in_scanned_files"`, `"columns_not_examined"`
    /// or `"not_scanned"`.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::PiiFound => "pii_found",
            Self::NoPiiInScannedFiles => "no_pii_in_scanned_files",
            Self::ColumnsNotExamined => "columns_not_examined",
            Self::NotScanned => "not_scanned",
        }
    }
}

/// A column not examined, in its table: one of the inventory's examples.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NotExaminedAt {
    /// The table, cut to 1 KiB.
    pub table: String,
    /// The column and why.
    pub column: NotExamined,
}

/// The inventory's headline counts, over the tables and entries held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InventorySummary {
    /// Tables with at least one PII location.
    pub tables_with_pii: u64,
    /// PII locations, `(table, column, rule)`.
    pub pii_columns: u64,
    /// Of those, the undocumented: the action items.
    pub undocumented: u64,
    /// Of the undocumented, those whose highest confidence is `confirmed`.
    pub undocumented_confirmed: u64,
    /// Of the undocumented, those whose highest confidence is `likely`.
    pub undocumented_likely: u64,
    /// Of the undocumented, those whose highest confidence is `possible`.
    pub undocumented_possible: u64,
    /// Of those, the documented.
    pub documented: u64,
    /// Tables with at least one file not scanned.
    pub tables_not_fully_scanned: u64,
    /// Of those, the tables whose every unscanned file is documented (its
    /// `content-not-scanned` finding suppressed).
    pub tables_not_fully_scanned_documented: u64,
    /// Tables with at least one column not examined in a scanned file.
    pub tables_with_columns_not_examined: u64,
}

/// One `(table, column path, PII rule)` location and what was found there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryEntry {
    column: String,
    rule: RuleId,
    /// Files whose unsuppressed finding is `confirmed`.
    pub files_confirmed: u64,
    /// Files whose unsuppressed finding is `likely`.
    pub files_likely: u64,
    /// Files whose unsuppressed finding is `possible`.
    pub files_possible: u64,
    /// Files whose finding was suppressed.
    pub files_suppressed: u64,
    highest: Confidence,
    by_values: bool,
    suppression: Option<usize>,
}

impl InventoryEntry {
    fn new(column: &str, rule: RuleId) -> Self {
        Self {
            column: truncate_str(column, MAX_COLUMN_BYTES).to_owned(),
            rule,
            files_confirmed: 0,
            files_likely: 0,
            files_possible: 0,
            files_suppressed: 0,
            highest: Confidence::Possible,
            by_values: false,
            suppression: None,
        }
    }

    /// The column path.
    #[must_use]
    pub fn column(&self) -> &str {
        &self.column
    }

    /// The PII rule.
    #[must_use]
    pub fn rule(&self) -> RuleId {
        self.rule
    }

    /// The highest confidence of any file's finding, suppressed or not.
    #[must_use]
    pub fn highest_confidence(&self) -> Confidence {
        self.highest
    }

    /// What the findings rest on.
    #[must_use]
    pub fn evidence(&self) -> EvidenceKind {
        if self.by_values {
            EvidenceKind::Values
        } else {
            EvidenceKind::ColumnName
        }
    }

    /// Documented when every file's finding was suppressed.
    #[must_use]
    pub fn status(&self) -> Status {
        match self.suppression {
            Some(entry) if self.unsuppressed() == 0 => Status::Documented { entry },
            _ => Status::Undocumented,
        }
    }

    fn unsuppressed(&self) -> u64 {
        self.files_confirmed
            .saturating_add(self.files_likely)
            .saturating_add(self.files_possible)
    }

    /// Every file counted here, suppressed or not.
    #[must_use]
    pub fn files(&self) -> u64 {
        self.findings()
    }

    /// Every file counted here, suppressed or not.
    fn findings(&self) -> u64 {
        self.unsuppressed().saturating_add(self.files_suppressed)
    }

    fn record(&mut self, detail: &ColumnDetail, suppression: Option<usize>) {
        let count = match (suppression, detail.confidence) {
            (Some(_), _) => &mut self.files_suppressed,
            (None, Confidence::Confirmed) => &mut self.files_confirmed,
            (None, Confidence::Likely) => &mut self.files_likely,
            (None, Confidence::Possible) => &mut self.files_possible,
        };
        *count = count.saturating_add(1);
        self.highest = self.highest.max(detail.confidence);
        self.by_values |= matches!(detail.evidence, Evidence::Values { .. });
        self.suppression = min_index(self.suppression, suppression);
    }

    fn merge(&mut self, other: &Self) {
        let add = |total: &mut u64, n: u64| *total = total.saturating_add(n);
        add(&mut self.files_confirmed, other.files_confirmed);
        add(&mut self.files_likely, other.files_likely);
        add(&mut self.files_possible, other.files_possible);
        add(&mut self.files_suppressed, other.files_suppressed);
        self.highest = self.highest.max(other.highest);
        self.by_values |= other.by_values;
        self.suppression = min_index(self.suppression, other.suppression);
    }

    /// Where this entry sorts within its table.
    fn sort_key(&self) -> (&str, usize) {
        (&self.column, self.rule.index())
    }
}

fn min_index(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// One table: its files and the PII locations in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    name: String,
    example_key: Option<String>,
    /// Parquet files in this table.
    pub files_eligible: u64,
    /// Files content-scanned, whole or partially.
    pub files_scanned: u64,
    /// Per reason (indexed by [`NotScannedReason::index`]): files not
    /// scanned, `[unsuppressed, suppressed]`.
    not_scanned: [[u64; 2]; NUM_REASONS],
    /// The earliest and latest `last_modified` of the table's files,
    /// scanned or not.
    dates: Option<(SystemTime, SystemTime)>,
    /// Columns not examined in scanned files, per reason (indexed by
    /// [`NotExaminedReason::index`]), counted once per file.
    not_examined: [u64; NUM_NOT_EXAMINED],
    /// Scanned files with at least one column not examined.
    files_with_columns_not_examined: u64,
    /// Sorted by `(column, rule)`.
    entries: Vec<InventoryEntry>,
}

impl Table {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            example_key: None,
            files_eligible: 0,
            files_scanned: 0,
            not_scanned: [[0; 2]; NUM_REASONS],
            dates: None,
            not_examined: [0; NUM_NOT_EXAMINED],
            files_with_columns_not_examined: 0,
            entries: Vec::new(),
        }
    }

    /// Columns not examined for `reason` in this table's scanned files,
    /// counted once per file they appear in.
    #[must_use]
    pub fn not_examined(&self, reason: NotExaminedReason) -> u64 {
        self.not_examined.get(reason.index()).copied().unwrap_or(0)
    }

    /// Columns not examined, for any reason, counted once per file.
    #[must_use]
    pub fn not_examined_total(&self) -> u64 {
        self.not_examined
            .iter()
            .fold(0, |total, &n| total.saturating_add(n))
    }

    /// Scanned files with at least one column not examined.
    #[must_use]
    pub fn files_with_columns_not_examined(&self) -> u64 {
        self.files_with_columns_not_examined
    }

    /// The `last_modified` of the table's oldest and newest Parquet files,
    /// scanned or not; `None` before any file.
    #[must_use]
    pub fn file_dates(&self) -> Option<(SystemTime, SystemTime)> {
        self.dates
    }

    fn offer_dates(&mut self, oldest: SystemTime, newest: SystemTime) {
        self.dates = Some(match self.dates {
            Some((low, high)) => (low.min(oldest), high.max(newest)),
            None => (oldest, newest),
        });
    }

    /// The table's name; `""` for the bucket root.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The lexicographically smallest key in this table with a PII
    /// finding (suppressed or not), cut to 1 KiB; `None` if no file had
    /// one.
    #[must_use]
    pub fn example_key(&self) -> Option<&str> {
        self.example_key.as_deref()
    }

    /// Files not scanned for `reason` whose `content-not-scanned` finding
    /// was not suppressed.
    #[must_use]
    pub fn not_scanned_unsuppressed(&self, reason: NotScannedReason) -> u64 {
        self.not_scanned
            .get(reason.index())
            .map_or(0, |&[unsuppressed, _]| unsuppressed)
    }

    /// Files not scanned for `reason` whose `content-not-scanned` finding
    /// was suppressed.
    #[must_use]
    pub fn not_scanned_suppressed(&self, reason: NotScannedReason) -> u64 {
        self.not_scanned
            .get(reason.index())
            .map_or(0, |&[_, suppressed]| suppressed)
    }

    /// Files not scanned, for any reason, suppressed or not.
    #[must_use]
    pub fn files_not_scanned(&self) -> u64 {
        self.files_eligible.saturating_sub(self.files_scanned)
    }

    /// The PII locations held for this table, sorted by column, then rule.
    #[must_use]
    pub fn entries(&self) -> &[InventoryEntry] {
        &self.entries
    }

    /// The PII locations in review order: undocumented first (the action
    /// items), then documented, each group by column, then rule.
    #[must_use]
    pub fn entries_for_review(&self) -> Vec<&InventoryEntry> {
        let (mut undocumented, documented): (Vec<_>, Vec<_>) = self
            .entries
            .iter()
            .partition(|entry| entry.status() == Status::Undocumented);
        undocumented.extend(documented);
        undocumented
    }

    /// What can be said about this table's personal data.
    #[must_use]
    pub fn status(&self) -> TableStatus {
        if !self.entries.is_empty() {
            TableStatus::PiiFound
        } else if self.files_scanned == 0 {
            TableStatus::NotScanned
        } else if self.files_with_columns_not_examined > 0 {
            TableStatus::ColumnsNotExamined
        } else {
            TableStatus::NoPiiInScannedFiles
        }
    }

    fn findings(&self) -> u64 {
        self.entries
            .iter()
            .fold(0, |total, entry| total.saturating_add(entry.findings()))
    }

    fn offer_example(&mut self, key: &str) {
        let key = truncate_str(key, MAX_NAME_BYTES);
        if self.example_key.as_deref().is_none_or(|held| key < held) {
            self.example_key = Some(key.to_owned());
        }
    }

    /// Adds `other`'s file counts and example key (not its entries).
    fn merge_files(&mut self, other: &Self) {
        let add = |total: &mut u64, n: u64| *total = total.saturating_add(n);
        add(&mut self.files_eligible, other.files_eligible);
        add(&mut self.files_scanned, other.files_scanned);
        add(
            &mut self.files_with_columns_not_examined,
            other.files_with_columns_not_examined,
        );
        for (mine, theirs) in self.not_examined.iter_mut().zip(other.not_examined) {
            add(mine, theirs);
        }
        for (mine, theirs) in self.not_scanned.iter_mut().zip(other.not_scanned) {
            for (count, n) in mine.iter_mut().zip(theirs) {
                add(count, n);
            }
        }
        if let Some(key) = &other.example_key {
            self.offer_example(key);
        }
        if let Some((oldest, newest)) = other.dates {
            self.offer_dates(oldest, newest);
        }
    }

    fn heap_bytes(&self) -> usize {
        self.name.capacity()
            + self.example_key.as_ref().map_or(0, String::capacity)
            + self.entries.capacity() * size_of::<InventoryEntry>()
            + self
                .entries
                .iter()
                .map(|entry| entry.column.capacity())
                .sum::<usize>()
    }
}

/// The per-table PII inventory; see this module's doc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiiInventory {
    /// Sorted by name; at most `max_tables`.
    tables: Vec<Table>,
    /// Entries held across all tables; at most `max_entries`.
    entry_count: usize,
    max_tables: usize,
    max_entries: usize,
    left_out_files: u64,
    left_out_findings: u64,
    /// The smallest columns not examined, sorted; at most
    /// [`MAX_NOT_EXAMINED_EXAMPLES`].
    not_examined: Vec<NotExaminedAt>,
    /// Whether a distinct column not examined was left out of the
    /// examples.
    not_examined_left_out: bool,
}

impl Default for PiiInventory {
    fn default() -> Self {
        Self::with_caps(MAX_TABLES, MAX_ENTRIES)
    }
}

impl PiiInventory {
    /// This inventory's worst-case size: itself, every table (with a name
    /// and an example key of 1 KiB), and every entry (with a 256-byte
    /// column path). Entry lists grow by doubling from 4 and shrink when
    /// an entry is dropped, so a table of `n` entries reserves at most
    /// `max(4, 2n)` slots: `4 × MAX_TABLES + 2 × MAX_ENTRIES` in all.
    ///
    /// Plus the not-examined examples: a list that grows by doubling to at
    /// most twice [`MAX_NOT_EXAMINED_EXAMPLES`] slots, each example with a
    /// 1 KiB table name and a 256-byte column path.
    pub const MAX_BYTES: usize = size_of::<Self>()
        + MAX_TABLES * (size_of::<Table>() + 2 * MAX_NAME_BYTES)
        + (4 * MAX_TABLES + 2 * MAX_ENTRIES) * size_of::<InventoryEntry>()
        + MAX_ENTRIES * MAX_COLUMN_BYTES
        + 2 * MAX_NOT_EXAMINED_EXAMPLES * size_of::<NotExaminedAt>()
        + MAX_NOT_EXAMINED_EXAMPLES * (MAX_NAME_BYTES + MAX_COLUMN_BYTES);

    /// An empty inventory holding at most `max_tables` tables and
    /// `max_entries` entries. Smaller caps than the defaults are for tests.
    #[must_use]
    pub(super) fn with_caps(max_tables: usize, max_entries: usize) -> Self {
        Self {
            tables: Vec::new(),
            entry_count: 0,
            max_tables,
            max_entries,
            left_out_files: 0,
            left_out_findings: 0,
            not_examined: Vec::new(),
            not_examined_left_out: false,
        }
    }

    /// The columns not examined kept as examples, sorted by table, column
    /// and reason: at most [`MAX_NOT_EXAMINED_EXAMPLES`].
    #[must_use]
    pub fn not_examined_examples(&self) -> &[NotExaminedAt] {
        &self.not_examined
    }

    /// The examples kept for table `name`.
    pub fn not_examined_in<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a NotExamined> {
        self.not_examined
            .iter()
            .filter(move |at| at.table == name)
            .map(|at| &at.column)
    }

    /// Whether a column not examined was left out of the examples (more
    /// than [`MAX_NOT_EXAMINED_EXAMPLES`] distinct ones, or one in a table
    /// left out over [`MAX_TABLES`]). The counts stay exact.
    #[must_use]
    pub fn not_examined_examples_truncated(&self) -> bool {
        self.not_examined_left_out
    }

    /// The tables held, sorted by name.
    #[must_use]
    pub fn tables(&self) -> &[Table] {
        &self.tables
    }

    /// Files in tables left out over [`MAX_TABLES`].
    #[must_use]
    pub fn left_out_files(&self) -> u64 {
        self.left_out_files
    }

    /// Findings in tables or entries left out over a cap.
    #[must_use]
    pub fn left_out_findings(&self) -> u64 {
        self.left_out_findings
    }

    /// Whether a cap left anything out.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.left_out_files > 0 || self.left_out_findings > 0
    }

    /// The headline counts over the tables and entries held.
    #[must_use]
    pub fn summary(&self) -> InventorySummary {
        let mut summary = InventorySummary::default();
        for table in &self.tables {
            if !table.entries.is_empty() {
                summary.tables_with_pii += 1;
            }
            if table.files_with_columns_not_examined > 0 {
                summary.tables_with_columns_not_examined += 1;
            }
            if table.files_not_scanned() > 0 {
                summary.tables_not_fully_scanned += 1;
                let undocumented = NotScannedReason::ALL
                    .iter()
                    .any(|&reason| table.not_scanned_unsuppressed(reason) > 0);
                if !undocumented {
                    summary.tables_not_fully_scanned_documented += 1;
                }
            }
            for entry in &table.entries {
                summary.pii_columns += 1;
                match entry.status() {
                    Status::Undocumented => {
                        summary.undocumented += 1;
                        match entry.highest_confidence() {
                            Confidence::Confirmed => summary.undocumented_confirmed += 1,
                            Confidence::Likely => summary.undocumented_likely += 1,
                            Confidence::Possible => summary.undocumented_possible += 1,
                        }
                    }
                    Status::Documented { .. } => summary.documented += 1,
                }
            }
        }
        summary
    }

    /// Records one eligible Parquet file, last modified at `modified`: how
    /// its scan ended and, if it was not scanned, whether its
    /// `content-not-scanned` finding was suppressed. A sniffed object that
    /// is not Parquet belongs to no table and is ignored.
    pub(super) fn observe_file(
        &mut self,
        key: &str,
        outcome: FileOutcome,
        suppressed: bool,
        modified: SystemTime,
    ) {
        if outcome == FileOutcome::SniffedNotParquet {
            return;
        }
        let Some(table) = self
            .table_index(table_of(key))
            .and_then(|index| self.tables.get_mut(index))
        else {
            self.left_out_files = self.left_out_files.saturating_add(1);
            return;
        };
        let add = |total: &mut u64| *total = total.saturating_add(1);
        add(&mut table.files_eligible);
        table.offer_dates(modified, modified);
        match outcome {
            FileOutcome::SniffedNotParquet => {}
            FileOutcome::ScannedWhole | FileOutcome::ScannedPartially => {
                add(&mut table.files_scanned);
            }
            FileOutcome::NotScanned(reason) => {
                if let Some(count) = table
                    .not_scanned
                    .get_mut(reason.index())
                    .and_then(|pair| pair.get_mut(usize::from(suppressed)))
                {
                    add(count);
                }
            }
        }
    }

    /// Records the columns not examined in the scanned file `key` (already
    /// recorded with [`Self::observe_file`]): `counts` per reason, and
    /// `examples`, the file's smallest.
    pub(super) fn observe_not_examined(
        &mut self,
        key: &str,
        counts: &[u64; NUM_NOT_EXAMINED],
        examples: &[NotExamined],
    ) {
        if counts.iter().all(|&n| n == 0) {
            return;
        }
        let name = truncate_str(table_of(key), MAX_NAME_BYTES);
        let Ok(index) = self
            .tables
            .binary_search_by(|table| table.name.as_str().cmp(name))
        else {
            // The table was left out over the cap: so are its columns.
            self.not_examined_left_out |= !examples.is_empty();
            return;
        };
        if let Some(table) = self.tables.get_mut(index) {
            for (total, &n) in table.not_examined.iter_mut().zip(counts) {
                *total = total.saturating_add(n);
            }
            table.files_with_columns_not_examined =
                table.files_with_columns_not_examined.saturating_add(1);
        }
        for column in examples {
            let at = NotExaminedAt {
                table: name.to_owned(),
                column: column.clone(),
            };
            self.not_examined_left_out |= offer_not_examined(&mut self.not_examined, &at);
        }
    }

    /// Records one PII finding in the file `key`: suppressed by the entry
    /// at index `suppression`, or not.
    pub(super) fn observe_pii(
        &mut self,
        key: &str,
        rule: RuleId,
        detail: &ColumnDetail,
        suppression: Option<usize>,
    ) {
        let Some(table) = self.table_index(table_of(key)) else {
            self.left_out_findings = self.left_out_findings.saturating_add(1);
            return;
        };
        if let Some(held) = self.tables.get_mut(table) {
            held.offer_example(key);
        }
        match self.entry_index(table, &detail.column, rule) {
            Some(entry) => entry.record(detail, suppression),
            None => self.left_out_findings = self.left_out_findings.saturating_add(1),
        }
    }

    /// Folds `other` in. Order-independent and exact: see this module's
    /// doc.
    pub(super) fn merge(&mut self, other: Self) {
        self.left_out_files = self.left_out_files.saturating_add(other.left_out_files);
        self.left_out_findings = self
            .left_out_findings
            .saturating_add(other.left_out_findings);
        self.not_examined_left_out |= other.not_examined_left_out;
        for at in &other.not_examined {
            self.not_examined_left_out |= offer_not_examined(&mut self.not_examined, at);
        }
        for theirs in other.tables {
            let Some(table) = self.table_index(&theirs.name) else {
                self.left_out_files = self.left_out_files.saturating_add(theirs.files_eligible);
                self.left_out_findings = self.left_out_findings.saturating_add(theirs.findings());
                continue;
            };
            if let Some(mine) = self.tables.get_mut(table) {
                mine.merge_files(&theirs);
            }
            for entry in &theirs.entries {
                match self.entry_index(table, &entry.column, entry.rule) {
                    Some(mine) => mine.merge(entry),
                    None => {
                        self.left_out_findings =
                            self.left_out_findings.saturating_add(entry.findings());
                    }
                }
            }
        }
    }

    /// The heap held: the table list, and every table's name, example key
    /// and entries.
    #[must_use]
    pub(super) fn heap_bytes(&self) -> usize {
        self.tables.capacity() * size_of::<Table>()
            + self.tables.iter().map(Table::heap_bytes).sum::<usize>()
            + self.not_examined.capacity() * size_of::<NotExaminedAt>()
            + self
                .not_examined
                .iter()
                .map(|at| at.table.capacity() + at.column.column.capacity())
                .sum::<usize>()
    }

    /// The index of table `name` (cut to 1 KiB), added if it is new and
    /// fits under the cap, evicting the largest table if `name` is
    /// smaller; `None` if it does not fit.
    fn table_index(&mut self, name: &str) -> Option<usize> {
        let name = truncate_str(name, MAX_NAME_BYTES);
        let at = match self
            .tables
            .binary_search_by(|table| table.name.as_str().cmp(name))
        {
            Ok(index) => return Some(index),
            Err(at) => at,
        };
        if self.tables.len() >= self.max_tables {
            if self
                .tables
                .last()
                .is_none_or(|last| last.name.as_str() <= name)
            {
                return None;
            }
            // The evicted table sorts after `name`, so `at` still holds.
            if let Some(evicted) = self.tables.pop() {
                let before = self.not_examined.len();
                self.not_examined.retain(|at| at.table != evicted.name);
                self.not_examined_left_out |= self.not_examined.len() < before;
                self.entry_count = self.entry_count.saturating_sub(evicted.entries.len());
                self.left_out_files = self.left_out_files.saturating_add(evicted.files_eligible);
                self.left_out_findings = self.left_out_findings.saturating_add(evicted.findings());
            }
        }
        self.tables.insert(at, Table::new(name));
        Some(at)
    }

    /// The entry `(column, rule)` in table `table`, added if it is new and
    /// fits under the cap, evicting the largest entry held if this one is
    /// smaller; `None` if it does not fit.
    fn entry_index(
        &mut self,
        table: usize,
        column: &str,
        rule: RuleId,
    ) -> Option<&mut InventoryEntry> {
        let column = truncate_str(column, MAX_COLUMN_BYTES);
        let key = (column, rule.index());
        let at = match self
            .tables
            .get(table)?
            .entries
            .binary_search_by(|entry| entry.sort_key().cmp(&key))
        {
            Ok(index) => return self.tables.get_mut(table)?.entries.get_mut(index),
            Err(at) => at,
        };
        if self.entry_count >= self.max_entries {
            // The largest entry held: the last one of the last table that
            // has any (tables are sorted by name).
            let (last_table, last_entry) =
                self.tables
                    .iter()
                    .enumerate()
                    .rev()
                    .find_map(|(index, held)| {
                        held.entries.len().checked_sub(1).map(|last| (index, last))
                    })?;
            let larger = last_table > table
                || (last_table == table
                    && self
                        .tables
                        .get(table)
                        .and_then(|held| held.entries.get(last_entry))
                        .is_some_and(|entry| entry.sort_key() > key));
            if !larger {
                return None;
            }
            // Within `table`, the evicted entry sorts after `at`, so `at`
            // still holds.
            let held = self.tables.get_mut(last_table)?;
            if last_entry < held.entries.len() {
                let evicted = held.entries.remove(last_entry);
                held.entries.shrink_to_fit();
                self.entry_count = self.entry_count.saturating_sub(1);
                self.left_out_findings = self.left_out_findings.saturating_add(evicted.findings());
            }
        }
        let entries = &mut self.tables.get_mut(table)?.entries;
        entries.insert(at, InventoryEntry::new(column, rule));
        self.entry_count += 1;
        entries.get_mut(at)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EvidenceKind, InventorySummary, PiiInventory, Status, Table, TableStatus, table_of,
    };
    use std::time::{Duration, SystemTime};

    use crate::content::FileOutcome;
    use crate::model::{
        ColumnDetail, Confidence, Evidence, MAX_NOT_EXAMINED_EXAMPLES, NotExamined,
        NotExaminedReason, NotScannedReason, RuleId,
    };

    /// `days` after the epoch.
    fn at(days: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(days * 86_400)
    }

    #[test]
    fn tables_are_named_by_the_key_s_directory_without_partitions_or_data() {
        for (key, table) in [
            // Hive partitions, one and nested.
            (
                "lake/customers/dt=2026-01-01/part-0.parquet",
                "lake/customers",
            ),
            (
                "lake/customers/dt=2026-01-01/region=in/part-0.parquet",
                "lake/customers",
            ),
            (
                "warehouse/db.db/t/year=2026/month=01/day=02/f.parquet",
                "warehouse/db.db/t",
            ),
            // Iceberg: data/, with and without partitions.
            ("lake/events/data/part-0.parquet", "lake/events"),
            (
                "lake/events/data/dt=2026-01-01/part-0.parquet",
                "lake/events",
            ),
            // Only one trailing data/ goes, and only after partitions.
            ("lake/data/data/f.parquet", "lake/data"),
            ("lake/data/x/f.parquet", "lake/data/x"),
            // A Delta table root, and the bucket root.
            ("lake/orders/part-00000-1a2b.snappy.parquet", "lake/orders"),
            ("orders.parquet", ""),
            ("dt=2026-01-01/f.parquet", ""),
            ("data/f.parquet", ""),
            ("/f.parquet", ""),
            // Odd characters: not partitions unless name=value with a name.
            ("lake/=x/f.parquet", "lake/=x"),
            ("lake/a=/f.parquet", "lake"),
            ("lake/t/a=b=c/f.parquet", "lake/t"),
            ("lake//dt=1/f.parquet", "lake/"),
            ("lake/t/", "lake/t"),
            ("lake/ünï cödé/ä=1/f.parquet", "lake/ünï cödé"),
            ("lake/\u{1b}[31m/f.parquet", "lake/\u{1b}[31m"),
        ] {
            assert_eq!(table_of(key), table, "{key:?}");
        }
    }

    fn detail(column: &str, confidence: Confidence) -> ColumnDetail {
        let evidence = if confidence == Confidence::Possible {
            Evidence::ColumnName
        } else {
            Evidence::Values {
                matched: 40,
                sampled: 50,
            }
        };
        ColumnDetail::new(column, confidence, evidence)
    }

    #[test]
    fn entries_count_files_by_confidence_and_say_whether_they_are_documented() {
        let mut inventory = PiiInventory::default();
        let email = detail("email", Confidence::Confirmed);
        inventory.observe_pii("t/dt=1/a.parquet", RuleId::PiiEmail, &email, None);
        inventory.observe_pii(
            "t/dt=2/b.parquet",
            RuleId::PiiEmail,
            &detail("email", Confidence::Likely),
            None,
        );
        inventory.observe_pii("t/dt=3/c.parquet", RuleId::PiiEmail, &email, Some(4));
        let dob = ColumnDetail::new("dob", Confidence::Likely, Evidence::ColumnName);
        inventory.observe_pii("t/dt=2/b.parquet", RuleId::PiiDateOfBirth, &dob, Some(7));
        inventory.observe_pii("t/dt=1/a.parquet", RuleId::PiiDateOfBirth, &dob, Some(2));
        inventory.observe_file("t/dt=1/a.parquet", FileOutcome::ScannedWhole, false, at(5));
        inventory.observe_file(
            "t/dt=9/z.parquet",
            FileOutcome::NotScanned(NotScannedReason::Unreadable),
            true,
            at(1),
        );
        inventory.observe_file(
            "t/dt=9/y.parquet",
            FileOutcome::NotScanned(NotScannedReason::Unreadable),
            false,
            at(9),
        );
        // Sniffed and not Parquet: no table, no file.
        inventory.observe_file("t/dt=9/x", FileOutcome::SniffedNotParquet, false, at(20));

        let [table] = inventory.tables() else {
            unreachable!("one table: {inventory:?}");
        };
        assert_eq!(table.name(), "t");
        assert_eq!(table.example_key(), Some("t/dt=1/a.parquet"));
        assert_eq!((table.files_eligible, table.files_scanned), (3, 1));
        // Every file's date counts, scanned or not.
        assert_eq!(table.file_dates(), Some((at(1), at(9))));
        assert_eq!(table.files_not_scanned(), 2);
        assert_eq!(
            table.not_scanned_suppressed(NotScannedReason::Unreadable),
            1
        );
        assert_eq!(
            table.not_scanned_unsuppressed(NotScannedReason::Unreadable),
            1
        );

        let [dob, email] = table.entries() else {
            unreachable!("two entries: {table:?}");
        };
        // Sorted by column: dob, then email.
        assert_eq!((dob.column(), dob.rule()), ("dob", RuleId::PiiDateOfBirth));
        assert_eq!(dob.files_suppressed, 2);
        assert_eq!(dob.status(), Status::Documented { entry: 2 });
        assert_eq!(dob.evidence(), EvidenceKind::ColumnName);
        assert_eq!(dob.highest_confidence(), Confidence::Likely);
        assert_eq!(
            (
                email.files_confirmed,
                email.files_likely,
                email.files_possible
            ),
            (1, 1, 0)
        );
        assert_eq!(email.files_suppressed, 1);
        assert_eq!(email.status(), Status::Undocumented);
        assert_eq!(email.evidence(), EvidenceKind::Values);
        assert_eq!(email.highest_confidence(), Confidence::Confirmed);
        assert!(!inventory.truncated());
    }

    /// One observation, replayed in many orders and splits.
    #[derive(Debug, Clone)]
    enum Event {
        File(String, FileOutcome, bool, SystemTime),
        Pii(String, RuleId, &'static str, Confidence, Option<usize>),
    }

    fn apply(inventory: &mut PiiInventory, event: &Event) {
        match event {
            Event::File(key, outcome, suppressed, modified) => {
                inventory.observe_file(key, *outcome, *suppressed, *modified);
            }
            Event::Pii(key, rule, column, confidence, suppression) => {
                inventory.observe_pii(key, *rule, &detail(column, *confidence), *suppression);
            }
        }
    }

    /// 12 tables, each with 3 files, findings in up to 3 columns.
    fn events() -> Vec<Event> {
        let mut out = Vec::new();
        let columns = ["email", "phone", "pan"];
        let rules = [RuleId::PiiEmail, RuleId::PiiPhone, RuleId::PiiInPan];
        for table in 0..12_usize {
            for file in 0..3_usize {
                let key = format!("t{table:02}/dt={file}/f.parquet");
                let outcome = if (table + file) % 5 == 0 {
                    FileOutcome::NotScanned(NotScannedReason::Unreadable)
                } else {
                    FileOutcome::ScannedWhole
                };
                let modified = at(u64::try_from((table * 7 + file * 3) % 11).unwrap_or(0));
                out.push(Event::File(key.clone(), outcome, file == 1, modified));
                for (index, (column, rule)) in columns.iter().zip(rules).enumerate() {
                    if (table + index) % 3 == 0 || file == 2 {
                        let confidence = [
                            Confidence::Confirmed,
                            Confidence::Likely,
                            Confidence::Possible,
                        ]
                        .get((file + index) % 3)
                        .copied()
                        .unwrap_or(Confidence::Possible);
                        let suppression = (table % 4 == 0).then_some(table + file);
                        out.push(Event::Pii(
                            key.clone(),
                            rule,
                            column,
                            confidence,
                            suppression,
                        ));
                    }
                }
            }
        }
        out
    }

    /// A deterministic permutation: a small LCG drives a Fisher-Yates
    /// shuffle.
    fn shuffled(mut events: Vec<Event>, seed: u64) -> Vec<Event> {
        let mut state = seed;
        for i in (1..events.len()).rev() {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let j = usize::try_from((state >> 33) % u64::try_from(i + 1).unwrap_or(1)).unwrap_or(0);
            events.swap(i, j);
        }
        events
    }

    fn observe(events: &[Event], max_tables: usize, max_entries: usize) -> PiiInventory {
        let mut inventory = PiiInventory::with_caps(max_tables, max_entries);
        for event in events {
            apply(&mut inventory, event);
        }
        inventory
    }

    fn totals(inventory: &PiiInventory) -> (u64, u64) {
        let files = inventory
            .tables()
            .iter()
            .fold(0, |n, table| n + table.files_eligible);
        let findings = inventory
            .tables()
            .iter()
            .fold(0, |n, table| n + table.findings());
        (
            files + inventory.left_out_files(),
            findings + inventory.left_out_findings(),
        )
    }

    #[test]
    fn any_order_and_any_merge_give_the_same_inventory_under_every_cap() {
        let events = events();
        let files = u64::try_from(
            events
                .iter()
                .filter(|e| matches!(e, Event::File(..)))
                .count(),
        )
        .unwrap_or(0);
        let findings = u64::try_from(events.len()).unwrap_or(0) - files;
        let all_entries: usize = observe(&events, 64, 1024)
            .tables()
            .iter()
            .map(|table| table.entries().len())
            .sum();
        for (max_tables, max_entries) in [(64, 1024), (5, 1024), (64, 7), (5, 7), (1, 1), (0, 0)] {
            let forward = observe(&events, max_tables, max_entries);
            assert_eq!(totals(&forward), (files, findings), "conserved");
            assert_eq!(
                forward.truncated(),
                max_tables < 12 || max_entries < all_entries,
                "{max_tables} {max_entries}"
            );
            for seed in 0..20 {
                let order = shuffled(events.clone(), seed);
                assert_eq!(
                    observe(&order, max_tables, max_entries),
                    forward,
                    "seed {seed}, caps {max_tables}/{max_entries}"
                );
                // Split in three, merged in two different orders.
                let third = order.len() / 3;
                let (a, rest) = order.split_at(third);
                let (b, c) = rest.split_at(third);
                let parts = [a, b, c].map(|part| observe(part, max_tables, max_entries));
                let [pa, pb, pc] = parts.clone();
                let mut left = pa;
                left.merge(pb);
                left.merge(pc);
                let [pa, pb, pc] = parts;
                let mut right = pc;
                let mut middle = pb;
                middle.merge(pa);
                right.merge(middle);
                assert_eq!(
                    left, forward,
                    "seed {seed}, caps {max_tables}/{max_entries}"
                );
                assert_eq!(
                    right, forward,
                    "seed {seed}, caps {max_tables}/{max_entries}"
                );
            }
        }
    }

    /// A small deterministic generator for the randomized test below.
    struct Lcg(u64);

    impl Lcg {
        fn below(&mut self, n: usize) -> usize {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            usize::try_from((self.0 >> 33) % u64::try_from(n.max(1)).unwrap_or(1)).unwrap_or(0)
        }
    }

    /// Property: under tiny caps, any observation order split into any
    /// number of parts at random points, each observed alone and merged
    /// back in a random order, equals one pass over everything: the same
    /// tables, entries, counts, file dates and left-out counts.
    #[test]
    fn random_orders_and_random_splits_merged_back_equal_a_single_pass() {
        let events = events();
        let mut rng = Lcg(0x5eed);
        for (max_tables, max_entries) in [(3, 4), (2, 9), (7, 2), (1, 1), (12, 100), (0, 3)] {
            let single = observe(&events, max_tables, max_entries);
            assert_eq!(
                totals(&single),
                totals(&observe(&events, 64, 1024)),
                "conserved, caps {max_tables}/{max_entries}"
            );
            for round in 0..40 {
                let order = shuffled(events.clone(), 1000 + round);
                let parts = 1 + rng.below(6);
                let mut cuts: Vec<usize> = (1..parts).map(|_| rng.below(order.len() + 1)).collect();
                cuts.sort_unstable();
                let mut pieces = Vec::new();
                let mut from = 0;
                for cut in cuts.into_iter().chain([order.len()]) {
                    pieces.push(observe(
                        order.get(from..cut).unwrap_or_default(),
                        max_tables,
                        max_entries,
                    ));
                    from = cut;
                }
                // Merge in a random order.
                let mut merged = PiiInventory::with_caps(max_tables, max_entries);
                while !pieces.is_empty() {
                    merged.merge(pieces.swap_remove(rng.below(pieces.len())));
                }
                assert_eq!(
                    merged, single,
                    "round {round}, {parts} parts, caps {max_tables}/{max_entries}"
                );
                assert_eq!(
                    (merged.left_out_files(), merged.left_out_findings()),
                    (single.left_out_files(), single.left_out_findings())
                );
            }
        }
    }

    #[test]
    fn over_a_cap_the_smallest_tables_and_entries_are_kept_and_the_rest_counted() {
        let events = events();
        let full = observe(&events, 64, 1024);
        let capped = observe(&events, 5, 9);
        // The 5 smallest table names.
        let names: Vec<&str> = capped.tables().iter().map(super::Table::name).collect();
        assert_eq!(names, ["t00", "t01", "t02", "t03", "t04"]);
        // The 9 smallest (table, column, rule) entries of those tables.
        let mut all: Vec<(String, String, usize)> = full
            .tables()
            .iter()
            .take(5)
            .flat_map(|table| {
                table.entries().iter().map(|entry| {
                    (
                        table.name().to_owned(),
                        entry.column().to_owned(),
                        entry.rule().index(),
                    )
                })
            })
            .collect();
        all.truncate(9);
        let kept: Vec<(String, String, usize)> = capped
            .tables()
            .iter()
            .flat_map(|table| {
                table.entries().iter().map(|entry| {
                    (
                        table.name().to_owned(),
                        entry.column().to_owned(),
                        entry.rule().index(),
                    )
                })
            })
            .collect();
        assert_eq!(kept, all);
        // Every kept count is exact: the same as with no cap.
        for table in capped.tables() {
            let uncapped = full.tables().iter().find(|t| t.name() == table.name());
            assert_eq!(
                uncapped.map(|t| (t.files_eligible, t.files_scanned, t.example_key())),
                Some((
                    table.files_eligible,
                    table.files_scanned,
                    table.example_key()
                ))
            );
            for entry in table.entries() {
                let same = uncapped.and_then(|t| {
                    t.entries()
                        .iter()
                        .find(|e| e.sort_key() == entry.sort_key())
                });
                assert_eq!(same, Some(entry));
            }
        }
        assert!(capped.left_out_files() > 0 && capped.left_out_findings() > 0);
    }

    #[test]
    fn tables_say_only_what_was_read_and_the_headline_counts_the_action_items() {
        let mut inventory = PiiInventory::default();
        let unreadable = FileOutcome::NotScanned(NotScannedReason::Unreadable);
        // Never read: unknown, not clean.
        inventory.observe_file("dark/a.parquet", unreadable, false, at(0));
        // Partly read, nothing found.
        inventory.observe_file("half/a.parquet", FileOutcome::ScannedWhole, false, at(0));
        inventory.observe_file("half/b.parquet", unreadable, true, at(0));
        // Fully read, nothing found.
        inventory.observe_file("clean/a.parquet", FileOutcome::ScannedWhole, false, at(0));
        // PII: two undocumented locations and one documented.
        inventory.observe_file("pii/a.parquet", FileOutcome::ScannedWhole, false, at(0));
        for (column, suppression) in [("zip", None), ("email", Some(0)), ("phone", None)] {
            let detail = detail(column, Confidence::Confirmed);
            inventory.observe_pii("pii/a.parquet", RuleId::PiiEmail, &detail, suppression);
        }

        let statuses: Vec<(&str, TableStatus)> = inventory
            .tables()
            .iter()
            .map(|t| (t.name(), t.status()))
            .collect();
        assert_eq!(
            statuses,
            [
                ("clean", TableStatus::NoPiiInScannedFiles),
                ("dark", TableStatus::NotScanned),
                ("half", TableStatus::NoPiiInScannedFiles),
                ("pii", TableStatus::PiiFound),
            ]
        );
        assert_eq!(
            inventory.summary(),
            InventorySummary {
                tables_with_pii: 1,
                pii_columns: 3,
                undocumented: 2,
                // Both undocumented locations are confirmed.
                undocumented_confirmed: 2,
                undocumented_likely: 0,
                undocumented_possible: 0,
                documented: 1,
                tables_not_fully_scanned: 2,
                // half's unscanned file is documented; dark's is not.
                tables_not_fully_scanned_documented: 1,
                tables_with_columns_not_examined: 0,
            }
        );
        // Review order: undocumented first, then documented, each by
        // column.
        let pii = inventory
            .tables()
            .last()
            .ok_or(())
            .map(Table::entries_for_review);
        let order: Vec<&str> = pii
            .unwrap_or_default()
            .iter()
            .map(|entry| entry.column())
            .collect();
        assert_eq!(order, ["phone", "zip", "email"]);
    }

    #[test]
    fn long_names_are_cut_and_the_inventory_stays_within_max_bytes() {
        let mut inventory = PiiInventory::default();
        let column = "c".repeat(400);
        for table in 0..(super::MAX_TABLES + 300) {
            let key = format!("{table:05}{}/{}", "t".repeat(1100), "k".repeat(200));
            inventory.observe_file(&key, FileOutcome::ScannedWhole, false, at(0));
            for n in 0..5 {
                let detail = ColumnDetail::new(
                    &format!("{n}{column}"),
                    Confidence::Confirmed,
                    Evidence::ColumnName,
                );
                inventory.observe_pii(&key, RuleId::PiiEmail, &detail, None);
            }
        }
        assert_eq!(inventory.tables().len(), super::MAX_TABLES);
        assert_eq!(
            inventory
                .tables()
                .iter()
                .map(|table| table.entries().len())
                .sum::<usize>(),
            super::MAX_ENTRIES
        );
        assert!(inventory.tables().iter().all(|t| t.name().len() <= 1024));
        assert!(inventory.truncated());
        assert!(
            size_of::<PiiInventory>() + inventory.heap_bytes() <= PiiInventory::MAX_BYTES,
            "{} + {} > {}",
            size_of::<PiiInventory>(),
            inventory.heap_bytes(),
            PiiInventory::MAX_BYTES
        );
    }

    fn not_examined(column: &str, reason: NotExaminedReason) -> NotExamined {
        NotExamined::new(column, reason)
    }

    /// Counts per reason for `examples`, one each.
    fn counts(examples: &[NotExamined]) -> [u64; NotExaminedReason::ALL.len()] {
        let mut counts = [0; NotExaminedReason::ALL.len()];
        for example in examples {
            if let Some(count) = counts.get_mut(example.reason.index()) {
                *count += 1;
            }
        }
        counts
    }

    /// The experiment's FHIR practitioners, before M12: every column that
    /// could hold PII was skipped, and the table read "no PII detected".
    /// Now it says the columns were not examined, and which.
    #[test]
    fn a_table_with_columns_not_examined_is_never_clean() {
        let mut inventory = PiiInventory::default();
        let skipped = [
            not_examined("telecom.value", NotExaminedReason::PageTooLarge),
            not_examined("phone_number", NotExaminedReason::UnsupportedType),
        ];
        for key in ["fhir/practitioner/a.parquet", "fhir/practitioner/b.parquet"] {
            inventory.observe_file(key, FileOutcome::ScannedWhole, false, at(0));
            inventory.observe_not_examined(key, &counts(&skipped), &skipped);
        }
        inventory.observe_file("clean/a.parquet", FileOutcome::ScannedWhole, false, at(0));
        inventory.observe_not_examined("clean/a.parquet", &counts(&[]), &[]);
        let status: Vec<(&str, TableStatus)> = inventory
            .tables()
            .iter()
            .map(|table| (table.name(), table.status()))
            .collect();
        assert_eq!(
            status,
            [
                ("clean", TableStatus::NoPiiInScannedFiles),
                ("fhir/practitioner", TableStatus::ColumnsNotExamined),
            ]
        );
        let table = inventory.tables().last().ok_or(()).cloned();
        let table = table.unwrap_or_else(|()| Table::new("missing"));
        assert_eq!(table.not_examined_total(), 4);
        assert_eq!(table.not_examined(NotExaminedReason::PageTooLarge), 2);
        assert_eq!(table.files_with_columns_not_examined(), 2);
        assert_eq!(
            TableStatus::ColumnsNotExamined.code(),
            "columns_not_examined"
        );
        // Examples are distinct columns, sorted.
        let examples: Vec<&str> = inventory
            .not_examined_in("fhir/practitioner")
            .map(|example| example.column.as_str())
            .collect();
        assert_eq!(examples, ["phone_number", "telecom.value"]);
        assert!(!inventory.not_examined_examples_truncated());
        assert_eq!(inventory.summary().tables_with_columns_not_examined, 1);
        // PII found elsewhere in the table wins the status, and the
        // columns not examined stay listed.
        let detail = detail("email", Confidence::Confirmed);
        inventory.observe_pii(
            "fhir/practitioner/a.parquet",
            RuleId::PiiEmail,
            &detail,
            None,
        );
        let table = inventory.tables().last().map(Table::status);
        assert_eq!(table, Some(TableStatus::PiiFound));
        assert_eq!(inventory.not_examined_in("fhir/practitioner").count(), 2);
    }

    /// The examples are the smallest across the inventory, the same in any
    /// order and however inventories are merged; leaving any out is
    /// recorded, and the counts stay exact.
    #[test]
    fn not_examined_examples_are_the_smallest_in_any_order() {
        let n = MAX_NOT_EXAMINED_EXAMPLES + 10;
        let files: Vec<(String, Vec<NotExamined>)> = (0..n)
            .map(|i| {
                (
                    format!("t{:03}/f.parquet", i % 7),
                    vec![not_examined(
                        &format!("c{i:03}"),
                        NotExaminedReason::Unreadable,
                    )],
                )
            })
            .collect();
        let observe = |inventory: &mut PiiInventory, files: &[(String, Vec<NotExamined>)]| {
            for (key, examples) in files {
                inventory.observe_file(key, FileOutcome::ScannedWhole, false, at(0));
                inventory.observe_not_examined(key, &counts(examples), examples);
            }
        };
        let mut forward = PiiInventory::default();
        observe(&mut forward, &files);
        let mut backward = PiiInventory::default();
        let reversed: Vec<_> = files.iter().rev().cloned().collect();
        observe(&mut backward, &reversed);
        let (first, second) = files.split_at(n / 2);
        let (mut left, mut right) = (PiiInventory::default(), PiiInventory::default());
        observe(&mut left, first);
        observe(&mut right, second);
        right.merge(left);
        for inventory in [&backward, &right] {
            assert_eq!(
                inventory.not_examined_examples(),
                forward.not_examined_examples()
            );
            assert!(inventory.not_examined_examples_truncated());
        }
        assert_eq!(
            forward.not_examined_examples().len(),
            MAX_NOT_EXAMINED_EXAMPLES
        );
        let total: u64 = forward.tables().iter().map(Table::not_examined_total).sum();
        assert_eq!(total, u64::try_from(n).unwrap_or(0));
        assert!(forward.heap_bytes() <= PiiInventory::MAX_BYTES);
    }
}
