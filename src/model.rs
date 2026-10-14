//! Shared domain vocabulary.
//!
//! Every domain type in `LakeScan` lives here. No other module may define its
//! own `ObjectMeta`, `Finding`, `Severity`, or `StorageClass`: the scanner,
//! the rule engine, the aggregators, and the reporter all speak this one
//! vocabulary, which is what keeps the pipeline a pipeline rather than four
//! programs that translate between each other.
//!
//! The listing vocabulary — [`ObjectMeta`], [`StorageClass`], [`RuleId`],
//! [`Severity`], [`Finding`] — plus, since M7, what content scanning adds
//! to it: the PII types it detects ([`PiiType`]), how sure it is
//! ([`Confidence`]), what a finding carries beyond its object
//! ([`Detail`], [`ColumnDetail`]), and why a file could not be scanned
//! ([`NotScannedReason`]).

/// Metadata for a single S3 object, as returned by one `ListObjectsV2` entry.
///
/// This is the scanner's sole output type: every field here is something the
/// scanner adapter (currently `S3Source`) read directly off the listing
/// response, converted by value with no cloning and no silent defaulting. A
/// missing or unconvertible field on the wire is a [`crate::error::LakeScanError::Transport`]
/// at the scanner boundary, never a default here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMeta {
    /// The object's full key (path) within the bucket.
    pub key: String,
    /// Size in bytes.
    pub size: u64,
    /// When the object was last written.
    pub last_modified: std::time::SystemTime,
    /// The object's entity tag, as reported by S3 (quotes included, exactly
    /// as received; this crate never strips or reinterprets it).
    pub etag: String,
    /// The storage class the object currently resides in.
    pub storage_class: StorageClass,
}

/// The S3 storage class an object currently resides in.
///
/// One variant per wire value known to the `aws-sdk-s3` version this crate is
/// built against, plus [`StorageClass::Other`] for any value the SDK does not
/// yet model. [`StorageClass::from_wire`] is the only place that performs
/// this mapping; nothing else in the crate may depend on the SDK's own enum
/// or its Rust variant names, so an SDK upgrade that adds a storage class
/// only ever touches that one function.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StorageClass {
    /// `STANDARD`.
    Standard,
    /// `REDUCED_REDUNDANCY`.
    ReducedRedundancy,
    /// `STANDARD_IA`.
    StandardIa,
    /// `ONEZONE_IA`.
    OnezoneIa,
    /// `INTELLIGENT_TIERING`.
    IntelligentTiering,
    /// `GLACIER`.
    Glacier,
    /// `GLACIER_IR`.
    GlacierIr,
    /// `DEEP_ARCHIVE`.
    DeepArchive,
    /// `OUTPOSTS`.
    Outposts,
    /// `SNOW`.
    Snow,
    /// `EXPRESS_ONEZONE`.
    ExpressOnezone,
    /// `AWS_BACKUP_LOW_COST_WARM`.
    AwsBackupLowCostWarm,
    /// `AWS_BACKUP_WARM`.
    AwsBackupWarm,
    /// `FSX_ONTAP`.
    FsxOntap,
    /// `FSX_OPENZFS`.
    FsxOpenzfs,
    /// A wire value not recognized above: either a storage class newer than
    /// this crate's `aws-sdk-s3` dependency, or (in tests) a deliberately
    /// synthetic one. Carries the wire string verbatim.
    Other(String),
}

impl StorageClass {
    /// Maps a storage-class wire value (e.g. `"STANDARD"`) to a [`StorageClass`].
    ///
    /// Never fails: an unrecognized value becomes [`StorageClass::Other`]
    /// rather than an error, since a new storage class is forward-compatible
    /// data, not a malformed response.
    #[must_use]
    pub fn from_wire(wire: &str) -> Self {
        match wire {
            "STANDARD" => Self::Standard,
            "REDUCED_REDUNDANCY" => Self::ReducedRedundancy,
            "STANDARD_IA" => Self::StandardIa,
            "ONEZONE_IA" => Self::OnezoneIa,
            "INTELLIGENT_TIERING" => Self::IntelligentTiering,
            "GLACIER" => Self::Glacier,
            "GLACIER_IR" => Self::GlacierIr,
            "DEEP_ARCHIVE" => Self::DeepArchive,
            "OUTPOSTS" => Self::Outposts,
            "SNOW" => Self::Snow,
            "EXPRESS_ONEZONE" => Self::ExpressOnezone,
            "AWS_BACKUP_LOW_COST_WARM" => Self::AwsBackupLowCostWarm,
            "AWS_BACKUP_WARM" => Self::AwsBackupWarm,
            "FSX_ONTAP" => Self::FsxOntap,
            "FSX_OPENZFS" => Self::FsxOpenzfs,
            other => Self::Other(other.to_owned()),
        }
    }

    /// The S3 wire string for this storage class, e.g. `"STANDARD"`. For
    /// [`Self::Other`], returns the wire value it was built from verbatim.
    ///
    /// The exact inverse of [`Self::from_wire`]: `from_wire(c.as_wire()) ==
    /// c` for every `c`, known or not, which the tests below check.
    #[must_use]
    pub fn as_wire(&self) -> &str {
        match self {
            Self::Standard => "STANDARD",
            Self::ReducedRedundancy => "REDUCED_REDUNDANCY",
            Self::StandardIa => "STANDARD_IA",
            Self::OnezoneIa => "ONEZONE_IA",
            Self::IntelligentTiering => "INTELLIGENT_TIERING",
            Self::Glacier => "GLACIER",
            Self::GlacierIr => "GLACIER_IR",
            Self::DeepArchive => "DEEP_ARCHIVE",
            Self::Outposts => "OUTPOSTS",
            Self::Snow => "SNOW",
            Self::ExpressOnezone => "EXPRESS_ONEZONE",
            Self::AwsBackupLowCostWarm => "AWS_BACKUP_LOW_COST_WARM",
            Self::AwsBackupWarm => "AWS_BACKUP_WARM",
            Self::FsxOntap => "FSX_ONTAP",
            Self::FsxOpenzfs => "FSX_OPENZFS",
            Self::Other(wire) => wire,
        }
    }

    /// This storage class's position among the *known* (non-[`Self::Other`])
    /// variants, in declaration order, or `None` for [`Self::Other`].
    ///
    /// Lets `aggregate` index a fixed per-known-class array for the
    /// inventory summary, with [`Self::Other`] handled separately since it
    /// has no fixed slot.
    #[must_use]
    pub fn known_index(&self) -> Option<usize> {
        match self {
            Self::Standard => Some(0),
            Self::ReducedRedundancy => Some(1),
            Self::StandardIa => Some(2),
            Self::OnezoneIa => Some(3),
            Self::IntelligentTiering => Some(4),
            Self::Glacier => Some(5),
            Self::GlacierIr => Some(6),
            Self::DeepArchive => Some(7),
            Self::Outposts => Some(8),
            Self::Snow => Some(9),
            Self::ExpressOnezone => Some(10),
            Self::AwsBackupLowCostWarm => Some(11),
            Self::AwsBackupWarm => Some(12),
            Self::FsxOntap => Some(13),
            Self::FsxOpenzfs => Some(14),
            Self::Other(_) => None,
        }
    }

    /// Every known (non-[`Self::Other`]) storage class, in
    /// [`Self::known_index`] order: `KNOWN[i].known_index() == Some(i)`.
    ///
    /// The single source of truth for "every known class" — `aggregate`
    /// sizes its per-class inventory slots from `KNOWN.len()`, and nothing
    /// else in the crate may keep its own copy of this list.
    pub const KNOWN: [Self; 15] = [
        Self::Standard,
        Self::ReducedRedundancy,
        Self::StandardIa,
        Self::OnezoneIa,
        Self::IntelligentTiering,
        Self::Glacier,
        Self::GlacierIr,
        Self::DeepArchive,
        Self::Outposts,
        Self::Snow,
        Self::ExpressOnezone,
        Self::AwsBackupLowCostWarm,
        Self::AwsBackupWarm,
        Self::FsxOntap,
        Self::FsxOpenzfs,
    ];
}

/// Identifies which rule raised a [`Finding`].
///
/// Fieldless, one variant per rule. The six listing rules come first, in
/// the order [`crate::rules::evaluate`] runs them; the content rules
/// (M7), raised by [`crate::content`] from inside Parquet files, follow.
/// [`RuleId::ALL`] materializes this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleId {
    /// The key's basename or path looks like a credential or secret file.
    SensitiveKey,
    /// The object sits in the deprecated `REDUCED_REDUNDANCY` storage class.
    ReducedRedundancy,
    /// A large `STANDARD` object has gone a long time unmodified.
    StaleStandard,
    /// A small object sits in a cold tier that bills a minimum object size.
    SmallObjectColdTier,
    /// A zero-byte object that is not a folder marker.
    ZeroByteObject,
    /// The storage class is one this build of `LakeScan` does not recognize.
    UnknownStorageClass,
    /// A Parquet column holds email addresses.
    PiiEmail,
    /// A Parquet column holds phone numbers.
    PiiPhone,
    /// A Parquet column holds Indian PAN (tax ID) numbers.
    PiiInPan,
    /// A Parquet column holds Aadhaar numbers.
    PiiInAadhaar,
    /// A Parquet column holds payment card numbers.
    PiiCardNumber,
    /// A Parquet column holds IP addresses.
    PiiIpAddress,
    /// A Parquet column's name says it holds people's names.
    PiiPersonName,
    /// A Parquet column's name says it holds dates of birth.
    PiiDateOfBirth,
    /// A Parquet file could not be content-scanned.
    ContentNotScanned,
}

impl RuleId {
    /// Every rule: the listing rules in the order
    /// [`crate::rules::evaluate`] checks them, then the content rules.
    pub const ALL: [Self; 15] = [
        Self::SensitiveKey,
        Self::ReducedRedundancy,
        Self::StaleStandard,
        Self::SmallObjectColdTier,
        Self::ZeroByteObject,
        Self::UnknownStorageClass,
        Self::PiiEmail,
        Self::PiiPhone,
        Self::PiiInPan,
        Self::PiiInAadhaar,
        Self::PiiCardNumber,
        Self::PiiIpAddress,
        Self::PiiPersonName,
        Self::PiiDateOfBirth,
        Self::ContentNotScanned,
    ];

    /// The rule's stable, machine-readable code, e.g. `"sensitive-key"`.
    ///
    /// **Frozen contract**, like [`crate::error::ExitCode`]'s integer
    /// values: reports and dashboards key off these strings, so an existing
    /// code must never change once shipped. Add new rules with new codes.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::SensitiveKey => "sensitive-key",
            Self::ReducedRedundancy => "reduced-redundancy",
            Self::StaleStandard => "stale-standard",
            Self::SmallObjectColdTier => "small-object-cold-tier",
            Self::ZeroByteObject => "zero-byte-object",
            Self::UnknownStorageClass => "unknown-storage-class",
            Self::PiiEmail => "pii-email",
            Self::PiiPhone => "pii-phone",
            Self::PiiInPan => "pii-in-pan",
            Self::PiiInAadhaar => "pii-in-aadhaar",
            Self::PiiCardNumber => "pii-card-number",
            Self::PiiIpAddress => "pii-ip-address",
            Self::PiiPersonName => "pii-person-name",
            Self::PiiDateOfBirth => "pii-date-of-birth",
            Self::ContentNotScanned => "content-not-scanned",
        }
    }

    /// This rule's position in [`RuleId::ALL`].
    ///
    /// Lets `aggregate` index fixed-size per-rule arrays (the findings
    /// matrix, the per-rule sample slots) without ever depending on the
    /// enum's underlying discriminant values.
    #[must_use]
    pub fn index(self) -> usize {
        match self {
            Self::SensitiveKey => 0,
            Self::ReducedRedundancy => 1,
            Self::StaleStandard => 2,
            Self::SmallObjectColdTier => 3,
            Self::ZeroByteObject => 4,
            Self::UnknownStorageClass => 5,
            Self::PiiEmail => 6,
            Self::PiiPhone => 7,
            Self::PiiInPan => 8,
            Self::PiiInAadhaar => 9,
            Self::PiiCardNumber => 10,
            Self::PiiIpAddress => 11,
            Self::PiiPersonName => 12,
            Self::PiiDateOfBirth => 13,
            Self::ContentNotScanned => 14,
        }
    }

    /// A one-line human description of what the rule flags.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::SensitiveKey => "Key looks like a credential or secret file",
            Self::ReducedRedundancy => {
                "Object uses the deprecated REDUCED_REDUNDANCY storage class"
            }
            Self::StaleStandard => "Large STANDARD object has gone unmodified for a long time",
            Self::SmallObjectColdTier => {
                "Small object sits in a cold storage tier that bills a size minimum"
            }
            Self::ZeroByteObject => "Zero-byte object that is not a folder marker",
            Self::UnknownStorageClass => {
                "Object reports a storage class this build of LakeScan does not recognize"
            }
            Self::PiiEmail => "Parquet column holds email addresses",
            Self::PiiPhone => "Parquet column holds phone numbers",
            Self::PiiInPan => "Parquet column holds Indian PAN numbers",
            Self::PiiInAadhaar => "Parquet column holds Aadhaar numbers",
            Self::PiiCardNumber => "Parquet column holds payment card numbers",
            Self::PiiIpAddress => "Parquet column holds IP addresses",
            Self::PiiPersonName => "Parquet column holds people's names",
            Self::PiiDateOfBirth => "Parquet column holds dates of birth",
            Self::ContentNotScanned => "Parquet file could not be content-scanned",
        }
    }

    /// Whether this rule is raised by content scanning rather than by the
    /// listing rules in [`crate::rules`].
    #[must_use]
    pub fn is_content(self) -> bool {
        self.index() >= Self::PiiEmail.index()
    }

    /// Whether this rule says a Parquet column holds personal data: a
    /// content rule other than `content-not-scanned`. Its findings are
    /// about a column, not a file, so a byte total is meaningless for them.
    #[must_use]
    pub fn is_pii(self) -> bool {
        self.is_content() && self != Self::ContentNotScanned
    }
}

/// A kind of personal data content scanning detects.
///
/// The first six are detected from values (each has a validator in
/// `content`); the last two only from a column's name and type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PiiType {
    /// An email address.
    Email,
    /// A phone number: E.164, or an Indian mobile number.
    Phone,
    /// An Indian Permanent Account Number (tax ID).
    InPan,
    /// An Aadhaar number (12 digits, Verhoeff checksum).
    InAadhaar,
    /// A payment card number (13 to 19 digits, Luhn checksum).
    CardNumber,
    /// An IPv4 or IPv6 address.
    IpAddress,
    /// A person's name (by column name only).
    PersonName,
    /// A date of birth (by column name only).
    DateOfBirth,
}

impl PiiType {
    /// Every type, in [`RuleId`] order.
    pub const ALL: [Self; 8] = [
        Self::Email,
        Self::Phone,
        Self::InPan,
        Self::InAadhaar,
        Self::CardNumber,
        Self::IpAddress,
        Self::PersonName,
        Self::DateOfBirth,
    ];

    /// The rule a finding of this type is raised under.
    #[must_use]
    pub fn rule(self) -> RuleId {
        match self {
            Self::Email => RuleId::PiiEmail,
            Self::Phone => RuleId::PiiPhone,
            Self::InPan => RuleId::PiiInPan,
            Self::InAadhaar => RuleId::PiiInAadhaar,
            Self::CardNumber => RuleId::PiiCardNumber,
            Self::IpAddress => RuleId::PiiIpAddress,
            Self::PersonName => RuleId::PiiPersonName,
            Self::DateOfBirth => RuleId::PiiDateOfBirth,
        }
    }

    /// Whether values can confirm this type (it has a validator), as
    /// opposed to only a column's name and type.
    #[must_use]
    pub fn has_validator(self) -> bool {
        !matches!(self, Self::PersonName | Self::DateOfBirth)
    }
}

/// How sure content scanning is that a column holds a [`PiiType`],
/// ordered `Possible < Likely < Confirmed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// A name hint only.
    Possible,
    /// Some value evidence, or a strong name hint on a column of fitting
    /// type.
    Likely,
    /// At least 80% of at least 30 cleaned values match.
    Confirmed,
}

impl Confidence {
    /// The stable code, e.g. `"confirmed"`. **Frozen contract**, like
    /// [`Severity::code`].
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Possible => "possible",
            Self::Likely => "likely",
            Self::Confirmed => "confirmed",
        }
    }

    /// The severity a finding at this confidence carries.
    #[must_use]
    pub fn severity(self) -> Severity {
        match self {
            Self::Possible => Severity::Info,
            Self::Likely => Severity::Medium,
            Self::Confirmed => Severity::High,
        }
    }
}

/// Why a Parquet file could not be content-scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NotScannedReason {
    /// The object does not carry the Parquet magic bytes.
    NotParquet,
    /// It looks like Parquet but could not be parsed (truncated, corrupt),
    /// or reading it failed for a reason other than access.
    Unreadable,
    /// `GetObject` was refused (`AccessDenied`, or a KMS key it could not
    /// use).
    AccessDenied,
    /// The file uses Parquet modular encryption.
    Encrypted,
    /// The footer is larger than the footer cap.
    FooterTooLarge,
    /// The file has columns whose values could be read, but every one of
    /// them was skipped (page too large, unreadable, unsupported codec), so
    /// no value was examined.
    NoColumnExamined,
}

impl NotScannedReason {
    /// Every reason, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::NotParquet,
        Self::Unreadable,
        Self::AccessDenied,
        Self::Encrypted,
        Self::FooterTooLarge,
        Self::NoColumnExamined,
    ];

    /// The stable code, e.g. `"not-parquet"`. **Frozen contract**.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NotParquet => "not-parquet",
            Self::Unreadable => "unreadable",
            Self::AccessDenied => "access-denied",
            Self::Encrypted => "encrypted",
            Self::FooterTooLarge => "footer-too-large",
            Self::NoColumnExamined => "no-column-examined",
        }
    }

    /// This reason's position in [`NotScannedReason::ALL`].
    #[must_use]
    pub fn index(self) -> usize {
        match self {
            Self::NotParquet => 0,
            Self::Unreadable => 1,
            Self::AccessDenied => 2,
            Self::Encrypted => 3,
            Self::FooterTooLarge => 4,
            Self::NoColumnExamined => 5,
        }
    }
}

/// The longest column path a [`ColumnDetail`] keeps; longer paths are cut
/// at a `char` boundary.
pub const MAX_COLUMN_BYTES: usize = 256;

/// What a PII finding rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Evidence {
    /// Sampled values: `matched` of `sampled` cleaned values validated as
    /// the type.
    Values {
        /// Cleaned sampled values that validated.
        matched: u64,
        /// Cleaned values sampled.
        sampled: u64,
    },
    /// The column's name (and type) alone: always the case for
    /// `PERSON_NAME` and `DATE_OF_BIRTH`, which have no validator, and for a
    /// `POSSIBLE` finding.
    ColumnName,
}

impl Evidence {
    /// The stable code: `"values"` or `"column-name"`. **Frozen contract**.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Values { .. } => "values",
            Self::ColumnName => "column-name",
        }
    }
}

/// What a PII finding says about the column it was raised on. Never holds
/// a sampled value: only the column's path, confidence and evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnDetail {
    /// The column's dotted path (`address.email` for a struct leaf), at
    /// most [`MAX_COLUMN_BYTES`] bytes.
    pub column: String,
    /// How sure the scan is.
    pub confidence: Confidence,
    /// What the finding rests on: value counts, or the column's name.
    pub evidence: Evidence,
}

impl ColumnDetail {
    /// Builds a detail, truncating `column` to [`MAX_COLUMN_BYTES`].
    #[must_use]
    pub fn new(column: &str, confidence: Confidence, evidence: Evidence) -> Self {
        Self {
            column: truncate_str(column, MAX_COLUMN_BYTES).to_owned(),
            confidence,
            evidence,
        }
    }
}

/// The longest prefix of `s` that is at most `max_bytes` long and ends on
/// a `char` boundary.
#[must_use]
pub fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or_default()
}

/// What a [`Finding`] carries beyond its rule, severity and object.
/// Additive: listing findings carry [`Detail::None`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detail<'a> {
    /// Nothing more: every listing finding.
    None,
    /// A PII finding's column, confidence and counts.
    Column(&'a ColumnDetail),
    /// Why a file could not be content-scanned.
    NotScanned(NotScannedReason),
}

impl<'a> Detail<'a> {
    /// The column detail, if this is a PII finding.
    #[must_use]
    pub fn column(self) -> Option<&'a ColumnDetail> {
        match self {
            Self::Column(detail) => Some(detail),
            Self::None | Self::NotScanned(_) => None,
        }
    }
}

/// One rule violation observed against one object.
///
/// Borrows the [`ObjectMeta`] it was raised against rather than copying any
/// of its fields, so a `Finding` can never outlive the scanner page it came
/// from. Anything downstream that needs to keep a finding past the current
/// page — [`crate::aggregate`], [`crate::report`] — must copy out whatever
/// fields it actually needs (the key, say) before the page is dropped;
/// nothing here extends the borrow for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finding<'a> {
    /// Which rule raised this finding.
    pub rule: RuleId,
    /// How serious this particular violation is.
    pub severity: Severity,
    /// The object the finding was raised against.
    pub object: &'a ObjectMeta,
    /// What else the finding says: the column for a PII finding, the
    /// reason for `content-not-scanned`, nothing for a listing finding.
    pub detail: Detail<'a>,
}

/// How much a [`Finding`] matters, ordered `Info < Low < Medium < High < Critical`.
///
/// The derived [`Ord`] follows declaration order, so comparing severities and
/// sorting findings by them are the same operation. Threshold checks rely on
/// this: a run fails when its worst severity is `>=` the configured floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Observed and recorded; no action implied.
    Info,
    /// A hygiene problem worth fixing eventually.
    Low,
    /// A real exposure or cost problem that should be scheduled.
    Medium,
    /// A serious problem that should be fixed now.
    High,
    /// Active, exploitable exposure. Fix before anything else.
    Critical,
}

impl Severity {
    /// Every severity, ascending — the same order the derived [`Ord`] uses.
    pub const ALL: [Self; 5] = [
        Self::Info,
        Self::Low,
        Self::Medium,
        Self::High,
        Self::Critical,
    ];

    /// This severity's position in [`Severity::ALL`].
    ///
    /// Lets `aggregate` index fixed-size per-severity arrays (the findings
    /// matrix) without depending on the enum's underlying discriminant
    /// values.
    #[must_use]
    pub fn index(self) -> usize {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }

    /// This severity's stable, machine-readable code, e.g. `"high"`.
    ///
    /// **Frozen contract**, like [`RuleId::code`] and
    /// [`crate::error::ExitCode`]'s integer values: reports key off these
    /// strings, so an existing code must never change once shipped.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ColumnDetail, Confidence, Evidence, MAX_COLUMN_BYTES, NotScannedReason, PiiType, RuleId,
        Severity, StorageClass,
    };

    /// The frozen contract. If this test is edited, the contract is broken.
    #[test]
    fn rule_id_codes_match_the_frozen_contract() {
        assert_eq!(RuleId::SensitiveKey.code(), "sensitive-key");
        assert_eq!(RuleId::ReducedRedundancy.code(), "reduced-redundancy");
        assert_eq!(RuleId::StaleStandard.code(), "stale-standard");
        assert_eq!(RuleId::SmallObjectColdTier.code(), "small-object-cold-tier");
        assert_eq!(RuleId::ZeroByteObject.code(), "zero-byte-object");
        assert_eq!(RuleId::UnknownStorageClass.code(), "unknown-storage-class");
        assert_eq!(RuleId::PiiEmail.code(), "pii-email");
        assert_eq!(RuleId::PiiPhone.code(), "pii-phone");
        assert_eq!(RuleId::PiiInPan.code(), "pii-in-pan");
        assert_eq!(RuleId::PiiInAadhaar.code(), "pii-in-aadhaar");
        assert_eq!(RuleId::PiiCardNumber.code(), "pii-card-number");
        assert_eq!(RuleId::PiiIpAddress.code(), "pii-ip-address");
        assert_eq!(RuleId::PiiPersonName.code(), "pii-person-name");
        assert_eq!(RuleId::PiiDateOfBirth.code(), "pii-date-of-birth");
        assert_eq!(RuleId::ContentNotScanned.code(), "content-not-scanned");
    }

    /// The frozen contract. If this test is edited, the contract is broken.
    #[test]
    fn confidence_and_reason_codes_match_the_frozen_contract() {
        assert_eq!(Confidence::Possible.code(), "possible");
        assert_eq!(Confidence::Likely.code(), "likely");
        assert_eq!(Confidence::Confirmed.code(), "confirmed");
        assert_eq!(NotScannedReason::NotParquet.code(), "not-parquet");
        assert_eq!(NotScannedReason::Unreadable.code(), "unreadable");
        assert_eq!(NotScannedReason::AccessDenied.code(), "access-denied");
        assert_eq!(NotScannedReason::Encrypted.code(), "encrypted");
        assert_eq!(NotScannedReason::FooterTooLarge.code(), "footer-too-large");
        assert_eq!(
            NotScannedReason::NoColumnExamined.code(),
            "no-column-examined"
        );
        assert_eq!(Evidence::ColumnName.code(), "column-name");
        assert_eq!(
            Evidence::Values {
                matched: 1,
                sampled: 2
            }
            .code(),
            "values"
        );
    }

    #[test]
    fn confidence_maps_to_severity() {
        assert_eq!(Confidence::Confirmed.severity(), Severity::High);
        assert_eq!(Confidence::Likely.severity(), Severity::Medium);
        assert_eq!(Confidence::Possible.severity(), Severity::Info);
        assert!(Confidence::Possible < Confidence::Likely);
        assert!(Confidence::Likely < Confidence::Confirmed);
    }

    #[test]
    fn every_pii_type_maps_to_a_distinct_content_rule() {
        let rules: Vec<RuleId> = PiiType::ALL.iter().map(|t| t.rule()).collect();
        for (index, rule) in rules.iter().enumerate() {
            assert!(rule.is_content(), "{rule:?}");
            assert_eq!(rules.iter().position(|r| r == rule), Some(index));
        }
        assert!(RuleId::ContentNotScanned.is_content());
        assert!(!RuleId::UnknownStorageClass.is_content());
        assert!(rules.iter().all(|rule| rule.is_pii()));
        assert!(!RuleId::ContentNotScanned.is_pii());
        assert!(!RuleId::SensitiveKey.is_pii());
    }

    #[test]
    fn not_scanned_reason_index_matches_all() {
        for (expected, reason) in NotScannedReason::ALL.iter().enumerate() {
            assert_eq!(reason.index(), expected, "{reason:?}");
        }
    }

    #[test]
    fn column_paths_are_truncated_at_a_char_boundary() {
        let long = "é".repeat(200);
        let detail = ColumnDetail::new(&long, Confidence::Likely, Evidence::ColumnName);
        assert!(detail.column.len() <= MAX_COLUMN_BYTES);
        assert!(detail.column.len().is_multiple_of(2));
        assert_eq!(
            ColumnDetail::new("a.b", Confidence::Likely, Evidence::ColumnName).column,
            "a.b"
        );
    }

    #[test]
    fn every_rule_id_code_is_unique() {
        let codes: Vec<&str> = RuleId::ALL.iter().map(|rule| rule.code()).collect();
        for (index, code) in codes.iter().enumerate() {
            let first_occurrence = codes.iter().position(|other| other == code);
            assert_eq!(
                first_occurrence,
                Some(index),
                "code {code:?} is not unique across RuleId::ALL"
            );
        }
    }

    #[test]
    fn rule_id_index_matches_declaration_order_in_all() {
        for (expected_index, rule) in RuleId::ALL.iter().enumerate() {
            assert_eq!(rule.index(), expected_index, "{rule:?}");
        }
    }

    #[test]
    fn severity_index_matches_declaration_order_in_all() {
        for (expected_index, severity) in Severity::ALL.iter().enumerate() {
            assert_eq!(severity.index(), expected_index, "{severity:?}");
        }
    }

    #[test]
    fn severity_all_is_every_variant_exactly_once_in_ascending_order() {
        let mut all = Severity::ALL;
        all.sort_unstable();
        assert_eq!(all, Severity::ALL, "Severity::ALL is not already ascending");
    }

    #[test]
    fn storage_class_known_index_matches_known_array_order() {
        for (expected_index, class) in StorageClass::KNOWN.iter().enumerate() {
            assert_eq!(class.known_index(), Some(expected_index), "{class:?}");
        }
    }

    #[test]
    fn storage_class_known_index_is_none_only_for_other() {
        for class in &StorageClass::KNOWN {
            assert!(class.known_index().is_some(), "{class:?} should be known");
        }
        assert_eq!(
            StorageClass::Other("NEW_CLASS".to_owned()).known_index(),
            None
        );
    }

    /// The frozen contract. If this test is edited, the contract is broken.
    #[test]
    fn severity_codes_match_the_frozen_contract() {
        assert_eq!(Severity::Info.code(), "info");
        assert_eq!(Severity::Low.code(), "low");
        assert_eq!(Severity::Medium.code(), "medium");
        assert_eq!(Severity::High.code(), "high");
        assert_eq!(Severity::Critical.code(), "critical");
    }

    #[test]
    fn as_wire_is_the_exact_inverse_of_from_wire_for_every_known_class() {
        for class in [
            StorageClass::Standard,
            StorageClass::ReducedRedundancy,
            StorageClass::StandardIa,
            StorageClass::OnezoneIa,
            StorageClass::IntelligentTiering,
            StorageClass::Glacier,
            StorageClass::GlacierIr,
            StorageClass::DeepArchive,
            StorageClass::Outposts,
            StorageClass::Snow,
            StorageClass::ExpressOnezone,
            StorageClass::AwsBackupLowCostWarm,
            StorageClass::AwsBackupWarm,
            StorageClass::FsxOntap,
            StorageClass::FsxOpenzfs,
        ] {
            assert_eq!(StorageClass::from_wire(class.as_wire()), class, "{class:?}");
        }
    }

    #[test]
    fn as_wire_is_the_exact_inverse_of_from_wire_for_other() {
        let other = StorageClass::Other("SOME_FUTURE_CLASS".to_owned());
        assert_eq!(StorageClass::from_wire(other.as_wire()), other);
    }

    #[test]
    fn from_wire_maps_every_known_value() {
        let known = [
            ("STANDARD", StorageClass::Standard),
            ("REDUCED_REDUNDANCY", StorageClass::ReducedRedundancy),
            ("STANDARD_IA", StorageClass::StandardIa),
            ("ONEZONE_IA", StorageClass::OnezoneIa),
            ("INTELLIGENT_TIERING", StorageClass::IntelligentTiering),
            ("GLACIER", StorageClass::Glacier),
            ("GLACIER_IR", StorageClass::GlacierIr),
            ("DEEP_ARCHIVE", StorageClass::DeepArchive),
            ("OUTPOSTS", StorageClass::Outposts),
            ("SNOW", StorageClass::Snow),
            ("EXPRESS_ONEZONE", StorageClass::ExpressOnezone),
            (
                "AWS_BACKUP_LOW_COST_WARM",
                StorageClass::AwsBackupLowCostWarm,
            ),
            ("AWS_BACKUP_WARM", StorageClass::AwsBackupWarm),
            ("FSX_ONTAP", StorageClass::FsxOntap),
            ("FSX_OPENZFS", StorageClass::FsxOpenzfs),
        ];

        for (wire, expected) in known {
            assert_eq!(StorageClass::from_wire(wire), expected, "wire value {wire}");
        }
    }

    #[test]
    fn from_wire_falls_back_to_other_for_unknown_values() {
        assert_eq!(
            StorageClass::from_wire("SOME_FUTURE_CLASS"),
            StorageClass::Other("SOME_FUTURE_CLASS".to_owned())
        );
    }

    #[test]
    fn severity_is_ordered_from_info_up_to_critical() {
        let mut shuffled = [
            Severity::High,
            Severity::Info,
            Severity::Critical,
            Severity::Low,
            Severity::Medium,
        ];
        shuffled.sort_unstable();

        assert_eq!(
            shuffled,
            [
                Severity::Info,
                Severity::Low,
                Severity::Medium,
                Severity::High,
                Severity::Critical,
            ]
        );
        assert!(Severity::Info < Severity::Critical);
        assert_eq!(shuffled.iter().max(), Some(&Severity::Critical));
        assert_eq!(shuffled.iter().min(), Some(&Severity::Info));
    }
}
