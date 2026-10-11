//! Shared domain vocabulary.
//!
//! Every domain type in `LakeScan` lives here. No other module may define its
//! own `ObjectMeta`, `Finding`, `Severity`, or `StorageClass`: the scanner,
//! the rule engine, the aggregators, and the reporter all speak this one
//! vocabulary, which is what keeps the pipeline a pipeline rather than four
//! programs that translate between each other.
//!
//! As of M2, every type in this module is complete: [`Severity`],
//! [`ObjectMeta`], [`StorageClass`], [`RuleId`], and [`Finding`].

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
}

/// Identifies which rule raised a [`Finding`].
///
/// Fieldless, one variant per `rules` v1 check, declared in the order
/// [`crate::rules::evaluate`] runs them — the same order materialized as
/// [`RuleId::ALL`].
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
}

impl RuleId {
    /// Every rule, in the order [`crate::rules::evaluate`] checks them.
    pub const ALL: [Self; 6] = [
        Self::SensitiveKey,
        Self::ReducedRedundancy,
        Self::StaleStandard,
        Self::SmallObjectColdTier,
        Self::ZeroByteObject,
        Self::UnknownStorageClass,
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

#[cfg(test)]
mod tests {
    use super::{RuleId, Severity, StorageClass};

    /// The frozen contract. If this test is edited, the contract is broken.
    #[test]
    fn rule_id_codes_match_the_frozen_contract() {
        assert_eq!(RuleId::SensitiveKey.code(), "sensitive-key");
        assert_eq!(RuleId::ReducedRedundancy.code(), "reduced-redundancy");
        assert_eq!(RuleId::StaleStandard.code(), "stale-standard");
        assert_eq!(RuleId::SmallObjectColdTier.code(), "small-object-cold-tier");
        assert_eq!(RuleId::ZeroByteObject.code(), "zero-byte-object");
        assert_eq!(RuleId::UnknownStorageClass.code(), "unknown-storage-class");
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
