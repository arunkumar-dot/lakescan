//! Shared domain vocabulary.
//!
//! Every domain type in `LakeScan` lives here. No other module may define its
//! own `ObjectMeta`, `Finding`, `Severity`, or `StorageClass`: the scanner,
//! the rule engine, the aggregators, and the reporter all speak this one
//! vocabulary, which is what keeps the pipeline a pipeline rather than four
//! programs that translate between each other.
//!
//! For M0 only [`Severity`] is complete. The remaining types are reserved
//! names with their fields deliberately unspecified; they are filled in by the
//! milestone noted on each one, from that milestone's spec rather than guessed
//! at here.

/// Metadata for a single S3 object, as returned by one `ListObjectsV2` entry.
///
/// Fields are defined by the scanner spec and arrive in M1.
// M1
#[derive(Debug)]
pub struct ObjectMeta {}

/// The S3 storage class an object currently resides in.
///
/// Variants are defined by the scanner spec and arrive in M1.
// M1
#[derive(Debug)]
pub enum StorageClass {}

/// One rule violation observed against one object.
///
/// Fields are defined by the rule-engine spec and arrive in M2.
// M2
#[derive(Debug)]
pub struct Finding {}

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
    use super::Severity;

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
