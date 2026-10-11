//! `stale-standard`: flags a large `STANDARD` object that has gone a long
//! time unmodified — a candidate for a cheaper storage class or lifecycle
//! rule. The title says "unmodified", not "unaccessed": a `ListObjectsV2`
//! listing only has `last_modified`, never a last-access time, and this
//! rule does not pretend otherwise.
//!
//! Objects smaller than [`MIN_SIZE_FOR_LOW`] are excluded even if old: the
//! IA storage classes this finding would steer an object toward bill a
//! 128 KiB minimum per object, and Intelligent-Tiering does not tier
//! objects below that size at all, so moving a smaller object would cost
//! more than it saves.

use std::time::Duration;

use super::EvalContext;
use crate::model::{ObjectMeta, Severity, StorageClass};

/// How long an object must have gone unmodified before this rule considers
/// it stale. Strictly greater than, not greater-or-equal: exactly 90 days
/// is not yet stale.
const STALE_AGE: Duration = Duration::from_hours(90 * 24);

/// The minimum size for a Low finding: below this, no cold storage class
/// would actually save money (see the module doc).
const MIN_SIZE_FOR_LOW: u64 = 128 * 1024;

/// The minimum size for a Medium finding: a stale object at least this
/// large is a materially bigger cost opportunity than a merely-Low one.
const MIN_SIZE_FOR_MEDIUM: u64 = 1024 * 1024 * 1024;

pub(super) fn check(object: &ObjectMeta, ctx: &EvalContext) -> Option<Severity> {
    if object.storage_class != StorageClass::Standard {
        return None;
    }

    // If last_modified is after "now" (a clock skew or a scripted test),
    // treat the object's age as zero rather than erroring: `duration_since`
    // returns `Err` in exactly that case.
    let age = ctx
        .now
        .duration_since(object.last_modified)
        .unwrap_or_default();
    if age <= STALE_AGE {
        return None;
    }

    if object.size >= MIN_SIZE_FOR_MEDIUM {
        Some(Severity::Medium)
    } else if object.size >= MIN_SIZE_FOR_LOW {
        Some(Severity::Low)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::{MIN_SIZE_FOR_LOW, MIN_SIZE_FOR_MEDIUM, STALE_AGE, check};
    use crate::model::{ObjectMeta, Severity, StorageClass};
    use crate::rules::EvalContext;

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000)
    }

    fn ctx() -> EvalContext {
        EvalContext { now: now() }
    }

    fn object(age: Duration, size: u64, storage_class: StorageClass) -> ObjectMeta {
        ObjectMeta {
            key: "object.bin".to_owned(),
            size,
            last_modified: now() - age,
            etag: "etag".to_owned(),
            storage_class,
        }
    }

    #[test]
    fn exactly_ninety_days_is_not_yet_stale() {
        let obj = object(STALE_AGE, 10 * MIN_SIZE_FOR_MEDIUM, StorageClass::Standard);
        assert_eq!(check(&obj, &ctx()), None);
    }

    #[test]
    fn ninety_days_and_one_second_is_stale() {
        let obj = object(
            STALE_AGE + Duration::from_secs(1),
            MIN_SIZE_FOR_LOW,
            StorageClass::Standard,
        );
        assert_eq!(check(&obj, &ctx()), Some(Severity::Low));
    }

    #[test]
    fn exactly_the_low_size_threshold_qualifies() {
        let obj = object(
            STALE_AGE + Duration::from_secs(1),
            MIN_SIZE_FOR_LOW,
            StorageClass::Standard,
        );
        assert_eq!(check(&obj, &ctx()), Some(Severity::Low));
    }

    #[test]
    fn one_byte_under_the_low_threshold_is_unflagged() {
        let obj = object(
            STALE_AGE + Duration::from_secs(1),
            MIN_SIZE_FOR_LOW - 1,
            StorageClass::Standard,
        );
        assert_eq!(check(&obj, &ctx()), None);
    }

    #[test]
    fn exactly_the_medium_size_threshold_qualifies_as_medium() {
        let obj = object(
            STALE_AGE + Duration::from_secs(1),
            MIN_SIZE_FOR_MEDIUM,
            StorageClass::Standard,
        );
        assert_eq!(check(&obj, &ctx()), Some(Severity::Medium));
    }

    #[test]
    fn one_byte_under_the_medium_threshold_is_still_low() {
        let obj = object(
            STALE_AGE + Duration::from_secs(1),
            MIN_SIZE_FOR_MEDIUM - 1,
            StorageClass::Standard,
        );
        assert_eq!(check(&obj, &ctx()), Some(Severity::Low));
    }

    #[test]
    fn a_last_modified_in_the_future_is_treated_as_age_zero() {
        let future = ObjectMeta {
            key: "object.bin".to_owned(),
            size: 10 * MIN_SIZE_FOR_MEDIUM,
            last_modified: now() + Duration::from_hours(1),
            etag: "etag".to_owned(),
            storage_class: StorageClass::Standard,
        };
        assert_eq!(check(&future, &ctx()), None);
    }

    #[test]
    fn only_standard_storage_class_is_considered() {
        let obj = object(
            STALE_AGE + Duration::from_secs(1),
            10 * MIN_SIZE_FOR_MEDIUM,
            StorageClass::Glacier,
        );
        assert_eq!(check(&obj, &ctx()), None);
    }
}
