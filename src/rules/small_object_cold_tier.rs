//! `small-object-cold-tier`: flags a small object parked in a cold storage
//! class that bills (or simply wastes) a size minimum it does not reach —
//! the mirror image of `stale-standard`'s exclusion, raised as its own
//! finding here because this time the object is already in the cold class.

use super::EvalContext;
use crate::model::{ObjectMeta, Severity, StorageClass};

/// Objects at or above this size are big enough that a cold tier's size
/// minimum no longer matters; only objects strictly smaller are flagged.
const SIZE_THRESHOLD: u64 = 128 * 1024;

pub(super) fn check(object: &ObjectMeta, _ctx: &EvalContext) -> Option<Severity> {
    if object.size >= SIZE_THRESHOLD {
        return None;
    }

    match object.storage_class {
        StorageClass::StandardIa
        | StorageClass::OnezoneIa
        | StorageClass::GlacierIr
        | StorageClass::Glacier
        | StorageClass::DeepArchive => Some(Severity::Low),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::{SIZE_THRESHOLD, check};
    use crate::model::{ObjectMeta, Severity, StorageClass};
    use crate::rules::EvalContext;

    fn ctx() -> EvalContext {
        EvalContext {
            now: SystemTime::UNIX_EPOCH,
        }
    }

    fn object(size: u64, storage_class: StorageClass) -> ObjectMeta {
        ObjectMeta {
            key: "object.bin".to_owned(),
            size,
            last_modified: SystemTime::UNIX_EPOCH,
            etag: "etag".to_owned(),
            storage_class,
        }
    }

    #[test]
    fn small_objects_in_every_cold_tier_are_low() {
        for class in [
            StorageClass::StandardIa,
            StorageClass::OnezoneIa,
            StorageClass::GlacierIr,
            StorageClass::Glacier,
            StorageClass::DeepArchive,
        ] {
            assert_eq!(
                check(&object(SIZE_THRESHOLD - 1, class.clone()), &ctx()),
                Some(Severity::Low),
                "{class:?}"
            );
        }
    }

    #[test]
    fn exactly_the_size_threshold_is_not_flagged() {
        assert_eq!(
            check(&object(SIZE_THRESHOLD, StorageClass::Glacier), &ctx()),
            None
        );
    }

    #[test]
    fn one_byte_under_the_threshold_is_flagged() {
        assert_eq!(
            check(&object(SIZE_THRESHOLD - 1, StorageClass::Glacier), &ctx()),
            Some(Severity::Low)
        );
    }

    #[test]
    fn warm_or_unrecognized_storage_classes_are_not_flagged_even_when_small() {
        for class in [
            StorageClass::Standard,
            StorageClass::ReducedRedundancy,
            StorageClass::IntelligentTiering,
            StorageClass::Other("NEW_CLASS".to_owned()),
        ] {
            assert_eq!(check(&object(1, class.clone()), &ctx()), None, "{class:?}");
        }
    }
}
