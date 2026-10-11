//! `reduced-redundancy`: flags objects still sitting in the deprecated
//! `REDUCED_REDUNDANCY` storage class, which AWS no longer recommends for
//! any workload (it trades durability for a cost saving `STANDARD` itself
//! has long since matched).

use super::EvalContext;
use crate::model::{ObjectMeta, Severity, StorageClass};

pub(super) fn check(object: &ObjectMeta, _ctx: &EvalContext) -> Option<Severity> {
    if object.storage_class == StorageClass::ReducedRedundancy {
        Some(Severity::Medium)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::check;
    use crate::model::{ObjectMeta, Severity, StorageClass};
    use crate::rules::EvalContext;

    fn ctx() -> EvalContext {
        EvalContext {
            now: SystemTime::UNIX_EPOCH,
        }
    }

    fn object_with_class(storage_class: StorageClass) -> ObjectMeta {
        ObjectMeta {
            key: "object.bin".to_owned(),
            size: 1024,
            last_modified: SystemTime::UNIX_EPOCH,
            etag: "etag".to_owned(),
            storage_class,
        }
    }

    #[test]
    fn reduced_redundancy_is_medium() {
        assert_eq!(
            check(&object_with_class(StorageClass::ReducedRedundancy), &ctx()),
            Some(Severity::Medium)
        );
    }

    #[test]
    fn every_other_storage_class_is_unflagged() {
        for class in [
            StorageClass::Standard,
            StorageClass::StandardIa,
            StorageClass::OnezoneIa,
            StorageClass::IntelligentTiering,
            StorageClass::Glacier,
            StorageClass::GlacierIr,
            StorageClass::DeepArchive,
            StorageClass::Outposts,
            StorageClass::Snow,
            StorageClass::ExpressOnezone,
            StorageClass::Other("NEW_CLASS".to_owned()),
        ] {
            assert_eq!(
                check(&object_with_class(class.clone()), &ctx()),
                None,
                "{class:?}"
            );
        }
    }
}
