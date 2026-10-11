//! `unknown-storage-class`: flags an object whose storage class this build
//! of `LakeScan` does not recognize ([`StorageClass::Other`]). This is
//! informational, not a finding about the object itself: it usually means
//! AWS has shipped a storage class newer than this crate's `aws-sdk-s3`
//! dependency, and the fix is to upgrade the dependency and extend
//! [`StorageClass::from_wire`], not to change the object.

use super::EvalContext;
use crate::model::{ObjectMeta, Severity, StorageClass};

pub(super) fn check(object: &ObjectMeta, _ctx: &EvalContext) -> Option<Severity> {
    match object.storage_class {
        StorageClass::Other(_) => Some(Severity::Info),
        _ => None,
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
    fn an_unrecognized_storage_class_is_flagged_info() {
        assert_eq!(
            check(
                &object_with_class(StorageClass::Other("NEW_CLASS".to_owned())),
                &ctx()
            ),
            Some(Severity::Info)
        );
    }

    #[test]
    fn every_recognized_storage_class_is_unflagged() {
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
            assert_eq!(
                check(&object_with_class(class.clone()), &ctx()),
                None,
                "{class:?}"
            );
        }
    }
}
