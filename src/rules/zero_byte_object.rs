//! `zero-byte-object`: flags a zero-byte object that is not a folder
//! marker. The S3 console (and other tools) create a zero-byte object
//! ending in `/` to represent an empty "folder" in the console's virtual
//! hierarchy; that is expected and not worth flagging. A zero-byte object
//! with no trailing slash is usually either a mistake or leftover
//! scaffolding from an incomplete upload.

use super::EvalContext;
use crate::model::{ObjectMeta, Severity};

pub(super) fn check(object: &ObjectMeta, _ctx: &EvalContext) -> Option<Severity> {
    if object.size == 0 && !object.key.ends_with('/') {
        Some(Severity::Info)
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

    fn object(key: &str, size: u64) -> ObjectMeta {
        ObjectMeta {
            key: key.to_owned(),
            size,
            last_modified: SystemTime::UNIX_EPOCH,
            etag: "etag".to_owned(),
            storage_class: StorageClass::Standard,
        }
    }

    #[test]
    fn a_zero_byte_file_is_flagged() {
        assert_eq!(check(&object("empty.txt", 0), &ctx()), Some(Severity::Info));
    }

    #[test]
    fn a_zero_byte_folder_marker_is_not_flagged() {
        assert_eq!(check(&object("folder/", 0), &ctx()), None);
        assert_eq!(check(&object("/", 0), &ctx()), None);
    }

    #[test]
    fn a_non_empty_object_is_never_flagged_regardless_of_trailing_slash() {
        assert_eq!(check(&object("file.txt", 1), &ctx()), None);
        assert_eq!(check(&object("weird/", 1), &ctx()), None);
    }
}
