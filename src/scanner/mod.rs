//! Enumerates S3 objects and emits [`ObjectMeta`] downstream.
//!
//! Single responsibility: turn a bucket and prefix into a stream of object
//! metadata. The scanner decides *what exists*; it never decides whether
//! anything is wrong with it.
//!
//! **Memory budget: 1 MB.** Exactly one `ListObjectsV2` page is live at a
//! time. A page is parsed, forwarded, and dropped before the next is
//! requested; no module-level collection ever grows with bucket size.
//!
//! [`ObjectMeta`]: crate::model::ObjectMeta
