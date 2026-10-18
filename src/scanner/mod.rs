//! Enumerates S3 objects and emits [`ObjectMeta`] downstream.
//!
//! Single responsibility: turn a bucket and prefix into a stream of object
//! metadata. The scanner decides *what exists*; it never decides whether
//! anything is wrong with it.
//!
//! **Memory budget: 4 MB.** Exactly one `ListObjectsV2` page is live at a
//! time: a page is parsed, forwarded, and dropped before the next is
//! requested, so no module-level collection ever grows with bucket size.
//! Worst case per page is 1000 keys of up to 1 KiB each held twice at once —
//! once as the raw XML response body and once as parsed [`ObjectMeta`]
//! entries — which puts the tight bound near 2 MB before per-entry
//! allocator overhead, so 4 MB is headroom, not a guess.
//!
//! The pagination seam is [`PageSource`]: [`Scanner`] drives it one page at a
//! time and is tested against a scripted fake, with no network in the
//! default test run. The only production implementation is [`S3Source`],
//! which talks to `ListObjectsV2` and converts entries into [`ObjectMeta`]
//! with no cloning and no silent defaulting of missing fields.
//!
//! [`ObjectMeta`]: crate::model::ObjectMeta

mod page_source;
mod s3_source;

pub use page_source::{PAGE_SIZE, PageSource, Scanner};
pub use s3_source::S3Source;
pub(crate) use s3_source::bucket_region;
