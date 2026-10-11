//! The pagination seam ([`PageSource`]) and the driver that walks it
//! ([`Scanner`]), independent of any particular backend.

use std::future::Future;

use crate::error::LakeScanError;
use crate::model::ObjectMeta;

/// The number of entries requested per page, and the capacity the
/// [`Scanner`]'s reusable buffer is allocated with.
///
/// A [`PageSource`] must never append more than this many entries to the
/// `out` buffer in a single [`PageSource::fetch_page`] call; doing so is a
/// contract violation that [`Scanner::next_page`] reports as a
/// [`LakeScanError::Transport`].
pub const PAGE_SIZE: u16 = 1000;

/// A source of pages of [`ObjectMeta`], abstracting over how they are
/// fetched so [`Scanner`]'s pagination logic can be tested without the
/// network.
///
/// Implementations append at most [`PAGE_SIZE`] entries to `out` per call and
/// return the continuation token for the next page, or `None` when the
/// listing is exhausted. This uses the desugared `-> impl Future<...> + Send`
/// return type rather than `async fn` so that `async_fn_in_trait` does not
/// fire under `-D warnings`.
pub trait PageSource {
    /// Fetches one page, appending its entries to `out` and returning the
    /// continuation token for the next page (`None` if this was the last
    /// one).
    ///
    /// # Errors
    /// Returns an error if the page could not be fetched or decoded. The
    /// specific category is up to the implementation; [`S3Source`](super::S3Source)
    /// documents its own mapping.
    fn fetch_page(
        &mut self,
        continuation: Option<String>,
        out: &mut Vec<ObjectMeta>,
    ) -> impl Future<Output = Result<Option<String>, LakeScanError>> + Send;
}

/// Drives a [`PageSource`] one page at a time, holding exactly one page's
/// worth of [`ObjectMeta`] in memory.
///
/// The reusable buffer is allocated once, with capacity [`PAGE_SIZE`], and is
/// cleared (never reallocated) between pages: [`Scanner`] owns the only
/// `Vec` in the pipeline whose size could in principle grow with the bucket,
/// and it is pinned to a constant capacity by construction.
pub struct Scanner<S: PageSource> {
    source: S,
    buffer: Vec<ObjectMeta>,
    continuation: Option<String>,
    /// Set once the listing is known to be finished, whether by exhaustion
    /// or by error. After this, `next_page` short-circuits to `Ok(None)`
    /// without touching the source again.
    exhausted: bool,
}

impl<S: PageSource> Scanner<S> {
    /// Builds a [`Scanner`] that will start listing from the beginning.
    #[must_use]
    pub fn new(source: S) -> Self {
        Self {
            source,
            buffer: Vec::with_capacity(usize::from(PAGE_SIZE)),
            continuation: None,
            exhausted: false,
        }
    }

    /// Fetches and returns the next page, or `Ok(None)` once the listing is
    /// exhausted.
    ///
    /// The returned slice borrows `self`: only one page can be live at a
    /// time, by construction rather than by convention. Empty pages that
    /// still carry a continuation token are skipped transparently; `Ok(None)`
    /// is returned only once the source itself reports no more pages.
    ///
    /// Fused: once this has returned `Ok(None)` or an `Err`, every later call
    /// returns `Ok(None)` without invoking the source again.
    ///
    /// # Errors
    /// Returns [`LakeScanError::Transport`] if the source's call fails, if it
    /// appends more than [`PAGE_SIZE`] entries in one page, or if it returns
    /// the same continuation token it was just handed (a sign of a stuck
    /// pagination cursor rather than genuine progress).
    pub async fn next_page(&mut self) -> Result<Option<&[ObjectMeta]>, LakeScanError> {
        if self.exhausted {
            return Ok(None);
        }

        loop {
            self.buffer.clear();
            let requested = self.continuation.clone();

            let fetch_result = self
                .source
                .fetch_page(requested.clone(), &mut self.buffer)
                .await;
            let next = match fetch_result {
                Ok(next) => next,
                Err(err) => {
                    self.exhausted = true;
                    return Err(err);
                }
            };

            if self.buffer.len() > usize::from(PAGE_SIZE) {
                self.exhausted = true;
                return Err(LakeScanError::Transport(format!(
                    "page source returned {} entries, exceeding the page size of {PAGE_SIZE}",
                    self.buffer.len(),
                )));
            }

            if requested.is_some() && next == requested {
                self.exhausted = true;
                return Err(LakeScanError::Transport(
                    "page source returned the same continuation token it was just given".to_owned(),
                ));
            }

            self.continuation = next;

            if self.buffer.is_empty() {
                if self.continuation.is_some() {
                    // Empty intermediate page: keep going with the new token.
                    continue;
                }
                self.exhausted = true;
                return Ok(None);
            }

            if self.continuation.is_none() {
                self.exhausted = true;
            }

            return Ok(Some(self.buffer.as_slice()));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::time::SystemTime;

    use super::{PAGE_SIZE, PageSource, Scanner};
    use crate::error::LakeScanError;
    use crate::model::{ObjectMeta, StorageClass};

    /// One scripted response to a single `fetch_page` call.
    enum Step {
        /// Append these entries and report this continuation token.
        Page(Vec<ObjectMeta>, Option<String>),
        /// Fail with this error.
        Err(LakeScanError),
    }

    /// A [`PageSource`] driven entirely by a pre-scripted queue of [`Step`]s,
    /// so `Scanner`'s pagination logic can be exercised with no network.
    struct FakeSource {
        steps: VecDeque<Step>,
    }

    impl FakeSource {
        fn new(steps: Vec<Step>) -> Self {
            Self {
                steps: steps.into(),
            }
        }
    }

    impl PageSource for FakeSource {
        fn fetch_page(
            &mut self,
            _continuation: Option<String>,
            out: &mut Vec<ObjectMeta>,
        ) -> impl Future<Output = Result<Option<String>, LakeScanError>> + Send {
            // Scripted, never actually asynchronous, so this returns an
            // already-ready future (`std::future::ready`) rather than an
            // `async fn` with no `.await` in it.
            std::future::ready(match self.steps.pop_front() {
                Some(Step::Page(entries, next)) => {
                    out.extend(entries);
                    Ok(next)
                }
                Some(Step::Err(err)) => Err(err),
                None => Ok(None),
            })
        }
    }

    fn meta(key: &str) -> ObjectMeta {
        ObjectMeta {
            key: key.to_owned(),
            size: 0,
            last_modified: SystemTime::UNIX_EPOCH,
            etag: "etag".to_owned(),
            storage_class: StorageClass::Standard,
        }
    }

    #[tokio::test]
    async fn pages_are_returned_in_order_across_multiple_fetches() -> Result<(), LakeScanError> {
        let mut scanner = Scanner::new(FakeSource::new(vec![
            Step::Page(vec![meta("a"), meta("b")], Some("tok-1".to_owned())),
            Step::Page(vec![meta("c")], None),
        ]));

        let first = scanner.next_page().await?;
        assert_eq!(first, Some([meta("a"), meta("b")].as_slice()));

        let second = scanner.next_page().await?;
        assert_eq!(second, Some([meta("c")].as_slice()));

        let third = scanner.next_page().await?;
        assert_eq!(third, None);

        Ok(())
    }

    #[tokio::test]
    async fn empty_intermediate_pages_are_skipped() -> Result<(), LakeScanError> {
        let mut scanner = Scanner::new(FakeSource::new(vec![
            Step::Page(vec![], Some("tok-1".to_owned())),
            Step::Page(vec![], Some("tok-2".to_owned())),
            Step::Page(vec![meta("a")], None),
        ]));

        let page = scanner.next_page().await?;
        assert_eq!(page, Some([meta("a")].as_slice()));

        let end = scanner.next_page().await?;
        assert_eq!(end, None);

        Ok(())
    }

    #[tokio::test]
    async fn an_empty_final_page_returns_none() -> Result<(), LakeScanError> {
        let mut scanner = Scanner::new(FakeSource::new(vec![
            Step::Page(vec![meta("a")], Some("tok-1".to_owned())),
            Step::Page(vec![], None),
        ]));

        let page = scanner.next_page().await?;
        assert_eq!(page, Some([meta("a")].as_slice()));

        let end = scanner.next_page().await?;
        assert_eq!(end, None);

        Ok(())
    }

    #[tokio::test]
    async fn buffer_capacity_is_page_size_and_never_grows() -> Result<(), LakeScanError> {
        let many_entries: Vec<ObjectMeta> = (0..usize::from(PAGE_SIZE))
            .map(|n| meta(&n.to_string()))
            .collect();

        let mut scanner = Scanner::new(FakeSource::new(vec![
            Step::Page(many_entries.clone(), Some("tok-1".to_owned())),
            Step::Page(many_entries, None),
        ]));

        assert_eq!(scanner.buffer.capacity(), usize::from(PAGE_SIZE));

        scanner.next_page().await?;
        assert_eq!(scanner.buffer.capacity(), usize::from(PAGE_SIZE));

        scanner.next_page().await?;
        assert_eq!(scanner.buffer.capacity(), usize::from(PAGE_SIZE));

        Ok(())
    }

    #[tokio::test]
    async fn a_page_larger_than_page_size_is_a_transport_error() {
        let too_many: Vec<ObjectMeta> = (0..=usize::from(PAGE_SIZE))
            .map(|n| meta(&n.to_string()))
            .collect();
        let mut scanner = Scanner::new(FakeSource::new(vec![Step::Page(too_many, None)]));

        let result = scanner.next_page().await;
        assert!(matches!(result, Err(LakeScanError::Transport(_))));

        // Fused after the error.
        let after = scanner.next_page().await;
        assert!(matches!(after, Ok(None)));
    }

    #[tokio::test]
    async fn a_repeated_continuation_token_is_a_transport_error() {
        let mut scanner = Scanner::new(FakeSource::new(vec![
            Step::Page(vec![meta("a")], Some("tok-1".to_owned())),
            Step::Page(vec![meta("b")], Some("tok-1".to_owned())),
        ]));

        let first = scanner.next_page().await;
        assert!(matches!(first, Ok(Some(_))));

        let second = scanner.next_page().await;
        assert!(matches!(second, Err(LakeScanError::Transport(_))));
    }

    #[tokio::test]
    async fn a_source_error_propagates_and_then_the_scanner_is_exhausted() {
        let mut scanner = Scanner::new(FakeSource::new(vec![Step::Err(LakeScanError::Transport(
            "boom".to_owned(),
        ))]));

        let first = scanner.next_page().await;
        assert!(matches!(first, Err(LakeScanError::Transport(_))));

        let second = scanner.next_page().await;
        assert!(matches!(second, Ok(None)));
    }
}
