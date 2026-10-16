//! The read seam: [`ObjectReader`] fetches one byte range of one object,
//! like `scanner::PageSource` for listing.
//!
//! Content scanning is tested and benchmarked against in-memory readers
//! (`content::SimStore`); the only production implementation is
//! [`S3ObjectReader`], one ranged `GetObject` per call, with the SDK's
//! adaptive retry mode. Reads take `&self`, so files scanned at once, and
//! the ranges of one file, share one reader. A failed read is never a
//! scan-aborting error: it becomes a [`FetchError`], which the caller
//! turns into a `content-not-scanned` finding.

use std::future::Future;
use std::sync::Arc;

use aws_sdk_s3::config::retry::RetryConfig;

use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::primitives::AggregatedBytes;

/// Why a read failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// The read was refused: `AccessDenied`, or a KMS key the caller may
    /// not use.
    AccessDenied,
    /// Anything else, after the SDK's retries: throttling, a timeout, a
    /// 5xx, a vanished object.
    Failed,
}

/// Reads byte ranges of objects in one bucket. Cheap to clone (clones
/// share one client), and shared by concurrent scans.
pub trait ObjectReader: Clone + Send + Sync + 'static {
    /// Reads bytes `start..end` (end exclusive) of the object at `key`.
    /// `start < end` always.
    ///
    /// # Errors
    /// Returns [`FetchError::AccessDenied`] when the read was refused and
    /// [`FetchError::Failed`] for any other failure.
    fn read_range(
        &self,
        key: &str,
        start: u64,
        end: u64,
    ) -> impl Future<Output = Result<AggregatedBytes, FetchError>> + Send;
}

/// Ranged `GetObject` against one bucket.
#[derive(Debug, Clone)]
pub struct S3ObjectReader {
    client: aws_sdk_s3::Client,
    bucket: Arc<str>,
}

impl S3ObjectReader {
    /// Reads from `bucket` through a copy of `client` switched to the
    /// SDK's adaptive retry mode, which also slows the request rate when
    /// S3 throttles (503 `SlowDown`), so high `--concurrency` backs off.
    #[must_use]
    pub fn new(client: &aws_sdk_s3::Client, bucket: &str) -> Self {
        let config = client
            .config()
            .to_builder()
            .retry_config(RetryConfig::adaptive())
            .build();
        Self {
            client: aws_sdk_s3::Client::from_conf(config),
            bucket: Arc::from(bucket),
        }
    }
}

impl ObjectReader for S3ObjectReader {
    async fn read_range(
        &self,
        key: &str,
        start: u64,
        end: u64,
    ) -> Result<AggregatedBytes, FetchError> {
        let last = end.checked_sub(1).ok_or(FetchError::Failed)?;
        let output = self
            .client
            .get_object()
            .bucket(&*self.bucket)
            .key(key)
            .range(format!("bytes={start}-{last}"))
            .send()
            .await
            .map_err(|err| classify(&err))?;
        output.body.collect().await.map_err(|_| FetchError::Failed)
    }
}

/// Classifies a failed `GetObject`.
fn classify<E: ProvideErrorMetadata, R>(err: &SdkError<E, R>) -> FetchError {
    match err {
        SdkError::ServiceError(service) => classify_code(service.err().code()),
        _ => FetchError::Failed,
    }
}

/// `AccessDenied`, and the KMS errors S3 returns when the object's key
/// cannot be used, are refusals; every other code is a failure.
fn classify_code(code: Option<&str>) -> FetchError {
    match code {
        Some(code) if code == "AccessDenied" || code.starts_with("KMS.") => {
            FetchError::AccessDenied
        }
        _ => FetchError::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::{FetchError, classify_code};

    #[test]
    fn refusals_are_access_denied_and_everything_else_failed() {
        assert_eq!(
            classify_code(Some("AccessDenied")),
            FetchError::AccessDenied
        );
        assert_eq!(
            classify_code(Some("KMS.DisabledException")),
            FetchError::AccessDenied
        );
        for code in [
            Some("NoSuchKey"),
            Some("InternalError"),
            Some("SlowDown"),
            None,
        ] {
            assert_eq!(classify_code(code), FetchError::Failed, "{code:?}");
        }
    }
}
