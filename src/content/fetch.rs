//! The read seam: [`ObjectReader`] fetches one byte range of one object.
//!
//! Content scanning is tested against in-memory readers; the only
//! production implementation is [`S3ObjectReader`], one ranged
//! `GetObject` per call. A failed read is never a scan-aborting error: it
//! becomes a [`FetchError`], which the caller turns into a
//! `content-not-scanned` finding.

use std::future::Future;

use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::primitives::AggregatedBytes;

/// Why a read failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// The read was refused: `AccessDenied`, or a KMS key the caller may
    /// not use.
    AccessDenied,
    /// Anything else: a network failure, a 5xx, a missing object.
    Failed,
}

/// Reads byte ranges of objects in one bucket.
pub trait ObjectReader {
    /// Reads bytes `start..end` (end exclusive) of the object at `key`.
    /// `start < end` always.
    ///
    /// # Errors
    /// Returns [`FetchError::AccessDenied`] when the read was refused and
    /// [`FetchError::Failed`] for any other failure.
    fn read_range(
        &mut self,
        key: &str,
        start: u64,
        end: u64,
    ) -> impl Future<Output = Result<AggregatedBytes, FetchError>> + Send;
}

/// Ranged `GetObject` against one bucket.
pub struct S3ObjectReader {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl S3ObjectReader {
    /// Reads from `bucket` through `client`.
    #[must_use]
    pub fn new(client: aws_sdk_s3::Client, bucket: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
        }
    }
}

impl ObjectReader for S3ObjectReader {
    async fn read_range(
        &mut self,
        key: &str,
        start: u64,
        end: u64,
    ) -> Result<AggregatedBytes, FetchError> {
        let last = end.checked_sub(1).ok_or(FetchError::Failed)?;
        let output = self
            .client
            .get_object()
            .bucket(self.bucket.as_str())
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
