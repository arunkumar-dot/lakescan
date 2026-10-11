//! The production [`PageSource`]: lists one S3 bucket (optionally scoped to
//! a prefix) via `ListObjectsV2` and converts each entry into an
//! [`ObjectMeta`].

use aws_config::BehaviorVersion;
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Error;
use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Output;
use aws_sdk_s3::types::Object;

use super::page_source::{PAGE_SIZE, PageSource};
use crate::error::LakeScanError;
use crate::model::{ObjectMeta, StorageClass};

/// Lists the objects of one bucket, optionally scoped to a prefix, through
/// `ListObjectsV2` with no delimiter (a full recursive listing rather than
/// one level of a virtual hierarchy).
pub struct S3Source {
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: Option<String>,
}

impl S3Source {
    /// Builds an [`S3Source`] for `bucket`, optionally scoped to `prefix`,
    /// loading AWS configuration from the environment the same way the AWS
    /// CLI does (environment variables, shared config/credentials files,
    /// then container/instance credentials).
    ///
    /// # Errors
    /// Returns [`LakeScanError::Usage`] if no AWS region is configured
    /// anywhere in that chain; `LakeScan` does not guess a region, since
    /// scanning the wrong one silently would be worse than refusing to
    /// start.
    pub async fn new(
        bucket: impl Into<String>,
        prefix: Option<String>,
    ) -> Result<Self, LakeScanError> {
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;

        if config.region().is_none() {
            return Err(LakeScanError::Usage(
                "no AWS region is configured; set the AWS_REGION environment variable \
                 (or configure a region in your AWS profile)"
                    .to_owned(),
            ));
        }

        Ok(Self {
            client: aws_sdk_s3::Client::new(&config),
            bucket: bucket.into(),
            prefix,
        })
    }
}

impl PageSource for S3Source {
    async fn fetch_page(
        &mut self,
        continuation: Option<String>,
        out: &mut Vec<ObjectMeta>,
    ) -> Result<Option<String>, LakeScanError> {
        let mut request = self
            .client
            .list_objects_v2()
            .bucket(self.bucket.as_str())
            .max_keys(i32::from(PAGE_SIZE));

        if let Some(prefix) = &self.prefix {
            request = request.prefix(prefix.as_str());
        }
        if let Some(token) = continuation {
            request = request.continuation_token(token);
        }

        let output = request.send().await.map_err(classify_sdk_error)?;

        let ListObjectsV2Output {
            is_truncated,
            contents,
            next_continuation_token,
            ..
        } = output;

        for object in contents.unwrap_or_default() {
            out.push(convert_object(object)?);
        }

        if is_truncated == Some(true) && next_continuation_token.is_none() {
            return Err(LakeScanError::Transport(
                "S3 reported more results are available (is_truncated) but returned no \
                 continuation token"
                    .to_owned(),
            ));
        }

        Ok(next_continuation_token)
    }
}

/// Converts one SDK [`Object`] into an [`ObjectMeta`], by value: `key` and
/// `e_tag` are moved out rather than cloned.
///
/// A missing or unconvertible field is a [`LakeScanError::Transport`] naming
/// both the field and the key, when the key itself is known; an entry is
/// never silently skipped.
fn convert_object(object: Object) -> Result<ObjectMeta, LakeScanError> {
    let Object {
        key,
        last_modified,
        e_tag,
        size,
        storage_class,
        ..
    } = object;

    let key = key.ok_or_else(|| {
        LakeScanError::Transport(
            "object entry in ListObjectsV2 response is missing its key".to_owned(),
        )
    })?;

    let size = size
        .ok_or_else(|| LakeScanError::Transport(format!("object {key:?} is missing its size")))?;
    let size = u64::try_from(size).map_err(|_| {
        LakeScanError::Transport(format!("object {key:?} reports a negative size ({size})"))
    })?;

    let last_modified = last_modified.ok_or_else(|| {
        LakeScanError::Transport(format!(
            "object {key:?} is missing its last_modified timestamp"
        ))
    })?;
    let last_modified = std::time::SystemTime::try_from(last_modified).map_err(|err| {
        LakeScanError::Transport(format!(
            "object {key:?} has an unconvertible last_modified timestamp: {err}"
        ))
    })?;

    let etag = e_tag
        .ok_or_else(|| LakeScanError::Transport(format!("object {key:?} is missing its etag")))?;

    let storage_class = storage_class.ok_or_else(|| {
        LakeScanError::Transport(format!("object {key:?} is missing its storage class"))
    })?;
    let storage_class = StorageClass::from_wire(storage_class.as_str());

    Ok(ObjectMeta {
        key,
        size,
        last_modified,
        etag,
        storage_class,
    })
}

/// Classifies a failed `ListObjectsV2` call into the `LakeScan` error
/// category it belongs to.
///
/// Generic over the SDK's raw-response type so this function never needs to
/// name it: at the real call site it is inferred from `.send()`'s error
/// type, and tests below pin it to `()`.
fn classify_sdk_error<R>(err: SdkError<ListObjectsV2Error, R>) -> LakeScanError {
    if let SdkError::ServiceError(service) = &err {
        return classify_service_error(service.err().code(), service.err().message());
    }

    let is_credential_failure = matches!(err, SdkError::ConstructionFailure(_));
    let detail = err.into_source().map_or_else(
        |_| "no further detail available".to_owned(),
        |source| source.to_string(),
    );

    if is_credential_failure {
        LakeScanError::Auth(format!("could not resolve AWS credentials: {detail}"))
    } else {
        LakeScanError::Transport(detail)
    }
}

/// Classifies an S3 error code and message into the `LakeScan` error
/// category it belongs to.
///
/// Pure and network-free, which is what makes the mapping unit-testable as a
/// plain table: see `error_codes_classify_into_their_contracted_category`
/// below. `ListObjectsV2Error` models only `NoSuchBucket` as a distinct Rust
/// variant; every other code (including ones `aws-sdk-s3` has never heard
/// of) arrives as `Unhandled`, so classification has to run on the string
/// code rather than on the SDK's enum shape.
fn classify_service_error(code: Option<&str>, message: Option<&str>) -> LakeScanError {
    let code = code.unwrap_or("unknown");
    let message = message.unwrap_or("no message provided");
    let detail = format!("{code}: {message}");

    match code {
        "AccessDenied"
        | "InvalidAccessKeyId"
        | "SignatureDoesNotMatch"
        | "ExpiredToken"
        | "InvalidToken"
        | "AllAccessDisabled" => LakeScanError::Auth(detail),

        "NoSuchBucket" => LakeScanError::Usage(format!(
            "{detail} (check the bucket name and that it exists)"
        )),
        "InvalidBucketName" => {
            LakeScanError::Usage(format!("{detail} (the bucket name is not valid)"))
        }
        "PermanentRedirect" => LakeScanError::Usage(format!(
            "{detail} (the bucket is in a different region; set AWS_REGION to match it)"
        )),
        "AuthorizationHeaderMalformed" => LakeScanError::Usage(format!(
            "{detail} (the configured AWS_REGION does not match the bucket's region)"
        )),

        _ => LakeScanError::Transport(detail),
    }
}

#[cfg(test)]
mod tests {
    use aws_sdk_s3::error::{ConnectorError, ErrorMetadata};
    use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Error;

    use super::{classify_sdk_error, classify_service_error};
    use crate::error::LakeScanError;

    #[test]
    fn error_codes_classify_into_their_contracted_category() {
        let auth_codes = [
            "AccessDenied",
            "InvalidAccessKeyId",
            "SignatureDoesNotMatch",
            "ExpiredToken",
            "InvalidToken",
            "AllAccessDisabled",
        ];
        for code in auth_codes {
            assert!(
                matches!(
                    classify_service_error(Some(code), Some("x")),
                    LakeScanError::Auth(_)
                ),
                "{code} should classify as Auth"
            );
        }

        let usage_codes = [
            "NoSuchBucket",
            "InvalidBucketName",
            "PermanentRedirect",
            "AuthorizationHeaderMalformed",
        ];
        for code in usage_codes {
            assert!(
                matches!(
                    classify_service_error(Some(code), Some("x")),
                    LakeScanError::Usage(_)
                ),
                "{code} should classify as Usage"
            );
        }

        let transport_codes = [
            "InternalError",
            "SlowDown",
            "ServiceUnavailable",
            "RequestTimeout",
            "SomeCodeThisCrateHasNeverSeen",
        ];
        for code in transport_codes {
            assert!(
                matches!(
                    classify_service_error(Some(code), Some("x")),
                    LakeScanError::Transport(_)
                ),
                "{code} should classify as Transport"
            );
        }

        assert!(matches!(
            classify_service_error(None, None),
            LakeScanError::Transport(_)
        ));
    }

    #[test]
    fn construction_failure_classifies_as_auth() {
        let err: SdkErrorUnit = aws_sdk_s3::error::SdkError::construction_failure("no credentials");
        assert!(matches!(classify_sdk_error(err), LakeScanError::Auth(_)));
    }

    #[test]
    fn timeout_dispatch_and_response_failures_classify_as_transport() {
        let timeout: SdkErrorUnit = aws_sdk_s3::error::SdkError::timeout_error("took too long");
        assert!(matches!(
            classify_sdk_error(timeout),
            LakeScanError::Transport(_)
        ));

        let dispatch: SdkErrorUnit = aws_sdk_s3::error::SdkError::dispatch_failure(
            ConnectorError::io("connection reset".into()),
        );
        assert!(matches!(
            classify_sdk_error(dispatch),
            LakeScanError::Transport(_)
        ));

        let response: SdkErrorUnit =
            aws_sdk_s3::error::SdkError::response_error("unparseable body", ());
        assert!(matches!(
            classify_sdk_error(response),
            LakeScanError::Transport(_)
        ));
    }

    #[test]
    fn a_service_error_is_classified_by_its_code() {
        let meta = ErrorMetadata::builder()
            .code("NoSuchBucket")
            .message("the bucket does not exist")
            .build();
        let err: SdkErrorUnit =
            aws_sdk_s3::error::SdkError::service_error(ListObjectsV2Error::generic(meta), ());
        assert!(matches!(classify_sdk_error(err), LakeScanError::Usage(_)));
    }

    /// `SdkError<ListObjectsV2Error, R>` with the raw-response type pinned to
    /// `()`, since the tests here only care about the error path.
    type SdkErrorUnit = aws_sdk_s3::error::SdkError<ListObjectsV2Error, ()>;
}
