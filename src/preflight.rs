//! Checks that run before the first `ListObjectsV2` call, so a missing
//! credential, a denied bucket or a wrong region fails in a second with a
//! message that says what to fix, rather than partway into a scan or as a
//! confusing exit code.
//!
//! Two calls, in order: `sts:GetCallerIdentity` (are the credentials
//! usable at all?) and `s3:HeadBucket` (can they reach this bucket, in this
//! region?). The AWS calls sit behind [`AccessProbe`], so the mapping from
//! their outcomes to errors is tested without the network.

use std::future::Future;
use std::io::Write;

use aws_sdk_s3::config::http::HttpResponse;
use aws_sdk_s3::error::{DisplayErrorContext, SdkError};
use aws_sdk_s3::operation::head_bucket::HeadBucketError;

use crate::error::LakeScanError;
use crate::scanner::bucket_region;

/// Why `HeadBucket` failed, reduced to what the preflight acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BucketFailure {
    /// HTTP 403: the credentials may not list this bucket.
    Forbidden,
    /// HTTP 404: no such bucket, as far as this region can tell.
    NotFound,
    /// The bucket lives in another region, named when S3 said which.
    WrongRegion(Option<String>),
    /// Anything else: the network, a timeout, a 5xx.
    Other(String),
}

/// The two AWS calls the preflight makes.
pub trait AccessProbe {
    /// `sts:GetCallerIdentity`: the caller's ARN, or the SDK's error text.
    fn caller_identity(&self) -> impl Future<Output = Result<String, String>> + Send;

    /// `s3:HeadBucket` on the target bucket.
    fn head_bucket(&self) -> impl Future<Output = Result<(), BucketFailure>> + Send;
}

/// The production [`AccessProbe`].
pub struct AwsProbe {
    sts: aws_sdk_sts::Client,
    s3: aws_sdk_s3::Client,
    bucket: String,
}

impl AwsProbe {
    /// A probe for `bucket`, over the clients the scan itself uses.
    #[must_use]
    pub fn new(sts: aws_sdk_sts::Client, s3: aws_sdk_s3::Client, bucket: &str) -> Self {
        Self {
            sts,
            s3,
            bucket: bucket.to_owned(),
        }
    }
}

impl AccessProbe for AwsProbe {
    async fn caller_identity(&self) -> Result<String, String> {
        match self.sts.get_caller_identity().send().await {
            Ok(identity) => Ok(identity.arn.unwrap_or_else(|| "unknown".to_owned())),
            Err(err) => Err(DisplayErrorContext(&err).to_string()),
        }
    }

    async fn head_bucket(&self) -> Result<(), BucketFailure> {
        match self
            .s3
            .head_bucket()
            .bucket(self.bucket.as_str())
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(err) => Err(classify_head_error(&err)),
        }
    }
}

/// Maps a failed `HeadBucket` to a [`BucketFailure`]. HEAD responses have no
/// body, so the HTTP status (and the `x-amz-bucket-region` header) decide.
fn classify_head_error(err: &SdkError<HeadBucketError, HttpResponse>) -> BucketFailure {
    let status = err.raw_response().map(|raw| raw.status().as_u16());
    let region = bucket_region(err);
    match status {
        Some(403) => BucketFailure::Forbidden,
        Some(404) => BucketFailure::NotFound,
        Some(301) => BucketFailure::WrongRegion(region),
        // A signature for the wrong region is a 400 that still names the
        // bucket's region.
        Some(400) if region.is_some() => BucketFailure::WrongRegion(region),
        _ => BucketFailure::Other(DisplayErrorContext(err).to_string()),
    }
}

/// Runs both checks. On success, writes "credentials ok" to `debug` when
/// there is a sink for it.
///
/// # Errors
/// [`LakeScanError::Auth`] for unusable credentials or a denied bucket,
/// [`LakeScanError::Usage`] for a missing bucket or the wrong region, and
/// [`LakeScanError::Transport`] for any other `HeadBucket` failure.
pub async fn check<P: AccessProbe>(
    probe: &P,
    bucket: &str,
    debug: Option<&mut dyn Write>,
) -> Result<(), LakeScanError> {
    let caller = probe.caller_identity().await.map_err(|detail| {
        LakeScanError::Auth(format!(
            "credentials are missing, expired, or invalid — run 'aws configure' or set \
             AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. Details: {detail}"
        ))
    })?;
    if let Some(debug) = debug {
        // Best effort: a debug line that cannot be printed changes nothing.
        let _ = writeln!(debug, "lakescan: debug: credentials ok, caller: {caller}");
    }

    probe.head_bucket().await.map_err(|failure| match failure {
        BucketFailure::Forbidden => LakeScanError::Auth(format!(
            "access denied to s3://{bucket} — check that your credentials have \
             s3:ListBucket on arn:aws:s3:::{bucket}"
        )),
        BucketFailure::NotFound => LakeScanError::Usage(format!(
            "bucket s3://{bucket} does not exist or is in a different region — check the \
             bucket name and use --region if needed"
        )),
        BucketFailure::WrongRegion(Some(region)) => LakeScanError::Usage(format!(
            "bucket s3://{bucket} is in {region}; rerun with --region {region}"
        )),
        BucketFailure::WrongRegion(None) => LakeScanError::Usage(format!(
            "bucket s3://{bucket} is in a different region — rerun with --region set to the \
             bucket's region"
        )),
        BucketFailure::Other(detail) => {
            LakeScanError::Transport(format!("could not reach s3://{bucket}: {detail}"))
        }
    })
}

/// The one-line stderr hint printed under `--pii`, after the checks pass.
#[must_use]
pub fn pii_hint(bucket: &str) -> String {
    format!(
        "lakescan: --pii requires s3:GetObject on arn:aws:s3:::{bucket}/*; add kms:Decrypt if \
         the bucket uses SSE-KMS. Access-denied errors on individual files will appear in the \
         report."
    )
}

#[cfg(test)]
mod tests {
    use aws_sdk_s3::error::ErrorMetadata;
    use aws_sdk_s3::primitives::SdkBody;

    use super::*;
    use crate::error::ExitCode;

    const CALLER: &str = "arn:aws:iam::111122223333:user/test";

    struct Mock {
        identity: Result<String, String>,
        bucket: Result<(), BucketFailure>,
    }

    impl AccessProbe for Mock {
        fn caller_identity(&self) -> impl Future<Output = Result<String, String>> + Send {
            std::future::ready(self.identity.clone())
        }
        fn head_bucket(&self) -> impl Future<Output = Result<(), BucketFailure>> + Send {
            std::future::ready(self.bucket.clone())
        }
    }

    async fn failure(mock: Mock) -> Result<(ExitCode, String), Box<dyn std::error::Error>> {
        let err = check(&mock, "lake", None)
            .await
            .err()
            .ok_or("the preflight passed")?;
        Ok((ExitCode::from(&err), err.to_string()))
    }

    #[tokio::test]
    async fn bad_credentials_exit_three_and_say_how_to_fix_them()
    -> Result<(), Box<dyn std::error::Error>> {
        let (code, message) = failure(Mock {
            identity: Err("ExpiredToken: the token has expired".to_owned()),
            bucket: Ok(()),
        })
        .await?;
        assert_eq!(code, ExitCode::Auth);
        assert_eq!(
            message,
            "auth: credentials are missing, expired, or invalid — run 'aws configure' or set \
             AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. Details: ExpiredToken: the token \
             has expired"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_forbidden_bucket_exits_three_naming_s3_list_bucket()
    -> Result<(), Box<dyn std::error::Error>> {
        let (code, message) = failure(Mock {
            identity: Ok(CALLER.to_owned()),
            bucket: Err(BucketFailure::Forbidden),
        })
        .await?;
        assert_eq!(code, ExitCode::Auth);
        assert_eq!(
            message,
            "auth: access denied to s3://lake — check that your credentials have \
             s3:ListBucket on arn:aws:s3:::lake"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_missing_bucket_exits_two() -> Result<(), Box<dyn std::error::Error>> {
        let (code, message) = failure(Mock {
            identity: Ok(CALLER.to_owned()),
            bucket: Err(BucketFailure::NotFound),
        })
        .await?;
        assert_eq!(code, ExitCode::Usage);
        assert_eq!(
            message,
            "usage: bucket s3://lake does not exist or is in a different region — check the \
             bucket name and use --region if needed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_redirect_exits_two_naming_the_region() -> Result<(), Box<dyn std::error::Error>> {
        let (code, message) = failure(Mock {
            identity: Ok(CALLER.to_owned()),
            bucket: Err(BucketFailure::WrongRegion(Some("eu-west-1".to_owned()))),
        })
        .await?;
        assert_eq!(code, ExitCode::Usage);
        assert_eq!(
            message,
            "usage: bucket s3://lake is in eu-west-1; rerun with --region eu-west-1"
        );
        Ok(())
    }

    #[tokio::test]
    async fn any_other_head_failure_exits_four() -> Result<(), Box<dyn std::error::Error>> {
        let (code, message) = failure(Mock {
            identity: Ok(CALLER.to_owned()),
            bucket: Err(BucketFailure::Other("connection reset".to_owned())),
        })
        .await?;
        assert_eq!(code, ExitCode::Transport);
        assert!(message.contains("connection reset"), "{message}");
        Ok(())
    }

    #[tokio::test]
    async fn success_logs_the_caller_only_when_asked_to() -> Result<(), Box<dyn std::error::Error>>
    {
        let mock = Mock {
            identity: Ok(CALLER.to_owned()),
            bucket: Ok(()),
        };
        check(&mock, "lake", None).await?;
        let mut log = Vec::new();
        check(&mock, "lake", Some(&mut log)).await?;
        assert_eq!(
            String::from_utf8(log)?,
            format!("lakescan: debug: credentials ok, caller: {CALLER}\n")
        );
        Ok(())
    }

    #[test]
    fn the_pii_hint_names_the_bucket() {
        assert_eq!(
            pii_hint("lake"),
            "lakescan: --pii requires s3:GetObject on arn:aws:s3:::lake/*; add kms:Decrypt if \
             the bucket uses SSE-KMS. Access-denied errors on individual files will appear in \
             the report."
        );
    }

    /// A `HeadBucket` error as the SDK produces it: a status, an optional
    /// region header, and no body.
    fn head_error(
        status: u16,
        region: Option<&str>,
    ) -> Result<SdkError<HeadBucketError, HttpResponse>, Box<dyn std::error::Error>> {
        let mut raw = HttpResponse::new(status.try_into()?, SdkBody::empty());
        if let Some(region) = region {
            raw.headers_mut()
                .try_insert("x-amz-bucket-region", region.to_owned())?;
        }
        let meta = ErrorMetadata::builder().build();
        Ok(SdkError::service_error(HeadBucketError::generic(meta), raw))
    }

    #[test]
    fn head_statuses_classify_into_bucket_failures() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            classify_head_error(&head_error(403, None)?),
            BucketFailure::Forbidden
        );
        assert_eq!(
            classify_head_error(&head_error(404, None)?),
            BucketFailure::NotFound
        );
        assert_eq!(
            classify_head_error(&head_error(301, Some("eu-west-1"))?),
            BucketFailure::WrongRegion(Some("eu-west-1".to_owned()))
        );
        assert_eq!(
            classify_head_error(&head_error(301, None)?),
            BucketFailure::WrongRegion(None)
        );
        assert_eq!(
            classify_head_error(&head_error(400, Some("eu-west-1"))?),
            BucketFailure::WrongRegion(Some("eu-west-1".to_owned()))
        );
        assert!(matches!(
            classify_head_error(&head_error(503, None)?),
            BucketFailure::Other(_)
        ));
        Ok(())
    }
}
