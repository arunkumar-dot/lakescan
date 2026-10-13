//! [`Target`]: the `s3://bucket[/prefix]` argument to `lakescan scan`.

use std::str::FromStr;

use crate::error::LakeScanError;

/// What a scan lists: one bucket, optionally scoped to a key prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    /// The bucket name, never empty.
    pub(crate) bucket: String,
    /// The key prefix, or `None` when the target names the whole bucket. An
    /// empty prefix (`s3://bucket/`) is the same as none.
    pub(crate) prefix: Option<String>,
}

impl FromStr for Target {
    type Err = LakeScanError;

    /// Parses `s3://bucket` or `s3://bucket/prefix`. Everything after the
    /// first `/` following the bucket is the prefix, verbatim, so
    /// `s3://bucket/a/b/` scopes to the prefix `a/b/`.
    ///
    /// # Errors
    /// Returns [`LakeScanError::Usage`] for anything else: a missing or
    /// different scheme, or an empty bucket name.
    fn from_str(target: &str) -> Result<Self, Self::Err> {
        let invalid = || {
            LakeScanError::Usage(format!(
                "invalid target {target:?}: expected s3://bucket or s3://bucket/prefix"
            ))
        };

        let rest = target.strip_prefix("s3://").ok_or_else(invalid)?;
        let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
        if bucket.is_empty() {
            return Err(invalid());
        }

        Ok(Self {
            bucket: bucket.to_owned(),
            prefix: (!prefix.is_empty()).then(|| prefix.to_owned()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Target;
    use crate::error::LakeScanError;

    fn target(bucket: &str, prefix: Option<&str>) -> Target {
        Target {
            bucket: bucket.to_owned(),
            prefix: prefix.map(str::to_owned),
        }
    }

    #[test]
    fn a_bare_bucket_has_no_prefix() -> Result<(), LakeScanError> {
        assert_eq!(
            "s3://my-bucket".parse::<Target>()?,
            target("my-bucket", None)
        );
        Ok(())
    }

    #[test]
    fn an_empty_prefix_means_none() -> Result<(), LakeScanError> {
        assert_eq!(
            "s3://my-bucket/".parse::<Target>()?,
            target("my-bucket", None)
        );
        Ok(())
    }

    #[test]
    fn everything_after_the_bucket_is_the_prefix_verbatim() -> Result<(), LakeScanError> {
        assert_eq!(
            "s3://my-bucket/logs/2024/".parse::<Target>()?,
            target("my-bucket", Some("logs/2024/"))
        );
        assert_eq!(
            "s3://my-bucket//double".parse::<Target>()?,
            target("my-bucket", Some("/double"))
        );
        Ok(())
    }

    #[test]
    fn anything_else_is_a_usage_error() {
        for bad in [
            "",
            "my-bucket",
            "s3:/my-bucket",
            "S3://my-bucket",
            "https://my-bucket",
            "s3://",
            "s3:///prefix",
        ] {
            assert!(
                matches!(bad.parse::<Target>(), Err(LakeScanError::Usage(_))),
                "{bad:?} should be a usage error"
            );
        }
    }
}
