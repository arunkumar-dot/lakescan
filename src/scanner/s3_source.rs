//! The production [`PageSource`]: lists one S3 bucket (optionally scoped to
//! a prefix) via `ListObjectsV2` and converts each entry into an
//! [`ObjectMeta`].
//!
//! # Key encoding
//!
//! Every listing is requested with `encoding-type=url`. An S3 key may
//! contain characters XML 1.0 cannot carry at all (ESC and most other
//! control characters); returned raw, one such key makes the whole response
//! body unparseable, so a single hostile key name could abort an entire
//! audit. URL-encoded, every key is plain ASCII on the wire, and
//! [`decode_url_key`] restores it here. `aws-sdk-s3` itself does not decode:
//! it hands back the `<Key>` text verbatim whatever the encoding type.
//!
//! Decoding follows botocore's handling of this parameter: keys are decoded
//! only when the response itself reports `EncodingType` `url` (a server that
//! ignored the request parameter sent raw keys, which must not be decoded a
//! second time), and `+` decodes to a space, as in
//! `urllib.parse.unquote_plus`. Unlike Python's `unquote_plus`, a malformed
//! `%` escape or a byte sequence that is not UTF-8 is an error rather than
//! being passed through or replaced: reporting a key that does not exist in
//! the bucket would be worse than refusing the page.

use aws_config::BehaviorVersion;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Error;
use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Output;
use aws_sdk_s3::types::{EncodingType, Object};

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
    /// `region`, when given, overrides whatever region that chain resolves.
    /// `endpoint_url`, when given, points the client at an S3-compatible
    /// endpoint instead of AWS and switches to path-style addressing
    /// (`http://host/bucket/key`), which local and self-hosted S3 servers
    /// generally require since they cannot serve a DNS name per bucket.
    ///
    /// # Errors
    /// Returns [`LakeScanError::Usage`] if no AWS region is configured
    /// anywhere in that chain and none was given; `LakeScan` does not guess
    /// a region, since scanning the wrong one silently would be worse than
    /// refusing to start.
    pub async fn new(
        bucket: impl Into<String>,
        prefix: Option<String>,
        region: Option<String>,
        endpoint_url: Option<String>,
    ) -> Result<Self, LakeScanError> {
        let mut loader = aws_config::defaults(BehaviorVersion::latest());
        if let Some(region) = region {
            loader = loader.region(Region::new(region));
        }
        if let Some(endpoint_url) = &endpoint_url {
            loader = loader.endpoint_url(endpoint_url.as_str());
        }
        let config = loader.load().await;

        if config.region().is_none() {
            return Err(LakeScanError::Usage(
                "no AWS region is configured; pass --region, set the AWS_REGION environment \
                 variable, or configure a region in your AWS profile"
                    .to_owned(),
            ));
        }

        let s3_config = aws_sdk_s3::config::Builder::from(&config)
            .force_path_style(endpoint_url.is_some())
            .build();

        Ok(Self {
            client: aws_sdk_s3::Client::from_conf(s3_config),
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
            .max_keys(i32::from(PAGE_SIZE))
            .encoding_type(EncodingType::Url);

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
            encoding_type,
            ..
        } = output;

        let keys_are_url_encoded = encoding_type == Some(EncodingType::Url);
        for object in contents.unwrap_or_default() {
            out.push(convert_object(object, keys_are_url_encoded)?);
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
/// `e_tag` are moved out rather than cloned. When `key_is_url_encoded`, the
/// key is decoded first (see this module's doc).
///
/// A missing or unconvertible field is a [`LakeScanError::Transport`] naming
/// both the field and the key, when the key itself is known; an entry is
/// never silently skipped.
fn convert_object(object: Object, key_is_url_encoded: bool) -> Result<ObjectMeta, LakeScanError> {
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
    let key = if key_is_url_encoded {
        decode_url_key(key)?
    } else {
        key
    };

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

/// Decodes one `encoding-type=url` key: `+` becomes a space and each `%XX`
/// escape becomes the byte it names, and the resulting bytes must be UTF-8.
///
/// Takes the raw key by value and returns it unchanged, without
/// allocating, when it contains nothing to decode — the common case for
/// ordinary keys.
///
/// # Errors
/// Returns [`LakeScanError::Transport`], naming the raw key, if a `%` is not
/// followed by two hex digits or if the decoded bytes are not valid UTF-8.
fn decode_url_key(raw: String) -> Result<String, LakeScanError> {
    if !raw.contains(['%', '+']) {
        return Ok(raw);
    }

    let mut decoded = Vec::with_capacity(raw.len());
    let mut bytes = raw.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'+' => decoded.push(b' '),
            b'%' => {
                let high = bytes.next().and_then(hex_digit_value);
                let low = bytes.next().and_then(hex_digit_value);
                let (Some(high), Some(low)) = (high, low) else {
                    return Err(LakeScanError::Transport(format!(
                        "object key {raw:?} contains a malformed percent escape"
                    )));
                };
                decoded.push((high << 4) | low);
            }
            other => decoded.push(other),
        }
    }

    String::from_utf8(decoded).map_err(|_| {
        LakeScanError::Transport(format!(
            "object key {raw:?} does not percent-decode to valid UTF-8"
        ))
    })
}

/// The value of one ASCII hex digit, either case, or `None` for any other
/// byte.
fn hex_digit_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
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

    use super::{classify_sdk_error, classify_service_error, decode_url_key};
    use crate::error::LakeScanError;

    fn decode(raw: &str) -> Result<String, LakeScanError> {
        decode_url_key(raw.to_owned())
    }

    #[test]
    fn a_key_with_nothing_to_decode_is_returned_unchanged() -> Result<(), LakeScanError> {
        assert_eq!(
            decode("reports/2024/summary.csv")?,
            "reports/2024/summary.csv"
        );
        assert_eq!(decode("")?, "");
        Ok(())
    }

    #[test]
    fn plus_decodes_to_a_space_but_an_escaped_plus_stays_a_plus() -> Result<(), LakeScanError> {
        assert_eq!(decode("a+b")?, "a b");
        assert_eq!(decode("a%2Bb")?, "a+b");
        assert_eq!(decode("a%2bb")?, "a+b");
        Ok(())
    }

    #[test]
    fn an_escaped_percent_decodes_once_only() -> Result<(), LakeScanError> {
        assert_eq!(decode("100%25")?, "100%");
        // `%2541` is an escaped `%` followed by a literal `41`, not `A`.
        assert_eq!(decode("%2541")?, "%41");
        Ok(())
    }

    #[test]
    fn an_escaped_space_decodes_like_plus() -> Result<(), LakeScanError> {
        assert_eq!(decode("my%20file.txt")?, "my file.txt");
        assert_eq!(
            decode("plus%2Band%25percent+space.txt")?,
            "plus+and%percent space.txt"
        );
        Ok(())
    }

    #[test]
    fn control_characters_and_multibyte_utf8_decode() -> Result<(), LakeScanError> {
        assert_eq!(decode("%1B%5B31mred")?, "\u{1b}[31mred");
        assert_eq!(decode("line%0Abreak")?, "line\nbreak");
        // U+00E9 (2 bytes), U+202E (3 bytes), U+1F600 (4 bytes).
        assert_eq!(decode("caf%C3%A9")?, "caf\u{e9}");
        assert_eq!(decode("%E2%80%AEgnp.exe")?, "\u{202e}gnp.exe");
        assert_eq!(decode("%F0%9F%98%80")?, "\u{1f600}");
        Ok(())
    }

    #[test]
    fn already_decoded_multibyte_characters_pass_through() -> Result<(), LakeScanError> {
        assert_eq!(decode("caf\u{e9}+%21")?, "caf\u{e9} !");
        Ok(())
    }

    #[test]
    fn malformed_escapes_are_transport_errors_naming_the_raw_key() {
        for raw in ["50%", "50%4", "%zz", "%4g", "%%41", "a%+1"] {
            assert_transport_error_naming(raw);
        }
    }

    #[test]
    fn bytes_that_are_not_utf8_are_transport_errors_naming_the_raw_key() {
        // A lone continuation byte, a truncated 2-byte sequence, and an
        // overlong encoding of '/'.
        for raw in ["%80", "%C3", "%C0%AF"] {
            assert_transport_error_naming(raw);
        }
    }

    fn assert_transport_error_naming(raw: &str) {
        let result = decode(raw);
        let quoted = format!("{raw:?}");
        assert!(
            matches!(&result, Err(LakeScanError::Transport(message)) if message.contains(&quoted)),
            "{raw:?} should be a Transport error naming the raw key, got {result:?}"
        );
    }

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
