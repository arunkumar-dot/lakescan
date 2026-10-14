//! Seeds a local S3-compatible server with the `LakeScan` demo bucket and
//! the content-scanning (PII) bucket.
//!
//! ```text
//! cargo run --example seed_local -- <endpoint-url>
//! ```
//!
//! Meant for an in-memory fake such as moto in server mode
//! (`docker run -p 5000:5000 motoserver/moto:5.2.3`), which accepts any
//! credentials. (Re)creates the `lakescan-demo` bucket, uploads every object
//! in `tests/support/seed_manifest.rs`, then lists the bucket back through
//! `LakeScan`'s own scanner and checks that every key arrived intact in the
//! storage class it was written with. Any upload the server rejected, and
//! any key or storage class it did not store faithfully, is reported by
//! name, and the run exits non-zero. It then (re)creates `lakescan-pii`
//! with the Parquet fixtures listed in `tests/support/pii_manifest.rs`.
//!
//! The region comes from the usual AWS configuration chain, defaulting to
//! `us-east-1` when none is configured.

#[path = "../tests/support/pii_manifest.rs"]
mod pii_manifest;
#[path = "../tests/support/seed_manifest.rs"]
mod seed_manifest;

use std::collections::BTreeMap;
use std::error::Error;

use aws_config::BehaviorVersion;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::Client;
use aws_sdk_s3::error::DisplayErrorContext;
use aws_sdk_s3::operation::head_bucket::HeadBucketError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::StorageClass;
use lakescan::scanner::{S3Source, Scanner};
use tokio::task::JoinSet;

use pii_manifest::{PII_BUCKET, PII_OBJECTS};
use seed_manifest::{BUCKET, SeedObject};

/// How many requests are in flight at once.
const CONCURRENCY: usize = 64;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("seed_local: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let endpoint = std::env::args()
        .nth(1)
        .ok_or("usage: cargo run --example seed_local -- <endpoint-url>")?;

    let config = aws_config::defaults(BehaviorVersion::latest())
        .region(RegionProviderChain::default_provider().or_else("us-east-1"))
        .endpoint_url(endpoint.as_str())
        .load()
        .await;
    let region = config.region().map(ToString::to_string);
    let client = Client::from_conf(
        aws_sdk_s3::config::Builder::from(&config)
            .force_path_style(true)
            .build(),
    );

    recreate_bucket(&client, BUCKET, &endpoint, region.clone()).await?;

    let mut objects = seed_manifest::objects();
    let rejected = upload(&client, &objects).await?;
    let written = objects.len() - rejected.len();
    for (key, storage_class, reason) in &rejected {
        eprintln!("rejected: {key:?} ({storage_class}): {reason}");
    }

    let mut mismatches = verify(BUCKET, &endpoint, region.clone(), &objects).await?;
    println!("wrote {written} objects to s3://{BUCKET} at {endpoint}");

    recreate_bucket(&client, PII_BUCKET, &endpoint, region.clone()).await?;
    objects = PII_OBJECTS
        .iter()
        .map(|(key, path)| {
            Ok(SeedObject {
                key: (*key).to_owned(),
                body: pii_manifest::fixture(path)?,
                storage_class: "STANDARD",
            })
        })
        .collect::<Result<_, std::io::Error>>()?;
    let mut pii_rejected = upload_to(&client, PII_BUCKET, &objects).await?;
    for (key, storage_class, reason) in &pii_rejected {
        eprintln!("rejected: {key:?} ({storage_class}): {reason}");
    }
    mismatches.extend(verify(PII_BUCKET, &endpoint, region, &objects).await?);
    for mismatch in &mismatches {
        eprintln!("mismatch: {mismatch}");
    }
    println!(
        "wrote {} objects to s3://{PII_BUCKET} at {endpoint}",
        objects.len() - pii_rejected.len()
    );

    let mut rejected = rejected;
    rejected.append(&mut pii_rejected);
    if rejected.is_empty() && mismatches.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} upload(s) rejected and {} listing mismatch(es); see above",
            rejected.len(),
            mismatches.len()
        )
        .into())
    }
}

/// Deletes `bucket` and everything in it, if it exists, then creates it
/// empty.
async fn recreate_bucket(
    client: &Client,
    bucket: &str,
    endpoint: &str,
    region: Option<String>,
) -> Result<(), Box<dyn Error>> {
    match client.head_bucket().bucket(bucket).send().await {
        Ok(_) => {
            // Listed through `LakeScan`'s scanner rather than a plain
            // `ListObjectsV2` call: a previous run's hostile keys would make
            // an unencoded listing response unparseable.
            let keys = list(bucket, endpoint, region)
                .await?
                .into_keys()
                .collect::<Vec<_>>();
            for chunk in keys.chunks(CONCURRENCY) {
                let mut tasks = JoinSet::new();
                for key in chunk {
                    let request = client.delete_object().bucket(bucket).key(key);
                    tasks.spawn(request.send());
                }
                while let Some(joined) = tasks.join_next().await {
                    joined?.map_err(|err| DisplayErrorContext(err).to_string())?;
                }
            }
            client
                .delete_bucket()
                .bucket(bucket)
                .send()
                .await
                .map_err(|err| DisplayErrorContext(err).to_string())?;
        }
        Err(err)
            if err
                .as_service_error()
                .is_some_and(HeadBucketError::is_not_found) => {}
        Err(err) => return Err(DisplayErrorContext(err).to_string().into()),
    }

    client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .map_err(|err| DisplayErrorContext(err).to_string())?;
    Ok(())
}

/// Uploads every object to the demo bucket; see [`upload_to`].
async fn upload(
    client: &Client,
    objects: &[SeedObject],
) -> Result<Vec<(String, &'static str, String)>, Box<dyn Error>> {
    upload_to(client, BUCKET, objects).await
}

/// Uploads every object to `bucket`, `CONCURRENCY` at a time, and returns
/// the ones the server rejected as `(key, storage class, reason)`.
async fn upload_to(
    client: &Client,
    bucket: &str,
    objects: &[SeedObject],
) -> Result<Vec<(String, &'static str, String)>, Box<dyn Error>> {
    let mut rejected = Vec::new();
    for chunk in objects.chunks(CONCURRENCY) {
        let mut tasks = JoinSet::new();
        for object in chunk {
            let request = client
                .put_object()
                .bucket(bucket)
                .key(object.key.as_str())
                .storage_class(StorageClass::from(object.storage_class))
                .body(ByteStream::from(object.body.clone()));
            let key = object.key.clone();
            let storage_class = object.storage_class;
            tasks.spawn(async move {
                request
                    .send()
                    .await
                    .map(|_| ())
                    .map_err(|err| (key, storage_class, DisplayErrorContext(err).to_string()))
            });
        }
        while let Some(joined) = tasks.join_next().await {
            if let Err(failure) = joined? {
                rejected.push(failure);
            }
        }
    }
    Ok(rejected)
}

/// Lists the bucket back and describes every way it differs from
/// `objects`: a key missing, a key not in the manifest, or a storage class
/// other than the one written.
async fn verify(
    bucket: &str,
    endpoint: &str,
    region: Option<String>,
    objects: &[SeedObject],
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut listed = list(bucket, endpoint, region).await?;
    let mut mismatches = Vec::new();
    for object in objects {
        match listed.remove(&object.key) {
            None => mismatches.push(format!("{:?} is missing from the listing", object.key)),
            Some(class) if class != object.storage_class => mismatches.push(format!(
                "{:?} was written as {} but listed as {class}",
                object.key, object.storage_class
            )),
            Some(_) => {}
        }
    }
    for key in listed.into_keys() {
        mismatches.push(format!("{key:?} is listed but was never written"));
    }
    Ok(mismatches)
}

/// Every key in `bucket` and its storage class's wire name.
async fn list(
    bucket: &str,
    endpoint: &str,
    region: Option<String>,
) -> Result<BTreeMap<String, String>, Box<dyn Error>> {
    let source = S3Source::new(bucket, None, region, Some(endpoint.to_owned())).await?;
    let mut scanner = Scanner::new(source);
    let mut listed = BTreeMap::new();
    while let Some(page) = scanner.next_page().await? {
        for object in page {
            listed.insert(
                object.key.clone(),
                object.storage_class.as_wire().to_owned(),
            );
        }
    }
    Ok(listed)
}
