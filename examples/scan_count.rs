//! Manual smoke test for the M1 scanner against a real bucket.
//!
//! Not run by `cargo test` — this is a hand-run check against real AWS
//! credentials, not an automated test:
//!
//! ```text
//! cargo run --example scan_count -- <bucket> [prefix]
//! ```
//!
//! Lists the bucket (optionally scoped to `prefix`) and prints the object
//! count, page count, total bytes, and the largest page length seen.

use lakescan::scanner::{S3Source, Scanner};
use lakescan::{ExitCode, LakeScanError};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => ExitCode::Ok.into(),
        Err(err) => {
            eprintln!("lakescan: {err}");
            ExitCode::from(&err).into()
        }
    }
}

/// Parses arguments, runs the scan, and prints the summary. Kept separate
/// from `main` so every failure path goes through `LakeScanError` and
/// `ExitCode` rather than an early `std::process::exit`.
async fn run() -> Result<(), LakeScanError> {
    let mut args = std::env::args().skip(1);
    let bucket = args
        .next()
        .ok_or_else(|| LakeScanError::Usage("usage: scan_count <bucket> [prefix]".to_owned()))?;
    let prefix = args.next();

    let source = S3Source::new(bucket, prefix).await?;
    let mut scanner = Scanner::new(source);

    let mut object_count: u64 = 0;
    let mut page_count: u64 = 0;
    let mut total_bytes: u128 = 0;
    let mut largest_page_len: usize = 0;

    while let Some(page) = scanner.next_page().await? {
        page_count += 1;
        largest_page_len = largest_page_len.max(page.len());
        object_count += u64::try_from(page.len()).unwrap_or(u64::MAX);

        for object in page {
            total_bytes += u128::from(object.size);
        }
    }

    println!("objects:      {object_count}");
    println!("pages:        {page_count}");
    println!("total bytes:  {total_bytes}");
    println!("largest page: {largest_page_len}");

    Ok(())
}
