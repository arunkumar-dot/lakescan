//! Thin binary wrapper around the `lakescan` library.
//!
//! All behavior lives in the library; this entry point exists only to run it
//! and to translate the result into a process exit status. For M0 it prints
//! the version and succeeds. Argument parsing arrives with the CLI milestone.

use lakescan::ExitCode;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    println!("lakescan {}", env!("CARGO_PKG_VERSION"));
    ExitCode::Ok.into()
}
