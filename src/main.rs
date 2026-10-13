//! Thin binary wrapper around the `lakescan` library.
//!
//! All behavior, argument parsing included, lives in [`lakescan::cli`]; this
//! entry point only collects the process arguments, runs the CLI, and hands
//! its [`lakescan::ExitCode`] back to the operating system.

#[tokio::main]
async fn main() -> std::process::ExitCode {
    lakescan::cli::run(std::env::args_os()).await.into()
}
