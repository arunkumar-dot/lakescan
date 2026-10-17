# Contributing to LakeScan

Thank you for your interest. Before opening a large pull request, please open an issue first so we can discuss whether it fits the project's direction.

## Running the quality gates

You need Rust 1.94.1 or newer. The five gates CI runs, in order:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo check --all-targets --all-features
cargo test --all-features
cargo build --release && ./target/release/lakescan --version
```

All five must pass before a pull request can be merged.

## Running the end-to-end tests

The e2e tests require Docker and run against a local moto server. On macOS, AirPlay Receiver holds port 5000, so map 5001:

```bash
docker run --rm -d --name lakescan-moto -p 5001:5000 motoserver/moto:5.2.3

AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1 \
  cargo run --example seed_local -- http://localhost:5001

AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1 \
  LAKESCAN_E2E_ENDPOINT=http://localhost:5001 \
  cargo test --test e2e --test e2e_pii -- --ignored

docker stop lakescan-moto
```

## What a good contribution looks like

- Fixes are welcome at any size. For new features, open an issue first.
- Follow the existing lint policy: no `#[allow]`, no `unwrap`, `expect`, `panic!` or indexing in production code.
- Every new behaviour needs a test. The e2e tests are the right place for anything that touches S3.
- Memory must not grow with bucket size. Every new aggregate structure needs a `MAX_BYTES` constant and a test that enforces it.
- If you add a rule, give it a frozen code. If you add a JSON field, document it in `src/report/mod.rs` and update the drift guard in `tests/readme.rs`.

## Licence

By contributing, you agree that your contribution is licensed under the same terms as the project (FSL-1.1-ALv2).
