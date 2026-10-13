# LakeScan

LakeScan audits an S3 bucket from its object listing. It pages through
`ListObjectsV2`, checks every object against a small set of rules (secret-looking
keys, deprecated or wasteful storage classes, stale data, empty objects), sets
aside findings you have explicitly accepted, and writes a summary as text or
JSON. It exits with a code your CI can act on.

Where the product is headed, and why, is in [docs/PRODUCT.md](docs/PRODUCT.md).

Memory use does not grow with the bucket. Every stage has a fixed budget: one
listing page in flight, fixed-size summaries, and a streaming writer. Scanning
ten objects or ten billion uses the same memory.

## Install

LakeScan is not published yet. Build it from source with Rust 1.94.1 or newer:

```sh
git clone https://github.com/arunkumar-dot/lakescan.git
cd lakescan
cargo build --release
./target/release/lakescan --version
```

## Quickstart: the local demo

The repository includes a seeder that fills a local S3 fake with a demo bucket.
That bucket has 2,413 objects across three listing pages, a few planted
problems, and some hostile key names. This needs Docker and no AWS account.

```sh
# 1. Start moto, an in-memory S3 fake that accepts any credentials.
#    On macOS, AirPlay Receiver already listens on port 5000, so map 5001.
docker run --rm -d --name lakescan-moto -p 5001:5000 motoserver/moto:5.2.3

# 2. Any credentials work against moto.
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1

# 3. Create and fill the lakescan-demo bucket.
cargo run --example seed_local -- http://localhost:5001

# 4. Scan it.
cargo run --release -- scan s3://lakescan-demo --endpoint-url http://localhost:5001
echo "exit code: $?"    # 1: the bucket has High findings

docker stop lakescan-moto
```

On Linux, or with AirPlay Receiver turned off, you can use `-p 5000:5000` and
`http://localhost:5000` instead.

## Usage

```text
lakescan scan <TARGET> [OPTIONS]
lakescan rules
lakescan --help | --version
```

`lakescan rules` prints every rule's code and title, one per line.

`lakescan scan` lists `<TARGET>`, which must be `s3://bucket` or
`s3://bucket/prefix`. An empty prefix (`s3://bucket/`) scans the whole bucket.
AWS credentials and the region come from the standard AWS configuration chain:
environment variables, shared config and credentials files, then
container or instance credentials.

| Flag | Default | Meaning |
|---|---|---|
| `--format text\|json` | `text` | Summary format. |
| `--output <PATH>` | stdout | Write the summary to `PATH`. `-` means stdout. |
| `--findings <PATH>` | off | Also stream every unsuppressed finding to `PATH` as JSON Lines, one record per finding, as it is found. `-` means stdout, which then requires `--output` to name a file. |
| `--fail-on <LEVEL>` | `high` | Exit 1 when the worst unsuppressed finding is at or above `LEVEL`: `info`, `low`, `medium`, `high`, `critical`, or `none` (never fail on findings). |
| `--region <REGION>` | from config | Overrides the configured AWS region. |
| `--endpoint-url <URL>` | AWS | An S3-compatible endpoint (`http://` or `https://`). Implies path-style addressing. |
| `--config <PATH>` | none | A suppression file (see [Suppressions](#suppressions)). Only used when given; never discovered automatically. |
| `--quiet` | off | No progress line and no suppression warnings on stderr. |

A progress line (`scanned N objects, M findings`) is shown on stderr only when
stderr is a terminal. Errors print one line to stderr, `lakescan: <error>`.

## Exit codes

The numbers are a stable contract. CI can branch on them.

| Code | Name | Meaning |
|---|---|---|
| 0 | `Ok` | The scan completed and no unsuppressed finding reached `--fail-on`. |
| 1 | `FindingsExceedThreshold` | The scan completed, but an unsuppressed finding reached `--fail-on`. |
| 2 | `Usage` | Bad arguments, an invalid target or config file, a nonexistent bucket, or a region mismatch. |
| 3 | `Auth` | Credentials are missing, expired, or rejected. |
| 4 | `Transport` | The network or S3 failed (DNS, TLS, timeouts, 5xx, an unparseable response). Often worth retrying. |
| 5 | `Report` | The summary or findings stream could not be written (full disk, bad path, permissions). |

A closed pipe (`lakescan ... | head`) is not an error.

## Rules

Rules see only what a listing reports for each object: key, size,
last-modified time, ETag, and storage class.

| Code | Severities | Flags | Why |
|---|---|---|---|
| `sensitive-key` | high, medium | High: a key whose name is a secret file on its own (`.env`, `.env.*` except `.example`/`.sample`/`.template`, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.htpasswd`, `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`) or ends in `.tfstate`, `.tfstate.backup`, `.ppk`, `.kdbx`. Medium: a name ending in `.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.keystore`, or any key under a `.git/` or `.ssh/` directory. Matching is case-insensitive. | Credentials in a data lake get copied, shared and exposed far more easily than credentials in a secrets manager. |
| `reduced-redundancy` | medium | Objects in `REDUCED_REDUNDANCY`. | The class is deprecated: it gives up durability and is no longer cheaper than `STANDARD`. |
| `stale-standard` | low, medium | `STANDARD` objects unmodified for more than 90 days. Low at 128 KiB or more, medium at 1 GiB or more. Smaller objects are never flagged. | They are candidates for a cheaper class or a lifecycle rule. Below 128 KiB, IA classes bill a minimum size and Intelligent-Tiering won't tier the object, so moving it would cost more. |
| `small-object-cold-tier` | low | Objects under 128 KiB in `STANDARD_IA`, `ONEZONE_IA`, `GLACIER_IR`, `GLACIER` or `DEEP_ARCHIVE`. | These classes bill a minimum object size (and Glacier adds per-object overhead), so small objects cost more there than in `STANDARD`. |
| `zero-byte-object` | info | Empty objects whose key does not end in `/`. | These are usually failed uploads or leftover scaffolding. Empty `folder/` markers are what consoles create, and they are not flagged. |
| `unknown-storage-class` | info | A storage class this build of LakeScan does not recognize. | This is a newer class than this build knows about. The other rules cannot judge such an object, so LakeScan says so instead of guessing. |

No v1 rule raises `critical`: a listing alone cannot prove an object is
exposed.

## Suppressions

Some findings are expected, such as a public example key in your docs or a
scratch prefix full of placeholders. List them in a TOML file and pass it with
`--config`:

```toml
version = 1

# One exact key, for one bucket, until a date.
[[suppress]]
rule = "sensitive-key"
key = "docs/examples/id_rsa"
reason = "Public example key used in our docs"
expires = 2027-01-31       # quoted "2027-01-31" works too
bucket = "my-bucket"       # only applies when scanning my-bucket

# Everything under a prefix.
[[suppress]]
rule = "zero-byte-object"
prefix = "tmp/"
reason = "Scratch space for the nightly job"

# An empty prefix suppresses a rule for the whole bucket.
[[suppress]]
rule = "stale-standard"
prefix = ""
reason = "Archive bucket: everything here is stale by design"
```

Each `[[suppress]]` entry has:

| Field | Required | Meaning |
|---|---|---|
| `rule` | yes | A rule code from the table above. |
| `key` / `prefix` | exactly one | `key` matches one key exactly. `prefix` matches every key that starts with it, and `""` matches all keys. |
| `reason` | yes | Why the finding is acceptable. Must not be blank. |
| `expires` | no | The last day (UTC) the entry applies. The day after, it stops suppressing and is reported as expired. |
| `bucket` | no | The entry applies only when scanning this bucket. For any other bucket it is ignored completely, and never reported as unused or expired. |

When several entries match a finding, the first one in the file wins.

A suppressed finding still counts, but only as suppressed. It does not appear
in the findings matrix, does not affect the verdict or exit code, and is not
written to the `--findings` stream. The summary shows each rule's suppressed
count. Its SUPPRESSIONS section (and `suppressions` in JSON) lists entries that
have **expired** and active entries that were **unused**, meaning they
suppressed nothing in this scan. Unless `--quiet` is given, each of those also
gets a one-line warning on stderr.

LakeScan refuses to start (exit code 2) on a config file it cannot fully
understand. The error message names the file and the offending entry. That
covers:

- `version` other than 1
- an unknown field (a typo like `reson` fails rather than being ignored)
- an unknown rule
- a blank reason
- both or neither of `key`/`prefix`
- a malformed date
- more than 10,000 entries
- a key or prefix over 1 KiB, a reason over 1 KiB, or a bucket name over 63 bytes
- a missing or unreadable file

## JSON output

`--format json` writes one JSON object. The full schema is documented in
[`src/report/mod.rs`](src/report/mod.rs). Its top-level fields:

- `schema_version`: currently `1`
- `tool`: name and version
- `scan`: bucket, prefix, start time (RFC 3339, UTC) and elapsed milliseconds
- `verdict`: `worst_severity`, or `null`
- `inventory`: object and byte totals, overall and per storage class
- `findings`: per rule, counts and bytes per severity plus `suppressed`
  `{count, bytes}`
- `suppressions`: `expired` and `unused` entries
- `samples`: up to 10 example findings per rule
- `largest_objects`: the 20 largest objects
- `size_histogram`, `age_histogram`
- `distinct_content`: an ETag-based estimate of distinct content, plus
  `duplicates_significant` (whether the duplicates exceed estimator error)

`--findings` writes one JSON object per line:
`{"key", "rule", "severity", "size", "storage_class", "last_modified"}`. Keys are
written in full and JSON-escaped, so any key round-trips exactly.

**Compatibility policy.** `schema_version` stays the same as long as changes are
additive: new fields, new sections, new list entries. Consumers should ignore
fields they don't recognize. Removing or renaming a field, changing its type, or
changing what it means bumps `schema_version`.

## Limitations

- **Listing data only.** LakeScan never reads object contents, bucket
  policies, ACLs, Block Public Access settings, or encryption configuration.
  It cannot tell you whether an object is public or encrypted, only whether
  its name, size, age and class look wrong.
- **`stale-standard` measures last modification, not last access.** A listing
  has no access time, so an object read every day but written two years ago
  is still flagged as stale.
- **Duplicate detection is a lower bound.** Duplicates are estimated from
  `(ETag, size)` pairs with a HyperLogLog sketch (about 1% error). The same
  content uploaded with a different multipart chunking, or encrypted with
  SSE-KMS or SSE-C, gets a different ETag and is not detected. Differences
  under about 2% of the object count are within the estimator's error and are
  reported as "no duplicates detected".
- **Keys are matched as listed.** Suppression keys and prefixes are compared
  byte for byte with the decoded S3 key. No glob or case folding is applied.

## Development

The five gates CI runs, in order:

```sh
cargo fmt --all -- --check                                   # 1. formatting
cargo clippy --all-targets --all-features -- -D warnings     # 2. lints
cargo check --all-targets --all-features                     # 3. check
cargo test --all-features                                    # 4. tests
cargo build --release && ./target/release/lakescan --version # 5. release build + smoke
```

The minimum supported Rust version is **1.94.1**, which CI also checks.
`rust-toolchain.toml` pins stable, so name the toolchain explicitly:

```sh
rustup toolchain install 1.94.1
cargo +1.94.1 check --all-targets
```

The end-to-end tests run the built binary against a seeded moto server. They
are `#[ignore]`d by default:

```sh
docker run --rm -d --name lakescan-moto -p 5001:5000 motoserver/moto:5.2.3
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1
export LAKESCAN_E2E_ENDPOINT=http://localhost:5001
cargo run --example seed_local -- "$LAKESCAN_E2E_ENDPOINT"
cargo test --test e2e -- --ignored
docker stop lakescan-moto
```

## License

Licensed under the [Functional Source License, Version 1.1, ALv2 Future License](LICENSE)
(FSL-1.1-ALv2).
