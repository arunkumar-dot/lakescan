#!/usr/bin/env bash
# A guided, hands-on tour of LakeScan against a local S3 fake (moto).
#
#   scripts/demo.sh             pause before each step (press Enter)
#   scripts/demo.sh --no-pause  run straight through
#
# Needs Docker and a Rust toolchain; no AWS account. It starts moto on host
# port 5001, builds the release binary, seeds the two demo buckets with the
# repository's seeder, then walks through every feature. Each step prints a
# one-line explanation, the command, its output, and what its exit code
# means. Files it writes go to target/demo/ (git-ignored) and are kept, so
# you can open them afterwards. moto is stopped when the script exits.
#
# Walked through, with real output, in docs/TUTORIAL.md.

set -uo pipefail

MOTO_IMAGE="motoserver/moto:5.2.3"
MOTO_CONTAINER="lakescan-demo-moto"
ENDPOINT="http://localhost:5001"

PAUSE=1
for arg in "$@"; do
  case "$arg" in
    --no-pause) PAUSE=0 ;;
    -h | --help)
      sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "demo.sh: unknown argument: $arg (try --help)" >&2
      exit 2
      ;;
  esac
done

REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO/target/demo"
LAKESCAN="$REPO/target/release/lakescan"

if [ -t 1 ]; then
  BOLD=$'\033[1m' DIM=$'\033[2m' CYAN=$'\033[36m' RESET=$'\033[0m'
else
  BOLD="" DIM="" CYAN="" RESET=""
fi

die() {
  echo "demo.sh: $*" >&2
  exit 1
}

# step <id> <title> <one-line explanation>
step() {
  echo
  echo "${BOLD}${CYAN}== Step $1: $2${RESET}"
  echo "$3"
  pause
}

pause() {
  if [ "$PAUSE" = 1 ]; then
    printf '%s' "${DIM}[Enter to run]${RESET} "
    read -r _ || true
  fi
}

# show <command...>: print the command as you would type it.
show() {
  echo "${BOLD}\$ $*${RESET}"
}

# note <text>: what to notice.
note() {
  echo "${DIM}->${RESET} $*"
}

# meaning <code>: the exit-code contract, from README.md.
meaning() {
  case "$1" in
    0) echo "Ok: the scan completed and no unsuppressed finding reached --fail-on" ;;
    1) echo "FindingsExceedThreshold: an unsuppressed finding reached --fail-on" ;;
    2) echo "Usage: bad arguments, target or config file" ;;
    3) echo "Auth: credentials missing, expired or rejected" ;;
    4) echo "Transport: the network or S3 failed" ;;
    5) echo "Report: an output could not be written" ;;
    6) echo "ContentNotScanned: a Parquet file could not be scanned and is not documented" ;;
    *) echo "outside the contract (101 is an internal error)" ;;
  esac
}

# exit_code <code> <why>: print the code, its contract meaning, and why
# this run got it.
exit_code() {
  echo "${BOLD}exit code: $1${RESET} ($(meaning "$1"))"
  [ -n "${2:-}" ] && note "$2"
}

# sections <"HEADER|HEADER"> <file>: print only those sections of a text
# summary. Sections are paragraphs whose first line is the header.
sections() {
  awk -v want="$1" '
    BEGIN { RS = ""; n = split(want, w, "|") }
    { split($0, line, "\n"); for (i = 1; i <= n; i++) if (line[1] == w[i]) { print; print "" } }
  ' "$2"
}

# pretty <json file>: jq if installed, else Python.
pretty() {
  if command -v jq >/dev/null 2>&1; then
    jq . "$1"
  else
    python3 -m json.tool "$1"
  fi
}

cleanup() {
  if [ -n "${STARTED_MOTO:-}" ]; then
    echo
    echo "Stopping moto ($MOTO_CONTAINER)..."
    docker stop "$MOTO_CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ---------------------------------------------------------------- setup

echo "${BOLD}LakeScan demo${RESET}: every feature, against a local S3 fake."
echo "Outputs go to $OUT"

step 0 "Setup" "Start moto (an in-memory S3 fake) on port 5001, build LakeScan, and seed the demo buckets."

docker info >/dev/null 2>&1 || die "Docker is not running. Start Docker Desktop (or the docker daemon) and try again."

show docker run --rm -d --name "$MOTO_CONTAINER" -p 5001:5000 "$MOTO_IMAGE"
if ! docker run --rm -d --name "$MOTO_CONTAINER" -p 5001:5000 "$MOTO_IMAGE" >/dev/null; then
  die "could not start moto. Is port 5001 in use, or is a '$MOTO_CONTAINER' container already running? (docker ps; docker stop <name>)"
fi
STARTED_MOTO=1
for _ in $(seq 1 60); do
  curl -s -o /dev/null "$ENDPOINT" && break
  sleep 0.5
done
curl -s -o /dev/null "$ENDPOINT" || die "moto did not answer on $ENDPOINT"
note "moto is up on $ENDPOINT (on macOS, AirPlay Receiver owns port 5000, hence 5001)"

# moto accepts any credentials; these keep the AWS SDK from looking for real ones.
show export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1
unset AWS_PROFILE AWS_SESSION_TOKEN

if ! command -v cargo >/dev/null 2>&1 && [ -x "$HOME/.cargo/bin/cargo" ]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi
command -v cargo >/dev/null 2>&1 || die "cargo not found; install Rust from https://rustup.rs"

cd "$REPO" || die "cannot enter $REPO"
show cargo build --release
cargo build --release || die "cargo build --release failed"
show cargo run --release --example seed_local -- "$ENDPOINT"
cargo run --release --quiet --example seed_local -- "$ENDPOINT" || die "seeding failed"
note "lakescan-demo: 2,413 small objects with planted problems; lakescan-pii: 11 Parquet files"

mkdir -p "$OUT"
cd "$OUT" || die "cannot enter $OUT"
rm -f summary.json pii-summary.txt inventory.csv demo.toml findings.jsonl report.html ./*-c1.* ./*-c16.* \
  documented*.txt documented*.csv
S3_DEMO="s3://lakescan-demo"
S3_PII="s3://lakescan-pii"
# In the commands below, `lakescan` is target/release/lakescan.
lakescan() { "$LAKESCAN" "$@"; }

# ---------------------------------------------------------------- a

step a "lakescan rules" "List every rule LakeScan knows: six metadata rules (free), then the PII content rules (--pii)."
show lakescan rules
lakescan rules
exit_code $? "Listing rules never fails."

# ---------------------------------------------------------------- b

step b "Metadata-only scan" "Scan the demo bucket from its listing alone: keys, sizes, dates, storage classes. No object is read."
show lakescan scan "$S3_DEMO" --endpoint-url "$ENDPOINT"
lakescan scan "$S3_DEMO" --endpoint-url "$ENDPOINT"
exit_code $? "Three keys look like secrets (sensitive-key, high), and high is the default --fail-on threshold."

# ---------------------------------------------------------------- c

step c "The same scan as JSON" "The same results as one JSON object, for scripts and dashboards. Shown pretty-printed, first 45 lines."
show lakescan scan "$S3_DEMO" --endpoint-url "$ENDPOINT" --format json --quiet '>' summary.json
lakescan scan "$S3_DEMO" --endpoint-url "$ENDPOINT" --format json --quiet >summary.json
code=$?
show pretty-print summary.json '|' head -45
pretty summary.json | head -45
echo "  ... (full file: $OUT/summary.json)"
exit_code "$code" "Same findings, same exit code: the format changes nothing else."

# ---------------------------------------------------------------- d

step d "PII scan" "With --pii, LakeScan also reads Parquet files and reports which columns hold personal data (never the values)."
show lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii '>' pii-summary.txt
lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii >pii-summary.txt
code=$?
sections "VERDICT|FINDINGS|CONTENT|COVERAGE|PII INVENTORY" pii-summary.txt
echo "  ... (SAMPLES, LARGEST OBJECTS and histograms omitted; full summary: $OUT/pii-summary.txt)"
exit_code "$code" "Not 1, although confirmed PII is high: 3 Parquet files could not be scanned and nobody documented them. Coverage fails closed, and 6 takes precedence over 1."

# ---------------------------------------------------------------- e

step e "PII inventory as CSV" "--inventory writes the inventory as CSV: one row per table, column and PII rule, for auditors and spreadsheets."
show lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --inventory inventory.csv --quiet '>' /dev/null
lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --inventory inventory.csv --quiet >/dev/null
code=$?
show head -6 inventory.csv
head -6 inventory.csv | tr -d '\r'
echo "  ... ($(($(wc -l <inventory.csv) - 1)) rows; full file: $OUT/inventory.csv)"
note "Every row says UNDOCUMENTED: nothing has been documented yet."
exit_code "$code" "Still 6: the CSV is an extra output, the same 3 files are still unscanned and undocumented."

# ---------------------------------------------------------------- f

step f1 "Document one PII column and one unscannable file" "A --config file records what is known and accepted: each entry names a rule, where it applies, and why."
cat >demo.toml <<'EOF'
version = 1

# Document a PII location: the email column of the customers table.
[[suppress]]
rule = "pii-email"
prefix = "lake/customers/"
column = "email"
reason = "Consented marketing contacts, DPA-12"
expires = 2027-06-30

# Document one file that cannot be scanned.
[[suppress]]
rule = "content-not-scanned"
key = "bad/not_parquet.parquet"
reason = "A CSV export misnamed .parquet; no personal data, reviewed 2026-10-16"
EOF
show cat demo.toml
cat demo.toml
echo
show lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --config demo.toml '>' documented-1.txt
lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --config demo.toml >documented-1.txt
code=$?
sections "COVERAGE" documented-1.txt
sed -n '/^PII INVENTORY/,/^  lake\/customers_brotli/p' documented-1.txt | sed '$d'
echo "  ... (full summary: $OUT/documented-1.txt)"
note "email is now 'documented' with its reason; billing.email is a different column and stays UNDOCUMENTED."
note "COVERAGE: 1 documented, 2 undocumented."
exit_code "$code" "Still 6: one undocumented unscannable file is enough to fail, and two remain. That is fail-closed."

step f2 "Document the other two unscannable files" "Add entries for the truncated file and the file whose every column was skipped, then rerun."
cat >>demo.toml <<'EOF'

[[suppress]]
rule = "content-not-scanned"
key = "bad/truncated.parquet"
reason = "Known-corrupt partial upload, kept for the incident record"

[[suppress]]
rule = "content-not-scanned"
prefix = "skipped/"
reason = "Oversized test pages; reviewed, no production data"
EOF
show tail -10 demo.toml
tail -10 demo.toml
echo
show lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --config demo.toml --inventory documented.csv '>' documented-2.txt
lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --config demo.toml --inventory documented.csv >documented-2.txt
code=$?
sections "COVERAGE" documented-2.txt
sed -n '/^PII INVENTORY/,/^    not scanned/p' documented-2.txt
show "grep ',documented,' documented.csv"
grep ',documented,' documented.csv | tr -d '\r'
exit_code "$code" "Changed from 6 to 1: coverage is fully accounted for, so the verdict now rests on the findings, and 30 PII columns are still undocumented (confirmed = high)."

# ---------------------------------------------------------------- g

step g "Findings stream" "--findings streams every unsuppressed finding as JSON Lines while the scan runs, for jq, SIEMs or tickets."
show lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --findings findings.jsonl --quiet '>' /dev/null
lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --findings findings.jsonl --quiet >/dev/null
code=$?
echo "$(wc -l <findings.jsonl | tr -d ' ') findings; two PII ones:"
show "grep '\"rule\":\"pii-' findings.jsonl | head -2"
grep '"rule":"pii-' findings.jsonl | head -2
note "A finding names the file, column, confidence and counts (matched/sampled). It never carries a value."
show grep -c @ findings.jsonl
grep -c @ findings.jsonl
note "0: no '@' anywhere, though there are 15 pii-email findings. No email address leaves the scanner."
exit_code "$code" "6 again: this run has no --config, so the 3 unscannable files are undocumented."

# ---------------------------------------------------------------- h

step h "HTML report" "--html writes one self-contained page (no network requests) to open, print or send. With demo.toml, so it shows documented entries."
show lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --config demo.toml --html report.html --quiet '>' /dev/null
lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --config demo.toml --html report.html --quiet >/dev/null
code=$?
ls -l report.html | awk '{print "report.html: " $5 " bytes"}'
if command -v open >/dev/null 2>&1; then
  show open report.html
  open report.html
elif command -v xdg-open >/dev/null 2>&1; then
  show xdg-open report.html
  xdg-open report.html >/dev/null 2>&1 &
else
  note "Open $OUT/report.html in a browser."
fi
note "Look for the 'Action needed' banner, the inventory filters (All / Undocumented / Documented), and the documented reasons."
exit_code "$code" "1, as in step f2: same scan, same config. The report also shows this code and its meaning."

# ---------------------------------------------------------------- i

step i "--fail-on none" "--fail-on sets which severity fails the run; 'none' never fails on findings. Coverage is a separate check."
show lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --config demo.toml --fail-on none --quiet '>' /dev/null
lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --config demo.toml --fail-on none --quiet >/dev/null
exit_code $? "0: the same findings as step f2, but none of them fails the run, and every unscannable file is documented."
echo
show lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --fail-on none --quiet '>' /dev/null
lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --fail-on none --quiet >/dev/null
exit_code $? "Without demo.toml it is 6 even with --fail-on none: --fail-on governs findings, never coverage."

# ---------------------------------------------------------------- j

step j "--concurrency 1 versus the default (16)" "Content scans run many files at once, but results are applied in listing order, so outputs must be identical."
show lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --quiet --concurrency 1 \
  --findings findings-c1.jsonl --inventory inventory-c1.csv '>' summary-c1.txt
lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --quiet --concurrency 1 \
  --findings findings-c1.jsonl --inventory inventory-c1.csv >summary-c1.txt
code1=$?
show lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --quiet \
  --findings findings-c16.jsonl --inventory inventory-c16.csv '>' summary-c16.txt
lakescan scan "$S3_PII" --endpoint-url "$ENDPOINT" --pii --quiet \
  --findings findings-c16.jsonl --inventory inventory-c16.csv >summary-c16.txt
code16=$?
echo "exit codes: $code1 (--concurrency 1) and $code16 (default)"
note "The summaries differ only in their 'started:' and 'elapsed:' lines, so those are left out of the comparison."
show diff '<(grep -v -E "^(started|elapsed):" summary-c1.txt)' '<(grep -v -E "^(started|elapsed):" summary-c16.txt)'
same=1
diff <(grep -v -E '^(started|elapsed):' summary-c1.txt) <(grep -v -E '^(started|elapsed):' summary-c16.txt) || same=0
show diff findings-c1.jsonl findings-c16.jsonl
diff findings-c1.jsonl findings-c16.jsonl || same=0
show diff inventory-c1.csv inventory-c16.csv
diff inventory-c1.csv inventory-c16.csv || same=0
if [ "$same" = 1 ]; then
  note "No diff output: the summary, the findings stream and the inventory are identical."
else
  note "The outputs DIFFER. That is a LakeScan bug; please report it."
fi

echo
echo "${BOLD}Done.${RESET} Everything this demo wrote is in $OUT"
echo "To read the walkthrough: docs/TUTORIAL.md"
