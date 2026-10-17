#!/bin/sh
# Runs the release binary with --pii over each dataset prefix of the local
# moto bucket, at default settings and with --pii-whole-file-max 0.
# usage: scan.sh BINARY ENDPOINT OUT_DIR
set -u
bin=$1 endpoint=$2 out=$3
mkdir -p "$out"
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_REGION=us-east-1
for mode in default wfm0; do
  extra=""
  [ "$mode" = wfm0 ] && extra="--pii-whole-file-max 0"
  for ds in synthea575k payments nemotron fhir bts wdi tlc ""; do
    name=${ds:-ALL}
    base="$out/$mode-$name"
    start=$(date +%s)
    # shellcheck disable=SC2086
    "$bin" scan "s3://real-data/$ds" --endpoint-url "$endpoint" --pii $extra \
      --format json --output "$base.summary.json" --findings "$base.findings.jsonl" \
      --inventory "$base.inventory.csv" --html "$base.html" 2> "$base.stderr"
    code=$?
    echo "$mode $name exit=$code secs=$(( $(date +%s) - start ))" | tee -a "$out/codes.txt"
  done
done
