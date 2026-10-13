"""Render results/results.json as the markdown tables in docs/experiments/parquet-pii.md.

    python3 report.py results/results.json
"""

import json
import sys

r = json.load(open(sys.argv[1]))
res = r["results"]

WRITERS = ["pyarrow", "polars", "duckdb"]
FILES = [("customers", 1_000_000), ("events", 2_000_000), ("customers", 10_000)]


def fmt_pct(x, digits=1):
    return "n/a" if x is None or x != x else f"{x:.{digits}f}%"


def fmt_bytes(n):
    for unit, size in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{n} B"


def one(**kw):
    return next(x for x in res if all(x[k] == v for k, v in kw.items()))


def setup_table():
    print("| File | Writer | Rows | Row groups | File size | Uncompressed (column chunks) |")
    print("|---|---|---:|---:|---:|---:|")
    for dataset, rows in FILES:
        for w in WRITERS:
            x = one(writer=w, dataset=dataset, rows=rows, strategy="S0")
            print(f"| `{x['file']}` | {w} | {rows:,} | {x['row_groups']} | "
                  f"{fmt_bytes(x['file_bytes'])} | {fmt_bytes(x['uncompressed_bytes'])} |")


def encoding_table(rows_filter):
    print("| Dataset | Column | PII type | pyarrow | polars | duckdb |")
    print("|---|---|---|---|---|---|")
    for dataset, rows in FILES:
        if rows not in rows_filter:
            continue
        cols = []
        for e in r["encodings"]:
            if e["dataset"] == dataset and e["rows"] == rows and e["column"] not in cols:
                cols.append(e["column"])
        for col in cols:
            cells = []
            for w in WRITERS:
                e = next(e for e in r["encodings"] if e["writer"] == w and e["dataset"] == dataset
                         and e["rows"] == rows and e["column"] == col)
                truth = e["truth"]
                cells.append(label(e))
            print(f"| {dataset} ({rows:,}) | `{col}` | {truth} | " + " | ".join(cells) + " |")


def label(e):
    if not e["dictionary_page"]:
        return "plain (no dictionary)"
    size = f"{e['dictionary_bytes'] / 1e3:.0f} KB dict"
    encs = e["data_page_encodings"]
    if any(x.endswith("?") for x in encs):
        return f"dictionary ({size}; page stats absent)"
    if "PLAIN" in encs:
        return f"dictionary, then PLAIN fallback ({size})"
    return f"dictionary ({size})"


def strategy_table(s):
    print("| File | Writer | Value recall | Value precision | Recall incl. names | Precision incl. names | "
          "Read | % of file | % of uncompressed | Ranges | Wall ms |")
    print("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for dataset, rows in FILES:
        for w in WRITERS:
            x = one(writer=w, dataset=dataset, rows=rows, strategy=s)
            vr = f"{x['value_recall']:.0f}% ({round(x['value_recall'] * x['value_detectable'] / 100)}/{x['value_detectable']})"
            cr = f"{x['combined_recall']:.0f}% ({round(x['combined_recall'] * x['all_pii'] / 100)}/{x['all_pii']})"
            print(f"| {dataset} {rows:,} | {w} | {vr} | {fmt_pct(x['value_precision'], 0)} | {cr} | "
                  f"{fmt_pct(x['combined_precision'], 0)} | {fmt_bytes(x['bytes_read'])} | "
                  f"{fmt_pct(x['pct_of_file'], 3)} | {fmt_pct(x['pct_of_uncompressed'], 3)} | {x['ranges']} | "
                  f"{x['wall_ms']:.1f} |")


def supplementary_table():
    print("| File | Writer | S2 value recall | S3 value recall | S3 value precision |")
    print("|---|---|---:|---:|---:|")
    for dataset, rows in FILES[:2]:
        for w in WRITERS:
            s2 = next(x for x in res if x["writer"] == w and x["dataset"] == dataset and x["rows"] == rows and x["strategy"] == "S2")
            s3 = next(x for x in res if x["writer"] == w and x["dataset"] == dataset and x["rows"] == rows and x["strategy"] == "S3")
            print(f"| {dataset} {rows:,} | {w} | {s2['supplementary_value_recall']:.0f}% | "
                  f"{s3['supplementary_value_recall']:.0f}% | {fmt_pct(s3['supplementary_value_precision'], 0)} |")


def verdict():
    print("| Writer | File | Best of S2/S3 meeting all three thresholds | Value recall | Value precision | % of uncompressed |")
    print("|---|---|---|---:|---:|---:|")
    for w in WRITERS:
        for dataset, rows in FILES[:2]:
            best = None
            for s in ("S2", "S3"):
                x = next(x for x in res if x["writer"] == w and x["dataset"] == dataset and x["rows"] == rows and x["strategy"] == s)
                ok = x["value_recall"] >= 90 and (x["value_precision"] or 0) >= 95 and x["pct_of_uncompressed"] <= 10
                if ok and best is None:
                    best = (s, x)
            x = best[1] if best else next(x for x in res if x["writer"] == w and x["dataset"] == dataset and x["rows"] == rows and x["strategy"] == "S3")
            print(f"| {w} | {dataset} {rows:,} | {'**' + best[0] + ' passes**' if best else '**fails** (shown: S3)'} | "
                  f"{x['value_recall']:.0f}% | {fmt_pct(x['value_precision'], 0)} | {fmt_pct(x['pct_of_uncompressed'], 2)} |")


section = sys.argv[2] if len(sys.argv) > 2 else "all"
if section in ("all", "setup"):
    setup_table()
if section in ("all", "encodings"):
    encoding_table({1_000_000, 2_000_000})
if section in ("all", "encodings_small"):
    encoding_table({10_000})
for s in ("S0", "S1", "S2", "S3"):
    if section in ("all", s):
        strategy_table(s)
if section in ("all", "supplementary"):
    supplementary_table()
if section in ("all", "verdict"):
    verdict()
