"""Render results/round2.json as the Round 2 tables in docs/experiments/parquet-pii.md.

    gen/.venv/bin/python report_r2.py results/round2.json data2 <section>

Sections: setup mess junk encodings S1 S3 S4 freetext s4bytes lake verdict.
The data directory is used only by `mess` (manifest) and `s4bytes` (footers).
"""

import json
import sys
from pathlib import Path

r = json.load(open(sys.argv[1]))
data = Path(sys.argv[2])
section = sys.argv[3]
res = r["results"]

WRITERS = ["pyarrow", "polars", "duckdb", "spark"]
BIG = [("customers", 1_000_000), ("events", 2_000_000), ("tickets", 1_000_000)]
LEVELS = ["CONFIRMED", "LIKELY", "POSSIBLE"]


def fmt_pct(x, digits=1):
    return "n/a" if x is None or x != x else f"{x:.{digits}f}%"


def fmt_bytes(n):
    for unit, size in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{n} B"


def one(**kw):
    return next(x for x in res if all(x[k] == v for k, v in kw.items()))


def col(x, name):
    return next(c for c in x["columns"] if c["column"] == name)


def setup():
    print("| File | Writer | Rows | Row groups | File size | Uncompressed (column chunks) |")
    print("|---|---|---:|---:|---:|---:|")
    for dataset, rows in BIG:
        for w in WRITERS:
            x = one(writer=w, dataset=dataset, strategy="S1")
            print(f"| `{x['file']}` | {w} | {rows:,} | {x['row_groups']} | {fmt_bytes(x['file_bytes'])} | "
                  f"{fmt_bytes(x['uncompressed_bytes'])} |")


def mess():
    m = json.load(open(data / "manifest.json"))["mess"]
    rows = {"customers": 1_000_000, "events": 2_000_000, "tickets": 1_000_000}
    print("| Dataset | Column | Null | Empty | Whitespace-only | Placeholder | Malformed | Padded |")
    print("|---|---|---:|---:|---:|---:|---:|---:|")
    for dataset, cols in m.items():
        for c, k in cols.items():
            cells = [fmt_pct(100 * k.get(f, 0) / rows[dataset]) for f in
                     ("null", "empty", "whitespace", "placeholder", "malformed", "padded")]
            print(f"| {dataset} | `{c}` | " + " | ".join(cells) + " |")


def junk():
    print("| File | Writer | Statistics values (structured PII columns) | Removed by cleaning | Invalid after cleaning |")
    print("|---|---|---:|---:|---:|")
    for dataset, rows in BIG[:2]:
        for w in WRITERS:
            j = one(writer=w, dataset=dataset, strategy="S1")["stat_junk"]
            print(f"| {dataset} {rows:,} | {w} | {j['values']} | {j['cleaned_away']} | {j['invalid_after_cleaning']} |")


def label(e):
    if not e["dictionary_page"]:
        return "plain"
    size = f"{e['dictionary_bytes'] / 1e3:.0f} KB dict"
    encs = e["data_page_encodings"]
    if any(x.endswith("?") for x in encs):
        return f"dictionary ({size}; page stats absent)"
    if "PLAIN" in encs:
        return f"dictionary, then PLAIN ({size})"
    return f"dictionary ({size})"


def encodings():
    print("| Dataset | Column | Ground truth | pyarrow | polars | duckdb | spark |")
    print("|---|---|---|---|---|---|---|")
    for dataset, rows in BIG + [("customers_lake", 10_000)]:
        cols = []
        for e in r["encodings"]:
            if e["dataset"] == dataset and e["column"] not in cols:
                cols.append(e["column"])
        for c in cols:
            cells, truth = [], None
            for w in WRITERS:
                e = next(e for e in r["encodings"] if e["writer"] == w and e["dataset"] == dataset and e["column"] == c)
                truth = e["truth"]
                cells.append(label(e))
            name = "lake file 000 (10,000)" if dataset == "customers_lake" else f"{dataset} ({rows:,})"
            print(f"| {name} | `{c}` | {truth} | " + " | ".join(cells) + " |")


def strategy(s):
    print("| File | Writer | CONFIRMED recall | CONFIRMED precision | ≥LIKELY recall | ≥LIKELY precision | "
          "≥POSSIBLE recall | ≥POSSIBLE precision | Read | % of file | % of uncompressed | Ranges | Wall ms |")
    print("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for dataset, rows in BIG[:2]:
        for w in WRITERS:
            x = one(writer=w, dataset=dataset, strategy=s)
            cells = []
            for lv in x["levels"]:
                cells.append(f"{lv['recall']:.0f}% ({lv['hits']}/{x['structured_pii']})")
                p = "n/a (0 flags)" if lv["precision"] is None else f"{lv['precision']:.0f}% ({lv['correct']}/{lv['flags']})"
                cells.append(p)
            print(f"| {dataset} {rows:,} | {w} | " + " | ".join(cells) + f" | {fmt_bytes(x['bytes_read'])} | "
                  f"{fmt_pct(x['pct_of_file'], 3)} | {fmt_pct(x['pct_of_uncompressed'], 3)} | {x['ranges']} | "
                  f"{x['wall_ms']:.1f} |")


SWEEP = [("customers", "notes"), ("tickets", "agent_notes"), ("tickets", "customer_reply"),
         ("tickets", "internal_comment"), ("tickets", "resolution")]


def freetext():
    print("| Writer | Column | Rows with an email | S1 | S3 | S3 pages only (diagnostic) | S4 | "
          "Values read from pages at S3 | Expected emails among them |")
    print("|---|---|---:|---|---|---|---|---:|---:|")
    for w in WRITERS:
        for dataset, c in SWEEP:
            xs = {s: col(one(writer=w, dataset=dataset, strategy=s), c) for s in ("S1", "S3", "S4")}
            rate = xs["S1"]["embedded_rate"]
            page_values = xs["S3"]["samples"] - xs["S1"]["samples"]
            flags = ["flagged" if xs[s]["embedded"] else "missed" for s in ("S1", "S3")]
            flags.append("flagged" if xs["S3"]["embedded_pages_only"] else "missed")
            flags.append("flagged" if xs["S4"]["embedded"] else "missed")
            print(f"| {w} | {dataset}.`{c}` | {100 * rate:.2f}% | " + " | ".join(flags) +
                  f" | {page_values:,} | {rate * page_values:.1f} |")
    print()
    print("| Writer | Free-text columns (all large files) | Flagged at S4 | Correct | S4 precision | "
          "Sweep columns ≥0.1% found at S4 | 0.01% column found at S4 |")
    print("|---|---|---:|---:|---:|---|---|")
    for w in WRITERS:
        xs = [one(writer=w, dataset=d, strategy="S4") for d, _ in BIG]
        free = [f"{x['dataset']}.{c}" for x in xs for c in x["free_text_columns"]]
        flags = sum(x["embedded_flags"] for x in xs)
        correct = sum(x["embedded_correct"] for x in xs)
        hi = [col(one(writer=w, dataset=d, strategy="S4"), c) for d, c in SWEEP if c != "resolution"]
        lo = col(one(writer=w, dataset="tickets", strategy="S4"), "resolution")
        print(f"| {w} | {', '.join('`' + f + '`' for f in free)} | {flags} | {correct} | "
              f"{fmt_pct(100 * correct / flags if flags else None, 0)} | "
              f"{sum(c['embedded'] for c in hi)}/{len(hi)} | {'yes' if lo['embedded'] else 'no'} |")


def s4bytes():
    import pyarrow.parquet as pq
    print("| File | Writer | S3 read | S4 read | S4 extra, by free-text column (compressed chunk bytes) | S4 % of uncompressed |")
    print("|---|---|---:|---:|---|---:|")
    for dataset, rows in BIG:
        for w in WRITERS:
            s3, s4 = one(writer=w, dataset=dataset, strategy="S3"), one(writer=w, dataset=dataset, strategy="S4")
            md = pq.ParquetFile(data / s4["file"]).metadata
            names = [md.schema.column(i).name for i in range(md.num_columns)]
            parts = []
            for c in s4["free_text_columns"]:
                i = names.index(c)
                size = sum(md.row_group(g).column(i).total_compressed_size for g in range(md.num_row_groups))
                parts.append(f"`{c}` {fmt_bytes(size)}")
            print(f"| {dataset} {rows:,} | {w} | {fmt_bytes(s3['bytes_read'])} | {fmt_bytes(s4['bytes_read'])} | "
                  f"{', '.join(parts)} | {fmt_pct(s4['pct_of_uncompressed'], 1)} |")


def lake():
    print("| Writer | Strategy | Files | Lake file bytes | Lake uncompressed | Bytes read | % of file bytes | "
          "% of uncompressed | Range reads | CONFIRMED recall (mean, min) | CONFIRMED precision (min) | "
          "`notes` flagged EMAIL_EMBEDDED |")
    print("|---|---|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|")
    for w in WRITERS:
        for s in ("S1", "S3", "S4"):
            xs = [x for x in res if x["dataset"] == "customers_lake" and x["writer"] == w and x["strategy"] == s]
            b = sum(x["bytes_read"] for x in xs)
            u = sum(x["uncompressed_bytes"] for x in xs)
            fb = sum(x["file_bytes"] for x in xs)
            rec = [x["levels"][0]["recall"] for x in xs]
            prec = [x["levels"][0]["precision"] for x in xs if x["levels"][0]["precision"] is not None]
            emb = sum(col(x, "notes")["embedded"] for x in xs)
            print(f"| {w} | {s} | {len(xs)} | {fmt_bytes(fb)} | {fmt_bytes(u)} | {fmt_bytes(b)} | "
                  f"{fmt_pct(100 * b / fb, 1)} | {fmt_pct(100 * b / u, 1)} | {sum(x['ranges'] for x in xs):,} | "
                  f"{sum(rec) / len(rec):.0f}%, {min(rec):.0f}% | {fmt_pct(min(prec) if prec else None, 0)} | "
                  f"{emb}/{len(xs)} files |")


def verdict():
    print("**Primary** (S3, CONFIRMED, structured columns):")
    print()
    print("| Writer | File | Recall | Precision | % of uncompressed | Result |")
    print("|---|---|---:|---:|---:|---|")
    for w in WRITERS:
        for dataset, rows in BIG[:2]:
            x = one(writer=w, dataset=dataset, strategy="S3")
            lv = x["levels"][0]
            ok = lv["recall"] >= 90 and (lv["precision"] or 0) >= 95 and x["pct_of_uncompressed"] <= 10
            print(f"| {w} | {dataset} {rows:,} | {lv['recall']:.0f}% ({lv['hits']}/{x['structured_pii']}) | "
                  f"{fmt_pct(lv['precision'], 0)} ({lv['correct']}/{lv['flags']}) | "
                  f"{fmt_pct(x['pct_of_uncompressed'], 2)} | {'**pass**' if ok else '**fail**'} |")
    print()
    print("**Secondary** (S4, EMAIL_EMBEDDED, rates down to 0.1%):")
    print()
    print("| Writer | Columns at ≥0.1% found | Precision over all large files | Result |")
    print("|---|---|---:|---|")
    for w in WRITERS:
        hi = [col(one(writer=w, dataset=d, strategy="S4"), c) for d, c in SWEEP if c != "resolution"]
        xs = [one(writer=w, dataset=d, strategy="S4") for d, _ in BIG]
        flags = sum(x["embedded_flags"] for x in xs)
        correct = sum(x["embedded_correct"] for x in xs)
        prec = 100 * correct / flags if flags else 0
        ok = all(c["embedded"] for c in hi) and prec >= 95
        print(f"| {w} | {sum(c['embedded'] for c in hi)}/{len(hi)} | {prec:.0f}% ({correct}/{flags}) | "
              f"{'**pass**' if ok else '**fail**'} |")


{"setup": setup, "mess": mess, "junk": junk, "encodings": encodings, "S1": lambda: strategy("S1"),
 "S3": lambda: strategy("S3"), "S4": lambda: strategy("S4"), "freetext": freetext, "s4bytes": s4bytes,
 "lake": lake, "verdict": verdict}[section]()
