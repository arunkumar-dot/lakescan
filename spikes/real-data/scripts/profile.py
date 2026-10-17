"""Profile every leaf column of every Parquet file under a directory, over
ALL its values (not LakeScan's sample), without printing any value:

- non-null count, average length;
- how many values pass each LakeScan validator (ported from
  src/content/detect.rs), before and after LakeScan's cleaning;
- the top shapes: each value as character classes, runs collapsed
  (`9` digit, `A` upper, `a` lower, other characters kept), e.g.
  `(9{3}) 9{3}-9{4}`. Shapes of long values are cut to 24 classes;
- placeholder candidates: values a broad missing-value list would call
  empty, grouped by class, and whether LakeScan's list already drops them.

Writes JSON Lines, one object per (file, column).

usage: python -I profile.py LAKE_DIR OUT.jsonl
"""

import collections
import ipaddress
import json
import pathlib
import re
import sys

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")
PAN = re.compile(r"^[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]$")
E164 = re.compile(r"^\+[1-9][0-9]{7,14}$")
INDIAN_MOBILE = re.compile(r"^(?:\+?91|0)?[6-9][0-9]{9}$")

# LakeScan's PLACEHOLDERS (src/content/clean.rs).
LAKESCAN_PLACEHOLDERS = {"n/a", "na", "null", "none", "nil", "unknown", "undefined",
                         "unk", "tbd", "test", "sample", "dummy", "-", "?", "."}

# A broader list of missing-value spellings, by class. Classes, not
# values, are what gets reported.
CANDIDATE_CLASSES = [
    ("float-nan-text", re.compile(r"^(nan|-?inf)$", re.I)),
    ("excel-error", re.compile(r"^#(n/a|value!|ref!|div/0!|name\?|null!|num!)$", re.I)),
    ("bracketed-null", re.compile(r"^[\(\[<{]\s*(null|none|empty|blank|missing|n/?a)\s*[\)\]>}]$", re.I)),
    ("dotted-na", re.compile(r"^n\.\s?a\.?$", re.I)),
    ("not-available-phrase", re.compile(r"^(not\s+(available|applicable|known|provided|specified|reported|stated)|no\s+data|missing|blank|empty|withheld|redacted|unspecified)$", re.I)),
    ("zero-only", re.compile(r"^0+(\.0+)?$")),
    ("epoch-or-1900-date", re.compile(r"^(1900-01-01|1970-01-01|0000-00-00|01/01/1900|01/01/1970)")),
    ("masked-run", re.compile(r"[*xX#]{4,}")),
    ("dots-or-dashes", re.compile(r"^[\.\-_ /]{2,}$")),
    ("quoted-empty", re.compile(r"^(''|\"\")$")),
    ("unknown-variant", re.compile(r"^(unknown|unk|n/k|not\s*known|\?{2,})", re.I)),
    ("placeholder-domain", re.compile(r"@(example|test|sample)\.(com|org|net)$", re.I)),
    ("us-555-phone", re.compile(r"^\(?\+?1?[\s\-\.]*\(?555\)?[\s\-\.]*\d{3}[\s\-\.]*\d{4}$")),
]


def verhoeff(digits):
    d = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
         [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
         [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
         [9,8,7,6,5,4,3,2,1,0]]
    p = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
         [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
         [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
    c = 0
    for i, x in enumerate(reversed(digits)):
        c = d[c][p[i % 8][x]]
    return c == 0


def luhn(digits):
    total = 0
    for i, x in enumerate(reversed(digits)):
        if i % 2:
            x *= 2
            if x > 9:
                x -= 9
        total += x
    return total % 10 == 0


def digits_without(value, seps):
    out = []
    for ch in value:
        if ch in seps:
            continue
        if not ("0" <= ch <= "9"):
            return []
        out.append(ord(ch) - 48)
    return out


def validators(v):
    hits = []
    if len(v) <= 254 and EMAIL.match(v):
        hits.append("email")
    if PAN.match(v.upper()):
        hits.append("in-pan")
    compact = re.sub(r"[ \-().]", "", v)
    if E164.match(compact) or INDIAN_MOBILE.match(compact):
        hits.append("phone")
    a = digits_without(v, " ")
    if len(a) == 12 and a[0] >= 2 and verhoeff(a):
        hits.append("in-aadhaar")
    c = digits_without(v, " -")
    if 13 <= len(c) <= 19 and luhn(c):
        hits.append("card-number")
    try:
        ipaddress.ip_address(v)
        hits.append("ip-address")
    except ValueError:
        pass
    return hits


def lakescan_clean(raw):
    v = raw.strip()
    if not v or len(set(v)) == 1 or v.lower() in LAKESCAN_PLACEHOLDERS:
        return None
    return v


def shape(v):
    out, last, run = [], None, 0
    for ch in v[:200]:
        cls = "9" if ch.isdigit() else "A" if ch.isupper() else "a" if ch.islower() else ch
        if cls == last:
            run += 1
            continue
        if last is not None:
            out.append(last + (f"{{{run}}}" if run > 1 and last in "9Aa" else last * (run - 1)))
        last, run = cls, 1
    if last is not None:
        out.append(last + (f"{{{run}}}" if run > 1 and last in "9Aa" else last * (run - 1)))
    s = "".join(out[:24])
    return s + ("…" if len(out) > 24 or len(v) > 200 else "")


def leaves(table):
    """(dotted path, flat array of leaf values) for every leaf, lists exploded."""
    def walk(name, arr):
        t = arr.type
        if pa.types.is_struct(t):
            for i in range(t.num_fields):
                yield from walk(f"{name}.{t.field(i).name}", pc.struct_field(arr, [i]))
        elif pa.types.is_list(t) or pa.types.is_large_list(t):
            yield from walk(f"{name}[]", pc.list_flatten(arr))
        else:
            yield name, arr
    for field in table.schema:
        yield from walk(field.name, table.column(field.name).combine_chunks())


def main(lake, out_path):
    with open(out_path, "w") as out:
        for path in sorted(pathlib.Path(lake).rglob("*.parquet")):
            table = pq.read_table(path)
            for name, arr in leaves(table):
                rec = {"file": str(path.relative_to(lake)), "column": name,
                       "type": str(arr.type), "rows": len(arr),
                       "non_null": len(arr) - arr.null_count}
                if pa.types.is_string(arr.type) or pa.types.is_large_string(arr.type) or \
                        pa.types.is_integer(arr.type):
                    values = [str(x) for x in arr.drop_null().to_pylist()]
                    raw_hits, clean_hits = collections.Counter(), collections.Counter()
                    shapes, cands = collections.Counter(), collections.Counter()
                    cleaned = 0
                    for v in values:
                        for h in validators(v.strip()):
                            raw_hits[h] += 1
                        c = lakescan_clean(v)
                        if c is not None:
                            cleaned += 1
                            for h in validators(c):
                                clean_hits[h] += 1
                        shapes[shape(v)] += 1
                        for cls, rx in CANDIDATE_CLASSES:
                            if rx.search(v.strip()):
                                cands[(cls, c is None)] += 1
                    n = max(len(values), 1)
                    rec.update({
                        "avg_len": round(sum(map(len, values)) / n, 1),
                        "distinct": len(set(values)),
                        "cleaned": cleaned,
                        "hits_clean": dict(clean_hits),
                        "top_shapes": [(s, round(k / n, 3)) for s, k in shapes.most_common(4)],
                        "placeholder_candidates": [
                            {"class": cls, "dropped_by_lakescan": dropped, "count": k}
                            for (cls, dropped), k in sorted(cands.items())],
                    })
                out.write(json.dumps(rec) + "\n")


if __name__ == "__main__":
    main(*sys.argv[1:])
