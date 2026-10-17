"""Count, per column, the values M12's new cleaning rules drop (a port of
src/content/clean.rs): reserved test-domain emails, masked runs, sentinel
dates. Prints counts only.

usage: python -I new_cleaning.py LAKE_DIR
"""
import pathlib
import sys

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

DOMAINS = ("example.com", "example.org", "example.net")
MASK = set("*xX#•-")


def test_email(v):
    if "@" not in v:
        return False
    d = v.rsplit("@", 1)[1].lower()
    under = any(d == p or (d.endswith(p) and d[: -len(p)].endswith(".")) for p in DOMAINS)
    return under or ("." in d and d.rsplit(".", 1)[1] == "test")


def masked(v):
    run, last = 0, None
    for c in v:
        run = run + 1 if (c in MASK and c == last) else 1
        last = c
        if run >= 4 and c in MASK:
            return True
    return False


def sentinel(v):
    return any(v.startswith(d) and all(c in "Tt 0:.Zz+" for c in v[len(d):])
               for d in ("1900-01-01", "1970-01-01"))


def leaves(name, arr):
    t = arr.type
    if pa.types.is_struct(t):
        for i in range(t.num_fields):
            yield from leaves(f"{name}.{t.field(i).name}", pc.struct_field(arr, [i]))
    elif pa.types.is_list(t) or pa.types.is_large_list(t):
        yield from leaves(f"{name}[]", pc.list_flatten(arr))
    elif pa.types.is_string(t) or pa.types.is_large_string(t):
        yield name, arr


for path in sorted(pathlib.Path(sys.argv[1]).rglob("*.parquet")):
    table = pq.read_table(path)
    for field in table.schema:
        for name, arr in leaves(field.name, table.column(field.name).combine_chunks()):
            values = [v.strip() for v in arr.drop_null().to_pylist() if v and v.strip()]
            counts = (sum(map(test_email, values)), sum(map(masked, values)), sum(map(sentinel, values)))
            if any(counts):
                print(f"{path.relative_to(sys.argv[1])}  {name}  of {len(values)}: "
                      f"test-email={counts[0]} masked={counts[1]} sentinel-date={counts[2]}")
