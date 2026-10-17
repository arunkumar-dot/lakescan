"""Build one probe Parquet file whose columns are every distinct leaf
column name found under LAKE_DIR, each a string column of 10 neutral
values ("v0".."v9") that no validator accepts. Scanning it with the
release binary shows exactly which names its hints fire on, including
leaves it never examines in the real files (repeated or float columns).

Fewer than 30 values, so validator-type hints show as POSSIBLE too.
Writes NAME_MAP.json: probe column -> the (file, path) leaves it stands for.

usage: python -I name_probe.py LAKE_DIR OUT.parquet NAME_MAP.json
"""

import json
import pathlib
import sys

import pyarrow as pa
import pyarrow.parquet as pq


def main(lake, out, name_map):
    leaves = {}
    for path in sorted(pathlib.Path(lake).rglob("*.parquet")):
        schema = pq.ParquetFile(path).metadata.schema
        for i in range(len(schema)):
            col = schema.column(i)
            # The leaf LakeScan hints on: the last segment of the path,
            # list wrappers ("list", "element") removed.
            parts = [p for p in col.path.split(".") if p not in ("list", "element")]
            leaf = parts[-1]
            leaves.setdefault(leaf, []).append([str(path.relative_to(lake)), col.path])
    values = pa.array([f"v{i}" for i in range(10)])
    table = pa.table({leaf: values for leaf in leaves})
    pq.write_table(table, out)
    pathlib.Path(name_map).write_text(json.dumps(leaves, indent=1))
    print(f"{len(leaves)} distinct leaf names")


if __name__ == "__main__":
    main(*sys.argv[1:])
