"""Print the schema of Parquet files: writer, rows, row groups, and each
leaf column's path, physical and logical type and repetition. Never values.

usage: python -I schema.py FILE.parquet...
"""

import sys

import pyarrow.parquet as pq


def main(paths):
    for path in paths:
        meta = pq.ParquetFile(path).metadata
        print(f"== {path}")
        print(f"   created_by={meta.created_by!r} rows={meta.num_rows} "
              f"row_groups={meta.num_row_groups} columns={meta.num_columns}")
        schema = meta.schema
        for i in range(meta.num_columns):
            col = schema.column(i)
            print(f"   {col.path:50s} {col.physical_type:22s} "
                  f"{str(col.logical_type):28s} rep={col.max_repetition_level}")


if __name__ == "__main__":
    main(sys.argv[1:])
