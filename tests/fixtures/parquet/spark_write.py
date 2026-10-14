"""Rewrites _spark_src/customers.parquet with Spark's defaults (parquet-java)
into spark/customers.parquet, and with GZIP (Spark's only change of option)
into gzip/spark/customers.parquet. Runs inside the pinned apache/spark image; see
README.md. coalesce(1) makes each output one file; no other writer option is
changed.

    spark-submit spark_write.py <this directory>
"""

import glob
import os
import shutil
import sys

from pyspark.sql import SparkSession

data = sys.argv[1]
spark = SparkSession.builder.master("local[*]").appName("lakescan-fixtures").getOrCreate()
spark.sparkContext.setLogLevel("WARN")

source = spark.read.parquet(f"{data}/_spark_src/customers.parquet").coalesce(1)
for target, options in (("spark", {}), ("gzip/spark", {"compression": "gzip"})):
    tmp = f"{data}/{target}/.tmp"
    source.write.mode("overwrite").options(**options).parquet(tmp)
    parts = glob.glob(f"{tmp}/part-*.parquet")
    assert len(parts) == 1, parts
    shutil.move(parts[0], f"{data}/{target}/customers.parquet")
    shutil.rmtree(tmp)
    size = os.path.getsize(f"{data}/{target}/customers.parquet")
    print(f"{target} {size / 1e3:.1f} KB; Spark {spark.version}")
