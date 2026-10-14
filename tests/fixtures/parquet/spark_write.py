"""Rewrites _spark_src/customers.parquet with Spark's defaults (parquet-java)
into spark/customers.parquet. Runs inside the pinned apache/spark image; see
README.md. coalesce(1) makes the output one file; no writer option is changed.

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

tmp = f"{data}/spark/.tmp"
spark.read.parquet(f"{data}/_spark_src/customers.parquet").coalesce(1).write.mode("overwrite").parquet(tmp)
parts = glob.glob(f"{tmp}/part-*.parquet")
assert len(parts) == 1, parts
shutil.move(parts[0], f"{data}/spark/customers.parquet")
shutil.rmtree(tmp)
print(f"spark {os.path.getsize(f'{data}/spark/customers.parquet') / 1e3:.1f} KB; Spark {spark.version}")
