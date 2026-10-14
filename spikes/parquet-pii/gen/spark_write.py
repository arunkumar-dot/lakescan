"""Rewrite round 2's tables with Spark (parquet-java) at default settings.

Runs inside the pinned apache/spark image (see docs/experiments/parquet-pii.md):
reads <data>/_spark_src/*.parquet, written by generate_r2.py, and writes
<data>/spark/<name>.parquet and <data>/spark/lake/customers_NNN.parquet.
coalesce(1) makes each output a single file; no writer option is changed.

    spark-submit gen/spark_write.py <data>
"""

import glob
import json
import os
import shutil
import sys

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

LAKE_FILES, LAKE_ROWS = 100, 10_000

data = sys.argv[1]
spark = SparkSession.builder.master("local[*]").appName("parquet-pii-spike").getOrCreate()
spark.sparkContext.setLogLevel("WARN")


def write(df, dest):
    tmp = dest + ".tmp"
    df.coalesce(1).write.mode("overwrite").parquet(tmp)
    parts = glob.glob(f"{tmp}/part-*.parquet")
    assert len(parts) == 1, parts
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.move(parts[0], dest)
    shutil.rmtree(tmp)
    print(f"  spark {dest}: {os.path.getsize(dest) / 1e6:.1f} MB", flush=True)


for name in ("customers_1m", "events_2m", "tickets_1m"):
    write(spark.read.parquet(f"{data}/_spark_src/{name}.parquet"), f"{data}/spark/{name}.parquet")

customers = spark.read.parquet(f"{data}/_spark_src/customers_1m.parquet")
for i in range(LAKE_FILES):
    part = customers.where((F.col("customer_id") > i * LAKE_ROWS) & (F.col("customer_id") <= (i + 1) * LAKE_ROWS))
    write(part, f"{data}/spark/lake/customers_{i:03d}.parquet")

jars = sorted(os.path.basename(j) for j in glob.glob(os.environ["SPARK_HOME"] + "/jars/parquet-hadoop-*.jar"))
manifest_path = f"{data}/manifest.json"
manifest = json.load(open(manifest_path))
manifest["versions"]["spark"] = spark.version
manifest["versions"]["parquet_java"] = jars[0].removeprefix("parquet-hadoop-").removesuffix(".jar")
manifest["versions"]["spark_python"] = sys.version.split()[0]
json.dump(manifest, open(manifest_path, "w"), indent=2)
print(f"versions: {manifest['versions']}", flush=True)
