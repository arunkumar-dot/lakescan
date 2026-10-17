"""(Re)create a bucket on a local S3 fake and upload a directory tree into
it, keys relative to the tree, then check every key and size came back.

usage: python -I seed.py ENDPOINT BUCKET LAKE_DIR
"""

import pathlib
import sys

import boto3
from botocore.config import Config


def main(endpoint, bucket, lake):
    s3 = boto3.client(
        "s3", endpoint_url=endpoint, region_name="us-east-1",
        aws_access_key_id="test", aws_secret_access_key="test",
        config=Config(s3={"addressing_style": "path"}),
    )
    existing = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    if bucket in existing:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    s3.create_bucket(Bucket=bucket)
    root = pathlib.Path(lake)
    sent = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        key = path.relative_to(root).as_posix()
        s3.upload_file(str(path), bucket, key)
        sent[key] = path.stat().st_size
    got = {}
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            got[obj["Key"]] = obj["Size"]
    if got != sent:
        sys.exit(f"mismatch: sent {len(sent)}, listed {len(got)}")
    print(f"{bucket}: {len(sent)} objects, {sum(sent.values())} bytes")


if __name__ == "__main__":
    main(*sys.argv[1:])
