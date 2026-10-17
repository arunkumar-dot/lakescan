"""Pull Patient, Practitioner and Organization resources out of Synthea
FHIR bundles into one NDJSON file per resource type. Copies resources as
they are; prints only counts.

usage: python -I fhir_extract.py BUNDLE_DIR OUT_DIR
"""

import json
import pathlib
import sys

KEEP = ("Patient", "Practitioner", "Organization")


def main(bundle_dir, out_dir):
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    sinks = {kind: open(out / f"{kind.lower()}.ndjson", "w") for kind in KEEP}
    counts = dict.fromkeys(KEEP, 0)
    for path in sorted(pathlib.Path(bundle_dir).glob("*.json")):
        bundle = json.loads(path.read_text())
        for entry in bundle.get("entry", []):
            resource = entry.get("resource", {})
            kind = resource.get("resourceType")
            if kind in sinks:
                sinks[kind].write(json.dumps(resource) + "\n")
                counts[kind] += 1
    for sink in sinks.values():
        sink.close()
    print(counts)


if __name__ == "__main__":
    main(*sys.argv[1:])
