"""Score a findings file against the ground truth in truth.py.

A finding is counted per (table, column): the table is the key's directory.
A finding on a Tier A column is a true positive whatever its rule (the
rule is printed so a wrong type shows); any other finding is a false
positive. Prints JSON.

usage: python -I score.py FINDINGS.jsonl
"""

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from truth import TIER_A  # noqa: E402


def main(path):
    found = {}
    for line in open(path):
        f = json.loads(line)
        if "column" not in f:
            continue
        table = f["key"].rsplit("/", 1)[0]
        cell = found.setdefault((table, f["column"]), {"rule": f["rule"], "confidence": set(),
                                                       "evidence": set(), "files": 0})
        cell["confidence"].add(f["confidence"])
        cell["evidence"].add(f["evidence"] + (f" {f['matched']}/{f['sampled']}" if "matched" in f else ""))
        cell["files"] += 1
    truth = {(t, c): (k, s) for t, c, k, s in TIER_A}
    tp = [(t, c, v) for (t, c), v in found.items() if (t, c) in truth]
    fp = [(t, c, v) for (t, c), v in found.items() if (t, c) not in truth]
    fn = [(t, c, k, s) for (t, c), (k, s) in truth.items() if (t, c) not in found]

    def at_least_likely(v):
        return bool(v["confidence"] & {"likely", "confirmed"})

    in_scope = [k for k, (_, s) in truth.items() if s]
    tp_in = [x for x in tp if truth[(x[0], x[1])][1]]
    out = {
        "found_columns": len(found),
        "tp": len(tp), "fp": len(fp), "fn": len(fn),
        "precision_all": round(len(tp) / max(len(found), 1), 3),
        "recall_all_tier_a": round(len(tp) / len(truth), 3),
        "recall_in_scope": round(len(tp_in) / len(in_scope), 3),
        "tp_likely_or_better": sum(at_least_likely(v) for *_, v in tp),
        "fp_likely_or_better": sum(at_least_likely(v) for *_, v in fp),
        "tier_a": len(truth), "in_scope": len(in_scope),
        "tp_list": [[t, c, v["rule"], sorted(v["confidence"]), sorted(v["evidence"])] for t, c, v in tp],
        "fp_list": [[t, c, v["rule"], sorted(v["confidence"]), sorted(v["evidence"])] for t, c, v in fp],
        "fn_list": [list(x) for x in fn],
    }
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:])
