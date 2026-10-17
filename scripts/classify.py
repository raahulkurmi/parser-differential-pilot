"""results/raw/*.jsonl -> results/pairs.jsonl (one line per (case, parser pair)).

Usage: python3 scripts/classify.py
"""

import json
import os

from pdp_common import PAIRS, classify, load_manifest, load_raw, role_pair


def main():
    manifest = load_manifest()
    recs = load_raw()
    os.makedirs("results", exist_ok=True)
    n = 0
    with open("results/pairs.jsonl", "w", encoding="utf-8") as out:
        for row in manifest:
            cid = row["id"]
            for a, b in PAIRS:
                cls, diffs = classify(recs[(cid, a)], recs[(cid, b)], "rfc")
                cls_strict, diffs_strict = classify(recs[(cid, a)], recs[(cid, b)], "strict")
                out.write(json.dumps({
                    "case": cid, "category": row["category"], "a": a, "b": b, "roles": role_pair(a, b),
                    "class": cls, "diffs": diffs,
                    "class_strict_aud": cls_strict, "diffs_strict_aud": diffs_strict,
                }) + "\n")
                n += 1
    print(f"wrote {n} pair classifications to results/pairs.jsonl")


if __name__ == "__main__":
    main()
