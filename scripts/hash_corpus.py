"""Write corpus/SHA256SUMS (shasum -a 256 format) for every corpus file and MANIFEST.csv.

Usage: python3 scripts/hash_corpus.py
"""

import hashlib
import os

paths = sorted(
    [os.path.join("corpus", n) for n in os.listdir("corpus") if n.endswith(".json") or n == "MANIFEST.csv"]
    + [os.path.join("corpus", "tokens", n) for n in os.listdir("corpus/tokens") if n.endswith(".jwt")]
)
with open("corpus/SHA256SUMS", "w", encoding="ascii") as out:
    for p in paths:
        with open(p, "rb") as f:
            out.write(f"{hashlib.sha256(f.read()).hexdigest()}  {p}\n")
print(f"hashed {len(paths)} files")
