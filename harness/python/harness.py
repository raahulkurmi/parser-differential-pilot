"""Python harness: py-json, py-pyjwt.

Usage: harness.py --parser <id> --corpus <dir> --pubkey <pem>   (JSONL on stdout)
Canonical value encoding: docs/PREREGISTRATION.md section 5.2.
"""

import argparse
import csv
import json
import os
import struct
import sys

import jwt

FIELDS = ["iss", "sub", "aud", "exp", "iat"]
ABSENT = {"t": "absent"}

# Every optional claim check PyJWT exposes is disabled; only the signature is verified.
PYJWT_OPTIONS = {
    "verify_signature": True,
    "verify_exp": False,
    "verify_nbf": False,
    "verify_iat": False,
    "verify_aud": False,
    "verify_iss": False,
    "verify_sub": False,
    "verify_jti": False,
    "require": [],
}


def canon(v):
    if v is None:
        return {"t": "null"}
    if isinstance(v, bool):
        return {"t": "bool", "v": v}
    if isinstance(v, str):
        return {"t": "string", "cp": [ord(c) for c in v]}
    if isinstance(v, int):
        return {"t": "number", "kind": "int", "v": str(v)}
    if isinstance(v, float):
        return {"t": "number", "kind": "f64", "bits": struct.pack(">d", v).hex()}
    if isinstance(v, list):
        return {"t": "array", "v": [canon(e) for e in v]}
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-8", "surrogatepass"))
        return {"t": "object", "v": [[canon(k), canon(v[k])] for k in keys]}
    return {"t": "other", "v": f"{type(v).__name__}:{v!r}"}


def fields_from_map(m):
    return {f: canon(m[f]) if f in m else ABSENT for f in FIELDS}


def py_json(data):
    # Bytes are passed directly: json.loads detects UTF-8/16/32 and a UTF-8 BOM.
    obj = json.loads(data)
    if not isinstance(obj, dict):
        raise ValueError("top-level value is not an object")
    return fields_from_map(obj)


def py_pyjwt(token, pub):
    claims = jwt.decode(token, pub, algorithms=["RS256"], options=PYJWT_OPTIONS)
    return fields_from_map(claims)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--parser", required=True, choices=["py-json", "py-pyjwt"])
    ap.add_argument("--corpus", default="corpus")
    ap.add_argument("--pubkey", default="testdata/keys/TEST_ONLY_rs256_public.pem")
    a = ap.parse_args()

    with open(os.path.join(a.corpus, "MANIFEST.csv"), newline="", encoding="utf-8") as f:
        ids = [row["id"] for row in csv.DictReader(f)]
    with open(a.pubkey, "rb") as f:
        pub = f.read()

    for cid in ids:
        rec = {"schema": 1, "case": cid, "parser": a.parser}
        try:
            if a.parser == "py-json":
                with open(os.path.join(a.corpus, cid + ".json"), "rb") as f:
                    fields = py_json(f.read())
            else:
                with open(os.path.join(a.corpus, "tokens", cid + ".jwt"), "r", encoding="ascii") as f:
                    fields = py_pyjwt(f.read().strip(), pub)
            rec.update(outcome="ACCEPT", error=None, fields=fields)
        except (OSError, KeyboardInterrupt):
            raise
        except Exception as e:  # any parser/verifier failure is a REJECT
            rec.update(outcome="REJECT", error=f"{type(e).__name__}: {e}", fields=None)
        sys.stdout.write(json.dumps(rec, ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
