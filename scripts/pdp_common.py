"""Shared definitions for the analysis scripts (docs/PREREGISTRATION.md sections 4-6)."""

import csv
import glob
import json
import math
import os
import struct
from decimal import Decimal
from fractions import Fraction
from itertools import combinations

FIELDS = ["iss", "sub", "aud", "exp", "iat"]

# parser id -> (role, implementation)
PARSERS = {
    "go-encjson-struct": ("general-purpose", "Go encoding/json, decode into tagged struct"),
    "go-golangjwt": ("verifier-side", "github.com/golang-jwt/jwt/v5, MapClaims"),
    "go-gojose": ("verifier-side", "gopkg.in/go-jose/go-jose.v2/jwt, typed jwt.Claims"),
    "go-opa-json": ("policy-side", "OPA Rego json.unmarshal"),
    "go-opa-jwt": ("policy-side", "OPA Rego io.jwt.verify_rs256 + io.jwt.decode"),
    "py-json": ("general-purpose", "CPython json.loads"),
    "py-pyjwt": ("verifier-side", "PyJWT jwt.decode"),
    "node-json": ("general-purpose", "Node.js JSON.parse"),
    "node-jose": ("verifier-side", "jose compactVerify + decodeJwt"),
    "node-jsonwebtoken": ("verifier-side", "jsonwebtoken verify"),
    "rs-serdejson": ("general-purpose", "serde_json::from_slice::<Value>"),
    "rs-jsonwebtoken": ("verifier-side", "jsonwebtoken::decode::<Map<String, Value>>"),
}
PARSER_IDS = list(PARSERS)
PAIRS = list(combinations(PARSER_IDS, 2))  # 66 unordered pairs, fixed order

AGREE, ACCEPTANCE, VALUE, BOTH_REJECT = "AGREE", "ACCEPTANCE", "VALUE", "BOTH-REJECT"


def load_manifest(corpus="corpus"):
    with open(os.path.join(corpus, "MANIFEST.csv"), newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_raw(raw_dir="results/raw", corpus="corpus"):
    """Return {(case, parser): record}; fail loudly on missing, extra or duplicate records."""
    case_ids = [r["id"] for r in load_manifest(corpus)]
    recs = {}
    for path in sorted(glob.glob(os.path.join(raw_dir, "*.jsonl"))):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                r = json.loads(line)
                key = (r["case"], r["parser"])
                if key in recs:
                    raise SystemExit(f"duplicate record {key} in {path}")
                if r["parser"] not in PARSERS or r["outcome"] not in ("ACCEPT", "REJECT") or r.get("schema") != 1:
                    raise SystemExit(f"malformed record {key} in {path}")
                if r["outcome"] == "ACCEPT" and set(r["fields"]) != set(FIELDS):
                    raise SystemExit(f"record {key} lacks one of the five fields")
                recs[key] = r
    missing = [(c, p) for c in case_ids for p in PARSER_IDS if (c, p) not in recs]
    if missing:
        raise SystemExit(f"{len(missing)} (case, parser) records missing, e.g. {missing[:3]}")
    extra = [k for k in recs if k[0] not in set(case_ids)]
    if extra:
        raise SystemExit(f"records for unknown cases, e.g. {extra[:3]}")
    return recs


def _number(v):
    """Exact numeric value: Fraction, or 'nan' / 'inf' / '-inf'. Negative zero equals zero."""
    kind = v["kind"]
    if kind == "int":
        return Fraction(int(v["v"]))
    if kind == "decimal":
        d = Decimal(v["v"])
        if d.is_nan():
            return "nan"
        if d.is_infinite():
            return "inf" if d > 0 else "-inf"
        return Fraction(d)
    if kind == "f64":
        x = struct.unpack(">d", bytes.fromhex(v["bits"]))[0]
        if math.isnan(x):
            return "nan"  # all NaN payloads are equal
        if math.isinf(x):
            return "inf" if x > 0 else "-inf"
        return Fraction(x)  # exact binary value
    raise ValueError(f"unknown number kind {kind}")


def norm(v):
    """Canonical encoded value -> hashable, comparable form (rules in PREREGISTRATION section 5.3)."""
    t = v["t"]
    if t == "absent":
        return ("ABSENT",)
    if t == "null":
        return ("null",)
    if t == "bool":
        return ("bool", bool(v["v"]))
    if t == "string":
        return ("str", tuple(v["cp"]))
    if t == "number":
        return ("num", _number(v))
    if t == "array":
        return ("arr", tuple(norm(e) for e in v["v"]))
    if t == "object":
        return ("obj", frozenset((norm(k), norm(x)) for k, x in v["v"]))
    if t == "other":
        return ("other", v["v"])
    raise ValueError(f"unknown value type {t}")


def field_value(rec, field, aud_rule="rfc"):
    """Normalised value of one field of an ACCEPT record.

    aud_rule="rfc" (primary): a string aud equals the one-element array holding it.
    aud_rule="strict" (sensitivity): string and array are different values.
    """
    n = norm(rec["fields"][field])
    if field == "aud" and aud_rule == "rfc" and n[0] == "str":
        return ("arr", (n,))
    return n


def classify(ra, rb, aud_rule="rfc"):
    """Classify one (input, parser pair). Returns (class, [field diffs])."""
    a_ok, b_ok = ra["outcome"] == "ACCEPT", rb["outcome"] == "ACCEPT"
    if not a_ok and not b_ok:
        return BOTH_REJECT, []
    if a_ok != b_ok:
        return ACCEPTANCE, []
    diffs = []
    for f in FIELDS:
        va, vb = field_value(ra, f, aud_rule), field_value(rb, f, aud_rule)
        if va != vb:
            diffs.append({"field": f, "a_absent": va == ("ABSENT",), "b_absent": vb == ("ABSENT",)})
    return (VALUE, diffs) if diffs else (AGREE, [])


def role_pair(a, b):
    return " x ".join(sorted([PARSERS[a][0], PARSERS[b][0]]))


def load_pairs(path="results/pairs.jsonl"):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def display(v):
    """Short human-readable rendering of an encoded value (for reports only)."""
    t = v["t"]
    if t == "string":
        return json.dumps("".join(chr(c) if c >= 0 else f"\\x{-c - 1:02x}" for c in v["cp"]), ensure_ascii=True)
    if t == "number":
        n = _number(v)
        return n if isinstance(n, str) else (str(n.numerator) if n.denominator == 1 else f"{float(n)!r}~{n}")
    if t in ("array",):
        return "[" + ",".join(str(display(e)) for e in v["v"]) + "]"
    if t == "object":
        return "{" + ",".join(f"{display(k)}:{display(x)}" for k, x in v["v"]) + "}"
    if t == "bool":
        return "true" if v["v"] else "false"
    return t.upper() if t in ("absent", "null") else f"<{v['v']}>"
