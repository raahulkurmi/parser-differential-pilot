"""Evaluate every pre-registered prediction (docs/PREREGISTRATION.md section 7).

Reads results/raw/*.jsonl and results/pairs.jsonl only. Writes
results/summary/predictions.csv and results/summary/PREDICTIONS.md.
Every prediction is reported, whether it holds or fails.

Usage: python3 scripts/check_predictions.py
"""

import csv
import os
from fractions import Fraction

from pdp_common import FIELDS, PAIRS, PARSER_IDS, PARSERS, VALUE, field_value, load_pairs, load_raw

R = load_raw()
P = load_pairs()
OUT = "results/summary"


def acc(c, p):
    return R[(c, p)]["outcome"] == "ACCEPT"


def val(c, p, f):
    return field_value(R[(c, p)], f, "rfc")


def accept_set(c):
    return {p for p in PARSER_IDS if acc(c, p)}


def s(text):
    return ("str", tuple(ord(ch) for ch in text))


def num(x):
    return ("num", Fraction(x))


ABSENT = ("ABSENT",)
value_pairs = {(p["a"], p["b"]) for p in P if p["class"] == VALUE}


def field_pairs(f):
    return {(p["a"], p["b"]) for p in P if p["class"] == VALUE and any(d["field"] == f for d in p["diffs"])}


B_LAST = {"iss": s("https://attacker.example"), "sub": s("admin"), "aud": ("arr", (s("other-api.example"),)),
          "exp": num(9999999999), "iat": num(1)}


def p1():
    n = len(value_pairs)
    return 50 <= n <= 63, f"{n} of {len(PAIRS)} pairs"


def p2():
    n = len({(p["a"], p["b"]) for p in P if p["class"] == "ACCEPTANCE"})
    return 54 <= n <= 64, f"{n} of {len(PAIRS)} pairs"


def p3():
    ctl = sorted({p["case"] for p in P if p["category"] == "control"})
    bad = [(c, q) for c in ctl for q in PARSER_IDS if not acc(c, q)]
    nonagree = [(p["case"], p["a"], p["b"]) for p in P if p["category"] == "control" and p["class"] != "AGREE"]
    return not bad and not nonagree, f"rejects={bad[:5]} non-agree pairs={len(nonagree)}"


def p4():
    bad = []
    checks = [(f"dup_{f}_diff", f, B_LAST[f]) for f in FIELDS] + [("dup_iss_triple", "iss", s("https://third.example"))]
    for c, f, want in checks:
        for q in PARSER_IDS:
            if acc(c, q) and val(c, q, f) != want:
                bad.append((c, q))
    return not bad, f"accepting parsers not reporting the last occurrence: {bad}"


DUP_CASES = [f"dup_{f}_diff" for f in FIELDS] + [f"dup_{f}_null" for f in FIELDS] + ["dup_iss_triple"]


def p5():
    gj = [c for c in DUP_CASES if acc(c, "go-gojose")]
    rs_rej = [f"dup_{f}_{k}" for f in ["iss", "sub", "aud", "exp"] for k in ["diff", "null"]] + ["dup_iss_triple"]
    rs_ok = all(not acc(c, "rs-jsonwebtoken") for c in rs_rej) and acc("dup_iat_diff", "rs-jsonwebtoken") and acc("dup_iat_null", "rs-jsonwebtoken")
    others = [(c, q) for c in DUP_CASES for q in PARSER_IDS if q not in ("go-gojose", "rs-jsonwebtoken") and not acc(c, q)]
    return not gj and rs_ok and not others, f"go-gojose accepted={gj}; rs-jsonwebtoken pattern holds={rs_ok}; other rejections={others}"


def p6():
    bad = [(p["case"], p["a"], p["b"]) for p in P if p["category"] == "duplicate-key" and p["class"] == VALUE]
    return not bad, f"{len(bad)} VALUE differentials in the duplicate-key category, e.g. {bad[:3]}"


def _only_go_struct_sees(c, f):
    go = acc(c, "go-encjson-struct") and val(c, "go-encjson-struct", f) != ABSENT
    others = [q for q in PARSER_IDS if q != "go-encjson-struct" and acc(c, q) and val(c, q, f) != ABSENT]
    return go, others


def p7():
    detail, ok = [], True
    for c, f in [(f"case_{f}_upper_only", f) for f in FIELDS] + [("case_iss_title_only", "iss")]:
        go, others = _only_go_struct_sees(c, f)
        ok = ok and go and not others
        detail.append(f"{c}: go-struct-present={go} others-present={others}")
    return ok, "; ".join(detail)


def p8():
    go, others = _only_go_struct_sees("case_sub_longs_only", "sub")
    return go and not others, f"go-struct-present={go} others-present={others}"


def p9():
    bad = {(p["case"], p["a"], p["b"]) for p in P if p["category"] == "case-variant" and p["class"] == VALUE
           and "go-encjson-struct" not in (p["a"], p["b"])}
    return not bad, f"{len(bad)} case-variant VALUE differentials without go-encjson-struct, e.g. {sorted(bad)[:3]}"


def p10():
    bad = []
    for c, f in [(f"uesc_{f}_first_char", f) for f in FIELDS] + [("uesc_iss_all_escaped", "iss")]:
        for q in PARSER_IDS:
            if acc(c, q) and (not acc("ctl_baseline", q) or val(c, q, f) != val("ctl_baseline", q, f)):
                bad.append((c, q))
    for f in FIELDS:
        c, d = f"uesc_{f}_dup_after", f"dup_{f}_diff"
        for q in PARSER_IDS:
            if acc(c, q) != acc(d, q) or (acc(c, q) and val(c, q, f) != val(d, q, f)):
                bad.append((c, q))
    return not bad, f"violations: {bad}"


def p11():
    c = "num_exp_2p53p1"
    py = acc(c, "py-json") and val(c, "py-json", "exp") == num(9007199254740993)
    nd = acc(c, "node-json") and val(c, "node-json", "exp") == num(9007199254740992)
    return py and nd, f"py-json exact={py}, node-json rounded={nd}"


def p12():
    c = "num_exp_1_5"
    gj = acc(c, "go-gojose") and val(c, "go-gojose", "exp") == num(1)
    py = acc(c, "py-json") and val(c, "py-json", "exp") == num(Fraction(3, 2))
    return gj and py, f"go-gojose=1: {gj}; py-json=1.5: {py}"


def p13():
    sets = {c: accept_set(c) for c in ["num_exp_nan", "num_exp_infinity", "num_iat_nan", "num_iat_infinity"]}
    return all(v == {"py-json", "py-pyjwt"} for v in sets.values()), str({k: sorted(v) for k, v in sets.items()})


def p14():
    a = accept_set("syn_bom_utf8")
    return a == {"py-json", "py-pyjwt", "node-jose"}, f"accept set {sorted(a)}"


def _all_reject(cases):
    acc_any = {c: sorted(accept_set(c)) for c in cases if accept_set(c)}
    return not acc_any, f"accepting: {acc_any}"


def p15():
    return _all_reject(["syn_comment_line", "syn_comment_block_inside", "syn_trailing_comma_object",
                        "syn_trailing_comma_array", "syn_single_quotes", "syn_unquoted_key"])


def p16():
    return _all_reject(["syn_trailing_garbage", "syn_trailing_object", "syn_trailing_nul"])


def p17():
    res = {c: (not acc(c, "go-gojose")) and acc(c, "py-json") for c in ["type_exp_string", "type_iss_number"]}
    return all(res.values()), str(res)


def p18():
    pv = [(a, b) for a, b in PAIRS if {PARSERS[a][0], PARSERS[b][0]} == {"policy-side", "verifier-side"}]
    n = len(set(pv) & value_pairs)
    return n >= 10, f"{n} of {len(pv)} policy-side x verifier-side pairs"


def p19():
    n = {f: len(field_pairs(f)) for f in FIELDS}
    top = max(n["iss"], n["sub"], n["aud"])
    return n["exp"] >= top and n["iat"] >= top, str(n)


def p20():
    c = "num_exp_overflow"
    ok = acc(c, "go-opa-json") and acc(c, "py-json") and val(c, "go-opa-json", "exp") != val(c, "py-json", "exp")
    return ok, f"opa accept={acc(c, 'go-opa-json')} py accept={acc(c, 'py-json')}"


def p21():
    c = "syn_raw_surrogate_utf8"
    ok = acc(c, "py-json") and acc(c, "go-golangjwt") and val(c, "py-json", "sub") != val(c, "go-golangjwt", "sub")
    return ok, f"py accept={acc(c, 'py-json')} golang-jwt accept={acc(c, 'go-golangjwt')}"


EXPECTED_AGREEING = {("py-json", "py-pyjwt"), ("go-opa-json", "go-opa-jwt"), ("rs-serdejson", "rs-jsonwebtoken"),
                     ("node-json", "node-jose"), ("node-json", "node-jsonwebtoken"), ("node-jose", "node-jsonwebtoken")}


def p22():
    zero = set(PAIRS) - value_pairs
    return zero == EXPECTED_AGREEING, f"pairs with no VALUE differential: {sorted(zero)}"


PREDICTIONS = [p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14, p15, p16, p17, p18, p19, p20, p21, p22]


def main():
    os.makedirs(OUT, exist_ok=True)
    rows = []
    for fn in PREDICTIONS:
        held, evidence = fn()
        rows.append((fn.__name__.upper(), "HOLDS" if held else "FAILS", evidence))
    with open(os.path.join(OUT, "predictions.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["prediction", "result", "evidence"])
        w.writerows(rows)
    with open(os.path.join(OUT, "PREDICTIONS.md"), "w", encoding="utf-8") as f:
        f.write("# Pre-registered predictions: results (generated by scripts/check_predictions.py; do not edit)\n\n")
        f.write(f"{sum(r[1] == 'HOLDS' for r in rows)} of {len(rows)} predictions hold.\n\n")
        f.write("| # | result | evidence |\n|---|---|---|\n")
        for r in rows:
            f.write(f"| {r[0]} | {r[1]} | {r[2].replace('|', '/')} |\n")
    for r in rows:
        print(f"{r[0]:>4} {r[1]}  {r[2]}")


if __name__ == "__main__":
    main()
