"""EXPLORATORY (post-hoc, NOT pre-registered) analysis. See docs/EXPLORATORY.md.

This analysis was designed after the pre-registered results were seen. It does
not replace the pre-registered metrics in results/summary/.

Reads only results/raw/*.jsonl (via load_raw) and results/pairs.jsonl.
Writes results/exploratory/*.csv and prints every number it reports.

Usage: python3 scripts/exploratory.py
"""

import csv
import os
import struct
from collections import defaultdict

from pdp_common import PAIRS, PARSERS, VALUE, load_manifest, load_pairs, load_raw

OUT = "results/exploratory"

# --- Exclusion definitions (fixed here, before any number is computed) -------

# (b) Extraction-rule artefact: go-jose's typed Subject string cannot hold null,
# so its null `sub` decodes to "" and is reported as ABSENT (PREREGISTRATION section 4).
EXTRACTION_ARTEFACT_CASES = {"type_sub_null"}

# (c) Number-representation inputs: `exp`/`iat` literals that every parser
# reads as a number, so that parsers can differ only in how exactly they hold
# it (exact integer, binary64, exact decimal, truncation or saturation to int64).
# Excluded: -1 (an ordinary integer) and 0123, +1, 0x10 (invalid literals, not
# a representation question).
NUMBER_REPRESENTATION_TAGS = ["1e10", "1_5", "2p53p1", "2p63", "2p64p1", "negzero", "exp_upper", "float_int",
                              "exp_form", "overflow", "underflow", "precision", "nan", "infinity"]
NUMBER_REPRESENTATION_CASES = {f"num_{f}_{t}": f for f in ("exp", "iat") for t in NUMBER_REPRESENTATION_TAGS}
# A (case, pair) VALUE differential is excluded under (c) only if the case is in
# NUMBER_REPRESENTATION_CASES and the only differing field is that case's
# target field (exp or iat). A differential on any other field still counts.

INT64_MIN, INT64_MAX_PLUS_1 = -(2**63), 2**63


def write(name, header, rows):
    with open(os.path.join(OUT, name), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def main():
    os.makedirs(OUT, exist_ok=True)
    manifest = load_manifest()
    category = {r["id"]: r["category"] for r in manifest}
    recs = load_raw()
    pairs = [p for p in load_pairs() if p["class"] == VALUE]  # primary aud rule
    total = len(PAIRS)
    lines = []

    def report(label, value):
        lines.append(f"{label}: {value}")
        print(f"{label}: {value}")

    # (a) / (b) identity fields iss OR sub
    def identity(exclude):
        hits = [(p, d["field"]) for p in pairs if p["case"] not in exclude for d in p["diffs"] if d["field"] in ("iss", "sub")]
        pair_set = {(p["a"], p["b"]) for p, _ in hits}
        by_case = defaultdict(set)
        for p, f in hits:
            by_case[(p["case"], f)].add((p["a"], p["b"]))
        return pair_set, by_case

    a_pairs, a_cases = identity(set())
    report("(a) pairs with >=1 VALUE differential on iss or sub", f"{len(a_pairs)} of {total}")
    write("a_identity_by_case.csv", ["case", "category", "field", "pairs_with_value_diff"],
          sorted(((c, category[c], f, len(s)) for (c, f), s in a_cases.items()), key=lambda r: (-r[3], r[0], r[2])))
    cat_a = defaultdict(set)
    for (c, _), s in a_cases.items():
        cat_a[category[c]] |= s
    write("a_identity_by_category.csv", ["category", "pairs_with_value_diff_on_iss_or_sub"], sorted((k, len(v)) for k, v in cat_a.items()))
    report("(a) categories responsible (pairs per category)", "; ".join(f"{k}={len(v)}" for k, v in sorted(cat_a.items())))

    b_pairs, b_cases = identity(EXTRACTION_ARTEFACT_CASES)
    report("(b) pairs with >=1 VALUE differential on iss or sub, excluding type_sub_null", f"{len(b_pairs)} of {total}")
    report("(b) pairs that drop out when type_sub_null is excluded", sorted(a_pairs - b_pairs))
    write("b_identity_by_case_excl_type_sub_null.csv", ["case", "category", "field", "pairs_with_value_diff"],
          sorted(((c, category[c], f, len(s)) for (c, f), s in b_cases.items()), key=lambda r: (-r[3], r[0], r[2])))

    # (c) any field, excluding number-representation-only differentials
    def kept(p):
        tgt = NUMBER_REPRESENTATION_CASES.get(p["case"])
        return tgt is None or any(d["field"] != tgt for d in p["diffs"])

    c_pairs = {(p["a"], p["b"]) for p in pairs if kept(p)}
    report("(c) pairs with >=1 VALUE differential on any field, excluding number-representation-only differentials",
           f"{len(c_pairs)} of {total}")
    c_alt = {(p["a"], p["b"]) for p in pairs if category[p["case"]] != "number"}
    report("(c-alt) same, excluding the whole number category (all 36 cases)", f"{len(c_alt)} of {total}")
    c_both = {(p["a"], p["b"]) for p in pairs if kept(p) and p["case"] not in EXTRACTION_ARTEFACT_CASES}
    report("(c+b) same as (c), also excluding type_sub_null", f"{len(c_both)} of {total}")
    write("c_pairs_excluding_number_representation.csv", ["a", "b", "roles", "in_c", "in_c_alt", "in_c_and_b"],
          [(a, b, f"{PARSERS[a][0]} x {PARSERS[b][0]}", (a, b) in c_pairs, (a, b) in c_alt, (a, b) in c_both) for a, b in PAIRS])

    # (d) policy-side x verifier-side pairs
    pv = [(a, b) for a, b in PAIRS if {PARSERS[a][0], PARSERS[b][0]} == {"policy-side", "verifier-side"}]
    fields_by_pair = defaultdict(set)
    for p in pairs:
        fields_by_pair[(p["a"], p["b"])] |= {d["field"] for d in p["diffs"]}
    d_rows = []
    for k in pv:
        fs = fields_by_pair.get(k, set())
        d_rows.append((*k, " ".join(sorted(fs)), bool(fs & {"iss", "sub"}), bool(fs) and fs <= {"exp", "iat"}))
    d_id = sum(r[3] for r in d_rows)
    d_num = sum(r[4] for r in d_rows)
    report("(d) policy-side x verifier-side pairs with >=1 VALUE differential on iss or sub", f"{d_id} of {len(pv)}")
    report("(d) policy-side x verifier-side pairs whose VALUE differentials are on exp/iat only", f"{d_num} of {len(pv)}")
    report("(d) policy-side x verifier-side pairs in neither group", f"{len(pv) - d_id - d_num} of {len(pv)}")
    d_id_b = sum(1 for k in pv if any(f in ("iss", "sub") for p in pairs if (p["a"], p["b"]) == k and p["case"] not in EXTRACTION_ARTEFACT_CASES
                                      for f in [d["field"] for d in p["diffs"]]))
    report("(d) policy-side x verifier-side pairs with >=1 VALUE differential on iss or sub, excluding type_sub_null", f"{d_id_b} of {len(pv)}")
    write("d_policy_x_verifier.csv", ["a", "b", "fields_with_value_diff", "iss_or_sub", "exp_iat_only"], d_rows)

    # (e) platform-dependent float-to-int64 conversion (go-jose NumericDate)
    # go-jose parses the literal with strconv.ParseFloat and converts it with int64(f).
    # The Go spec leaves that conversion implementation-defined when f is outside
    # the int64 range. The float64 that ParseFloat produced is taken from
    # go-encjson-struct's record for the same case (same Go parser, same literal).
    e_rows = []
    for r in manifest:
        c = r["id"]
        jose, ref = recs[(c, "go-gojose")], recs[(c, "go-encjson-struct")]
        if jose["outcome"] != "ACCEPT" or ref["outcome"] != "ACCEPT":
            continue
        for f in ("exp", "iat"):
            v = ref["fields"][f]
            if v["t"] == "number" and v["kind"] == "f64":
                x = struct.unpack(">d", bytes.fromhex(v["bits"]))[0]
                if not (INT64_MIN <= x < INT64_MAX_PLUS_1):
                    e_rows.append((c, f, repr(x), jose["fields"][f].get("v")))
    write("e_platform_dependent_int64.csv", ["case", "field", "float64_value", "go_gojose_reported_on_darwin_arm64"], e_rows)
    report("(e) cases whose go-gojose exp/iat value depends on platform float-to-int64 conversion",
           "; ".join(f"{c} ({f}: float64 {x} -> {v})" for c, f, x, v in e_rows) or "none")
    e_cases = {c for c, *_ in e_rows}
    all_pairs = {(p["a"], p["b"]) for p in pairs}
    # Precise: drop only differentials that involve go-gojose on those cases (the platform-dependent value).
    e_precise = {(p["a"], p["b"]) for p in pairs if not (p["case"] in e_cases and "go-gojose" in (p["a"], p["b"]))}
    report("(e) primary metric without go-gojose differentials on those cases", f"{len(e_precise)} of {total}")
    report("(e) pairs that depend only on the platform-dependent go-gojose values", sorted(all_pairs - e_precise) or "none")
    # Coarse: drop those cases entirely (also removes differentials that are not platform-dependent).
    e_coarse = {(p["a"], p["b"]) for p in pairs if p["case"] not in e_cases}
    report("(e-coarse) primary metric with those 4 cases removed entirely", f"{len(e_coarse)} of {total}")
    report("(e-coarse) pairs that drop out (their differentials on these cases do not involve go-gojose)", sorted(all_pairs - e_coarse))

    # (f) Added after (a)-(e) were run: type_exp_null and type_iat_null turned out to
    # carry the same extraction-rule artefact as type_sub_null (go-jose's typed
    # NumericDate pointer turns null into ABSENT). A (case, pair) differential is
    # excluded here if go-gojose is in the pair and, for every differing field,
    # go-gojose reports ABSENT while the other parser reports null.
    def null_artefact(p):
        if "go-gojose" not in (p["a"], p["b"]):
            return False
        other = p["b"] if p["a"] == "go-gojose" else p["a"]
        jose, oth = recs[(p["case"], "go-gojose")]["fields"], recs[(p["case"], other)]["fields"]
        return all(jose[d["field"]]["t"] == "absent" and oth[d["field"]]["t"] == "null" for d in p["diffs"])

    f_cases = sorted({p["case"] for p in pairs if null_artefact(p)})
    report("(f) cases carrying a go-gojose null-vs-ABSENT artefact", ", ".join(f_cases))
    f_id = {(p["a"], p["b"]) for p in pairs if not null_artefact(p) for d in p["diffs"] if d["field"] in ("iss", "sub")}
    report("(f) pairs with >=1 VALUE differential on iss or sub, excluding null-vs-ABSENT artefacts", f"{len(f_id)} of {total}")
    f_any = {(p["a"], p["b"]) for p in pairs if not null_artefact(p) and kept(p)}
    report("(f) pairs with >=1 VALUE differential on any field, excluding number-representation-only and null-vs-ABSENT artefacts",
           f"{len(f_any)} of {total}")
    report("(f) pairs in the any-field set without an iss or sub differential", sorted(f_any - f_id) or "none")
    f_pv = sum(1 for k in pv if k in f_id)
    report("(f) policy-side x verifier-side pairs with >=1 VALUE differential on iss or sub, excluding null-vs-ABSENT artefacts",
           f"{f_pv} of {len(pv)}")
    write("f_excluding_null_absent_artefacts.csv", ["a", "b", "roles", "iss_or_sub", "any_field_excl_number_repr"],
          [(a, b, f"{PARSERS[a][0]} x {PARSERS[b][0]}", (a, b) in f_id, (a, b) in f_any) for a, b in PAIRS])

    with open(os.path.join(OUT, "numbers.txt"), "w", encoding="utf-8") as f:
        f.write("EXPLORATORY (post-hoc, not pre-registered). Generated by scripts/exploratory.py.\n")
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
