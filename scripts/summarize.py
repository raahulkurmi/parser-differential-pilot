"""results/pairs.jsonl + results/raw/*.jsonl -> results/summary/*.csv and results/summary/SUMMARY.md.

Every number in the summary is computed here from those files; nothing is typed in by hand.
Usage: python3 scripts/summarize.py
"""

import csv
import os
from collections import defaultdict

from pdp_common import ACCEPTANCE, AGREE, BOTH_REJECT, FIELDS, PAIRS, PARSER_IDS, PARSERS, VALUE, load_manifest, load_pairs, load_raw, role_pair

OUT = "results/summary"


def pair_sets(pairs, cls_key="class", diffs_key="diffs"):
    value, acceptance = set(), set()
    by_field = defaultdict(set)
    by_field_absent = defaultdict(set)
    by_cat_value, by_cat_acc = defaultdict(set), defaultdict(set)
    for p in pairs:
        k = (p["a"], p["b"])
        if p[cls_key] == VALUE:
            value.add(k)
            by_cat_value[p["category"]].add(k)
            for d in p[diffs_key]:
                by_field[d["field"]].add(k)
                if d["a_absent"] or d["b_absent"]:
                    by_field_absent[d["field"]].add(k)
        elif p[cls_key] == ACCEPTANCE:
            acceptance.add(k)
            by_cat_acc[p["category"]].add(k)
    return value, acceptance, by_field, by_field_absent, by_cat_value, by_cat_acc


def write_csv(name, header, rows):
    with open(os.path.join(OUT, name), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)
    return [header] + [list(map(str, r)) for r in rows]


def md_table(rows):
    head, body = rows[0], rows[1:]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    lines += ["| " + " | ".join(map(str, r)) + " |" for r in body]
    return "\n".join(lines)


def main():
    os.makedirs(OUT, exist_ok=True)
    manifest = load_manifest()
    recs = load_raw()
    pairs = load_pairs()
    total = len(PAIRS)
    value, acceptance, by_field, by_field_absent, by_cat_value, by_cat_acc = pair_sets(pairs)
    value_s, acceptance_s, by_field_s, _, _, _ = pair_sets(pairs, "class_strict_aud", "diffs_strict_aud")

    role_groups = defaultdict(list)
    for a, b in PAIRS:
        role_groups[role_pair(a, b)].append((a, b))

    metrics = [
        ("PRIMARY: pairs with >=1 VALUE differential on a security-relevant field (aud rule: rfc)", len(value), total),
        ("pairs with >=1 ACCEPTANCE differential", len(acceptance), total),
        ("pairs with >=1 VALUE differential (aud rule: strict, sensitivity)", len(value_s), total),
        ("pairs with >=1 ACCEPTANCE differential (aud rule: strict, sensitivity)", len(acceptance_s), total),
    ]
    for rp in sorted(role_groups):
        g = role_groups[rp]
        metrics.append((f"[{rp}] pairs with >=1 VALUE differential", len(value & set(g)), len(g)))
        metrics.append((f"[{rp}] pairs with >=1 ACCEPTANCE differential", len(acceptance & set(g)), len(g)))
    t_metrics = write_csv("metrics.csv", ["metric", "count", "of"], metrics)

    cats = sorted({r["category"] for r in manifest})
    cat_rows = []
    for c in cats:
        cps = [p for p in pairs if p["category"] == c]
        cnt = {k: sum(1 for p in cps if p["class"] == k) for k in (AGREE, ACCEPTANCE, VALUE, BOTH_REJECT)}
        ncases = sum(1 for r in manifest if r["category"] == c)
        cat_rows.append((c, ncases, len(by_cat_value[c]), len(by_cat_acc[c]), cnt[AGREE], cnt[ACCEPTANCE], cnt[VALUE], cnt[BOTH_REJECT]))
    t_cat = write_csv("per_category.csv", ["category", "cases", "pairs_with_value_diff", "pairs_with_acceptance_diff",
                                           "AGREE", "ACCEPTANCE", "VALUE", "BOTH-REJECT"], cat_rows)

    t_field = write_csv("per_field.csv", ["field", "pairs_with_value_diff", "of_which_one_side_absent", "pairs_with_value_diff_strict_aud"],
                        [(f, len(by_field[f]), len(by_field_absent[f]), len(by_field_s[f])) for f in FIELDS])

    pair_rows = []
    for a, b in PAIRS:
        ps = [p for p in pairs if p["a"] == a and p["b"] == b]
        cnt = {k: sum(1 for p in ps if p["class"] == k) for k in (AGREE, ACCEPTANCE, VALUE, BOTH_REJECT)}
        fields = sorted({d["field"] for p in ps for d in p["diffs"]}, key=FIELDS.index)
        pair_rows.append((a, b, role_pair(a, b), cnt[VALUE], cnt[ACCEPTANCE], cnt[AGREE], cnt[BOTH_REJECT], " ".join(fields) or "-"))
    t_pair = write_csv("per_pair.csv", ["a", "b", "roles", "VALUE_cases", "ACCEPTANCE_cases", "AGREE_cases", "BOTH-REJECT_cases",
                                        "fields_with_value_diff"], pair_rows)

    acc_rows = []
    for pid in PARSER_IDS:
        row = [pid, PARSERS[pid][0]]
        for c in cats:
            ids = [r["id"] for r in manifest if r["category"] == c]
            row.append(f"{sum(1 for i in ids if recs[(i, pid)]['outcome'] == 'ACCEPT')}/{len(ids)}")
        acc_rows.append(row)
    t_acc = write_csv("per_parser_acceptance.csv", ["parser", "role"] + cats, acc_rows)

    with open(os.path.join(OUT, "SUMMARY.md"), "w", encoding="utf-8") as f:
        f.write("# Summary (generated by scripts/summarize.py; do not edit)\n\n")
        f.write(f"Corpus cases: {len(manifest)}. Parsers: {len(PARSER_IDS)}. Parser pairs: {total}.\n\n")
        for title, t in [("Metrics", t_metrics), ("Per category", t_cat), ("Per field", t_field),
                         ("Acceptance per parser and category", t_acc), ("Per pair", t_pair)]:
            f.write(f"## {title}\n\n{md_table(t)}\n\n")
    print(f"wrote {OUT}/SUMMARY.md")


if __name__ == "__main__":
    main()
