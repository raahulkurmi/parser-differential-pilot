"""Write corpus/<id>.json and corpus/MANIFEST.csv (corpus version v1).

Every payload is assembled from literal JSON text and written as raw bytes.
No JSON parser or serializer touches the payloads, so the bytes on disk are
exactly the bytes listed here.

Usage: python3 scripts/build_corpus.py   (from the repository root)
"""

import csv
import os

OUT = "corpus"

A = {  # baseline values (raw JSON text)
    "iss": '"https://issuer.example"',
    "sub": '"user-1"',
    "aud": '"api.example"',
    "exp": "4102444800",
    "iat": "1700000000",
}
B = {  # alternative values used for the second occurrence of a key
    "iss": '"https://attacker.example"',
    "sub": '"admin"',
    "aud": '"other-api.example"',
    "exp": "9999999999",
    "iat": "1",
}
FIELDS = ["iss", "sub", "aud", "exp", "iat"]
ESC_FIRST = {"iss": r"iss", "sub": r"sub", "aud": r"aud", "exp": r"exp", "iat": r"iat"}


def base():
    return [(f, A[f]) for f in FIELDS]


def obj(pairs):
    """Raw JSON object text from (raw key text, raw value text) pairs."""
    return "{" + ",".join(f'"{k}":{v}' for k, v in pairs) + "}"


def replace(field, value=None, key=None):
    """Baseline with one member's value and/or key text replaced."""
    return [((key if key is not None else k), (value if value is not None else v)) if k == field else (k, v) for k, v in base()]


def b(text):
    return text.encode("utf-8")


BASE = b(obj(base()))
cases = []  # (id, category, description, expected ambiguity, bytes)


def add(cid, cat, desc, amb, data):
    cases.append((cid, cat, desc, amb, data))


# --- control ---------------------------------------------------------------
add("ctl_baseline", "control", "All five claims, canonical form", "none", BASE)
add("ctl_reordered", "control", "All five claims in reverse member order", "none", b(obj(list(reversed(base())))))
add("ctl_minimal_iss_sub", "control", "Only iss and sub present", "none (aud/exp/iat ABSENT)", b(obj(base()[:2])))
add("ctl_empty_object", "control", "Empty object", "none (all fields ABSENT)", b"{}")
add("ctl_whitespace", "control", "Baseline with all four legal JSON whitespace characters between tokens",
    "none", b('{ \n\t"iss" :\r "https://issuer.example" ,\n "sub":"user-1", "aud":"api.example" ,"exp": 4102444800,"iat":1700000000 \n}'))

# --- duplicate keys ----------------------------------------------------------
for f in FIELDS:
    add(f"dup_{f}_diff", "duplicate-key", f"{f} appears twice: baseline value first, different value last",
        "first-wins vs last-wins vs reject", b(obj(base() + [(f, B[f])])))
for f in FIELDS:
    add(f"dup_{f}_null", "duplicate-key", f"{f} appears twice: baseline value first, null last",
        "last-wins null vs typed decoder ignoring null vs reject", b(obj(base() + [(f, "null")])))
add("dup_iss_triple", "duplicate-key", "iss appears three times with three different values",
    "first vs middle vs last vs reject", b(obj(base() + [("iss", B["iss"]), ("iss", '"https://third.example"')])))

# --- case-variant keys -------------------------------------------------------
for f in FIELDS:
    add(f"case_{f}_upper_only", "case-variant", f"{f} key written only in upper case ({f.upper()})",
        "case-insensitive field matching vs ABSENT", b(obj(replace(f, key=f.upper()))))
for f in FIELDS:
    add(f"case_{f}_lower_then_upper", "case-variant", f"{f} with baseline value, then {f.upper()} with a different value",
        "case-insensitive last-wins vs exact match", b(obj(base() + [(f.upper(), B[f])])))
for f in FIELDS:
    add(f"case_{f}_upper_then_lower", "case-variant", f"{f.upper()} with a different value, then {f} with baseline value",
        "case-insensitive last-wins vs exact match", b(obj([(f.upper(), B[f])] + base())))
add("case_iss_title_only", "case-variant", "iss key written only as Iss", "case-insensitive matching vs ABSENT",
    b(obj(replace("iss", key="Iss"))))
add("case_sub_longs_only", "case-variant", "sub key written only as U+017F LATIN SMALL LETTER LONG S + 'ub' (raw UTF-8)",
    "Unicode simple case folding (long s folds to s) vs ABSENT", b(obj(replace("sub", key="ſub"))))
add("case_iss_longs_after", "case-variant", "baseline iss, then key 'i' U+017F 's' (raw UTF-8) with a different value",
    "Unicode case folding last-wins vs exact match", b(obj(base() + [("iſs", B["iss"])])))

# --- Unicode-escaped keys and values -----------------------------------------
for f in FIELDS:
    add(f"uesc_{f}_first_char", "unicode-escape", f"{f} key with its first character written as a \\u escape ({ESC_FIRST[f]})",
        "escape decoded before key match vs ABSENT", b(obj(replace(f, key=ESC_FIRST[f]))))
for f in FIELDS:
    add(f"uesc_{f}_dup_after", "unicode-escape", f"baseline {f}, then {ESC_FIRST[f]} with a different value",
        "escaped duplicate recognised (last-wins) vs treated as distinct key", b(obj(base() + [(ESC_FIRST[f], B[f])])))
add("uesc_iss_all_escaped", "unicode-escape", r"iss key fully escaped (iss)", "escape decoding vs ABSENT",
    b(obj(replace("iss", key=r"iss"))))
add("uesc_iss_upper_escaped_only", "unicode-escape", r"iss key written only as ISS (escaped upper case)",
    "escape decoding combined with case-insensitive matching", b(obj(replace("iss", key=r"ISS"))))
add("uesc_iss_nul_suffix_after", "unicode-escape", r"baseline iss, then key iss\u0000 with a different value",
    "NUL truncation of keys vs distinct key", b(obj(base() + [(r"iss\u0000", B["iss"])])))
add("uesc_iss_lone_surrogate_after", "unicode-escape", r"baseline iss, then key iss\ud800 (lone surrogate) with a different value",
    "lone-surrogate key: reject vs replace with U+FFFD vs keep", b(obj(base() + [(r"iss\ud800", B["iss"])])))
add("uesc_iss_value_escaped", "unicode-escape", r"iss value with first character escaped (https://...)",
    "none expected (decodes to baseline)", b(obj(replace("iss", value=r'"https://issuer.example"'))))
add("uesc_iss_value_lone_surrogate", "unicode-escape", r"iss value ending in a lone surrogate escape \ud800",
    "reject vs U+FFFD replacement vs lone surrogate kept", b(obj(replace("iss", value=r'"https://issuer.example\ud800"'))))
add("uesc_sub_value_nul", "unicode-escape", r"sub value containing an escaped NUL (user-1\u0000admin)",
    "NUL truncation vs full string", b(obj(replace("sub", value=r'"user-1\u0000admin"'))))
add("uesc_iss_escaped_solidus", "unicode-escape", r"iss value with escaped solidus (https:\/\/issuer.example)",
    "none expected (decodes to baseline)", b(obj(replace("iss", value=r'"https:\/\/issuer.example"'))))
add("uesc_sub_surrogate_pair", "unicode-escape", r"sub value is a valid surrogate pair escape (😀)",
    "none expected (U+1F600)", b(obj(replace("sub", value=r'"😀"'))))

# --- numbers for exp / iat ---------------------------------------------------
NUMBERS = [
    ("1e10", "1e10", "exponent notation, exact integer value 10000000000"),
    ("1_5", "1.5", "non-integer"),
    ("2p53p1", "9007199254740993", "2^53+1, not representable as float64"),
    ("2p63", "9223372036854775808", "2^63, one above int64 max"),
    ("2p64p1", "18446744073709551617", "2^64+1, above uint64 max"),
    ("neg1", "-1", "negative"),
    ("negzero", "-0", "negative zero"),
    ("exp_upper", "1E9", "upper-case exponent, value 1000000000"),
    ("float_int", "4102444800.0", "integer value written with a fraction"),
    ("exp_form", "4.1024448e9", "baseline exp value in exponent form"),
    ("overflow", "1e400", "overflows float64"),
    ("underflow", "1e-400", "underflows float64 to zero"),
    ("precision", "4102444800.0000001", "fraction below float64 resolution at this magnitude"),
    ("nan", "NaN", "non-standard NaN literal"),
    ("infinity", "Infinity", "non-standard Infinity literal"),
    ("leading_zero", "0123", "invalid leading zero"),
    ("plus", "+1", "invalid leading plus sign"),
    ("hex", "0x10", "invalid hexadecimal literal"),
]
for f in ["exp", "iat"]:
    for tag, text, desc in NUMBERS:
        add(f"num_{f}_{tag}", "number", f"{f} = {text} ({desc})",
            "exact vs float64 vs integer-truncated value, or accept vs reject", b(obj(replace(f, value=text))))

# --- nested duplicates (aud) ------------------------------------------------
NEST = [
    ("nest_aud_array_dup_entries", '["api.example","api.example"]', "aud array with the same entry twice",
     "array kept as-is vs de-duplicated"),
    ("nest_aud_array_two", '["api.example","other-api.example"]', "aud array with two different entries", "none expected"),
    ("nest_aud_object_dup_keys", '{"x":"api.example","x":"other-api.example"}', "aud is an object with a duplicated member",
     "object type accepted vs rejected; inner first-wins vs last-wins"),
    ("nest_aud_array_obj_dup", '[{"x":"api.example","x":"other-api.example"}]', "aud array holding an object with a duplicated member",
     "inner first-wins vs last-wins; non-string element accepted vs rejected"),
    ("nest_aud_nested_array", '[["api.example"]]', "aud array nested inside an array", "accepted vs rejected; flattened vs not"),
    ("nest_aud_array_mixed_types", '["api.example",1]', "aud array with a string and a number", "accepted vs rejected"),
    ("nest_aud_empty_array", "[]", "aud is an empty array", "empty array vs ABSENT"),
    ("nest_aud_array_with_null", '["api.example",null]', "aud array with a null element", "accepted vs rejected; null kept vs dropped"),
]
for cid, val, desc, amb in NEST:
    add(cid, "nested-duplicate", desc, amb, b(obj(replace("aud", value=val))))
add("nest_aud_dup_array_then_string", "nested-duplicate", "aud appears twice: first as an array, last as a string",
    "first-wins vs last-wins across differing types", b(obj([(k, '["other-api.example"]' if k == "aud" else v) for k, v in base()] + [("aud", A["aud"])])))

# --- syntax: BOM, trailing data, trailing commas, comments, encodings --------
BASE_TEXT = obj(base())
SYN = [
    ("syn_bom_utf8", "UTF-8 byte order mark before the object", "BOM skipped vs rejected", b"\xef\xbb\xbf" + BASE),
    ("syn_utf16le_bom", "Whole document in UTF-16LE with BOM", "encoding detection vs rejected", b"\xff\xfe" + BASE_TEXT.encode("utf-16-le")),
    ("syn_utf16be_nobom", "Whole document in UTF-16BE without BOM", "encoding detection vs rejected", BASE_TEXT.encode("utf-16-be")),
    ("syn_trailing_garbage", "Non-whitespace byte 'x' after the object", "trailing data ignored vs rejected", BASE + b"x"),
    ("syn_trailing_object", "A second object (with a different iss) after the first", "first object used vs rejected",
     BASE + b(obj([("iss", B["iss"])]))),
    ("syn_trailing_whitespace", "Legal whitespace after the object", "none expected", BASE + b" \n\t\r"),
    ("syn_trailing_nul", "NUL byte after the object", "trailing NUL ignored vs rejected", BASE + b"\x00"),
    ("syn_leading_nbsp", "U+00A0 NO-BREAK SPACE (raw UTF-8) before the object", "non-JSON whitespace accepted vs rejected", b"\xc2\xa0" + BASE),
    ("syn_formfeed_ws", "Form feed used as whitespace between members", "non-JSON whitespace accepted vs rejected",
     b(obj(base()).replace(',"sub"', ',\f"sub"'))),
    ("syn_trailing_comma_object", "Trailing comma after the last member", "lenient accept vs reject", b(BASE_TEXT[:-1] + ",}")),
    ("syn_trailing_comma_array", "Trailing comma inside the aud array", "lenient accept vs reject",
     b(obj(replace("aud", value='["api.example",]')))),
    ("syn_comment_line", "Line comment before the object", "comments accepted vs rejected", b"// comment\n" + BASE),
    ("syn_comment_block_inside", "Block comment inside the object", "comments accepted vs rejected", b("{/* c */" + BASE_TEXT[1:])),
    ("syn_single_quotes", "iss value in single quotes", "lenient accept vs reject",
     b(obj(replace("iss", value="'https://issuer.example'")))),
    ("syn_unquoted_key", "iss key without quotes", "lenient accept vs reject", b(BASE_TEXT.replace('"iss"', "iss"))),
    ("syn_raw_control_char_in_string", "Raw (unescaped) TAB inside the sub value", "lenient accept vs reject",
     b(obj(replace("sub", value='"user\t1"')))),
    ("syn_invalid_utf8_in_value", "Byte 0xFF inside the sub value", "reject vs U+FFFD replacement",
     b'{"iss":"https://issuer.example","sub":"user-\xff1","aud":"api.example","exp":4102444800,"iat":1700000000}'),
    ("syn_overlong_utf8_key_after", "baseline iss, then key 'i' + overlong 2-byte 's' (C1 B3) + 's' with a different value",
     "reject vs U+FFFD replacement vs decoded as s",
     BASE[:-1] + b',"i\xc1\xb3s":"https://attacker.example"}'),
    ("syn_raw_surrogate_utf8", "sub value contains a UTF-8-encoded surrogate (ED A0 80)", "reject vs U+FFFD replacement vs kept",
     b'{"iss":"https://issuer.example","sub":"user-1\xed\xa0\x80","aud":"api.example","exp":4102444800,"iat":1700000000}'),
    ("syn_top_level_array", "Baseline object wrapped in an array", "all reject (claims set must be an object)", b"[" + BASE + b"]"),
]
for cid, desc, amb, data in SYN:
    add(cid, "syntax", desc, amb, data)

# --- type confusion ----------------------------------------------------------
TYPES = [
    ("type_aud_single_array", "aud", '["api.example"]', "aud as a one-element array", "string vs single-element array"),
    ("type_aud_number", "aud", "1", "aud as a number", "accepted vs rejected"),
    ("type_aud_object", "aud", '{"0":"api.example"}', "aud as an object", "accepted vs rejected"),
    ("type_aud_null", "aud", "null", "aud as null", "null vs ABSENT vs rejected"),
    ("type_aud_bool", "aud", "true", "aud as a boolean", "accepted vs rejected"),
    ("type_exp_string", "exp", '"4102444800"', "exp as a numeric string", "string kept vs coerced vs rejected"),
    ("type_iat_string", "iat", '"1700000000"', "iat as a numeric string", "string kept vs coerced vs rejected"),
    ("type_exp_string_float", "exp", '"4102444800.5"', "exp as a non-integer numeric string", "string kept vs coerced vs rejected"),
    ("type_exp_bool", "exp", "true", "exp as a boolean", "accepted vs rejected"),
    ("type_exp_null", "exp", "null", "exp as null", "null vs ABSENT vs rejected"),
    ("type_exp_array", "exp", "[4102444800]", "exp as a one-element array", "accepted vs rejected"),
    ("type_exp_object", "exp", '{"$numberLong":"4102444800"}', "exp as an object", "accepted vs rejected"),
    ("type_iss_number", "iss", "1", "iss as a number", "accepted vs rejected"),
    ("type_iss_array", "iss", '["https://issuer.example"]', "iss as a one-element array", "accepted vs rejected"),
    ("type_iss_object", "iss", '{"value":"https://issuer.example"}', "iss as an object", "accepted vs rejected"),
    ("type_sub_number", "sub", "123", "sub as a number", "accepted vs rejected"),
    ("type_sub_null", "sub", "null", "sub as null", "null vs ABSENT vs rejected"),
    ("type_sub_bool", "sub", "true", "sub as a boolean", "accepted vs rejected"),
    ("type_iat_null", "iat", "null", "iat as null", "null vs ABSENT vs rejected"),
]
for cid, f, val, desc, amb in TYPES:
    add(cid, "type-confusion", desc, amb, b(obj(replace(f, value=val))))


def main():
    ids = [c[0] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case id"
    os.makedirs(OUT, exist_ok=True)
    for cid, _, _, _, data in cases:
        with open(os.path.join(OUT, cid + ".json"), "wb") as f:
            f.write(data)
    with open(os.path.join(OUT, "MANIFEST.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["id", "category", "description", "expected ambiguity"])
        for cid, cat, desc, amb, _ in cases:
            w.writerow([cid, cat, desc, amb])
    print(f"wrote {len(cases)} cases")


if __name__ == "__main__":
    main()
