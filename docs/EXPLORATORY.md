# Exploratory analysis (post-hoc)

> **This analysis was designed after the pre-registered results had been seen.
> It is not pre-registered, and it does not replace the pre-registered metrics**
> in `results/summary/` or the prediction outcomes in `docs/PREDICTION_OUTCOMES.md`.
> It changes no pre-registered rule, result or file.

Results describe how each parser handles each input. They do not state or imply
that any product, deployment or combination of these libraries is vulnerable or
affected. Policy-side × verifier-side figures describe disagreement between
parsers, not between deployed systems.

- **Script:** `scripts/exploratory.py`.
- **Inputs:** it reads only the committed raw results (`results/raw/*.jsonl`, commit `7889750b92d0f30edae0fe13e4f9d31a530ce380`) and the pre-registered classification output (`results/pairs.jsonl`, primary `aud` rule).
- **Outputs:** it writes `results/exploratory/*.csv` and `results/exploratory/numbers.txt`. Every number below is quoted verbatim from `numbers.txt`.

## Definitions (fixed in the script before any number is computed)

- **Identity fields:** `iss` and `sub`. A pair counts if it has at least one VALUE differential on `iss` *or* `sub`, on at least one input.
- **Extraction-rule artefact:** `type_sub_null`. go-jose's typed `Subject` string cannot hold `null`, so it decodes to `""`, which the pre-registered rule (§4) reports as ABSENT. Raw-map parsers report `null`.
- **Number-representation inputs.** These are the 28 cases `num_{exp,iat}_{1e10, 1_5, 2p53p1, 2p63, 2p64p1, negzero, exp_upper, float_int, exp_form, overflow, underflow, precision, nan, infinity}`: `exp`/`iat` literals where parsers can differ only in how exactly they hold the number (exact integer, binary64, exact decimal, truncation or saturation to `int64`).
  - The other number cases are not in this set. `-1` is an ordinary integer, and `0123`, `+1` and `0x10` are invalid literals, which is not a representation question.
  - A (case, pair) VALUE differential is excluded only if the case is in this set *and* the only differing field is that case's target field. A differential on any other field still counts.
  - A coarser robustness variant (c-alt) instead excludes the whole number category (36 cases).

## Results

### (a) Pairs that disagree on `iss` or `sub`

```
(a) pairs with >=1 VALUE differential on iss or sub: 40 of 66
(a) categories responsible (pairs per category): case-variant=11; syntax=14; type-confusion=11; unicode-escape=31
```

The inputs responsible, with the number of pairs each one splits (from
`results/exploratory/a_identity_by_case.csv`):

| Case | Category | Field | Pairs |
|---|---|---|---|
| `uesc_iss_value_lone_surrogate` | unicode-escape | iss | 25 |
| `syn_raw_surrogate_utf8` | syntax | sub | 14 |
| `case_iss_longs_after`, `case_iss_lower_then_upper`, `case_iss_title_only`, `case_iss_upper_only`, `uesc_iss_upper_escaped_only` | case-variant / unicode-escape | iss | 11 each |
| `case_sub_longs_only`, `case_sub_lower_then_upper`, `case_sub_upper_only` | case-variant | sub | 11 each |
| `type_sub_null` | type-confusion | sub | 11 |

In parser terms:
- **lone-surrogate escape in a value:** some parsers keep the lone surrogate, others replace it with U+FFFD;
- **raw UTF-8-encoded surrogate bytes:** CPython decodes them to a surrogate, while Go and Node.js substitute U+FFFD;
- **case-variant keys:** only Go `encoding/json` struct decoding matches them case-insensitively;
- **`null` `sub`:** the go-jose typed-struct artefact defined above.

### (b) The same, excluding `type_sub_null`

```
(b) pairs with >=1 VALUE differential on iss or sub, excluding type_sub_null: 35 of 66
(b) pairs that drop out when type_sub_null is excluded: [('go-gojose', 'go-opa-json'), ('go-gojose', 'go-opa-jwt'), ('go-gojose', 'rs-jsonwebtoken'), ('go-gojose', 'rs-serdejson'), ('go-golangjwt', 'go-gojose')]
```

### (c) Any of the five fields, excluding number-representation-only differentials

```
(c) pairs with >=1 VALUE differential on any field, excluding number-representation-only differentials: 40 of 66
(c-alt) same, excluding the whole number category (all 36 cases): 40 of 66
(c+b) same as (c), also excluding type_sub_null: 40 of 66
```

Why (c+b) stays at 40 even though (b) drops 5 pairs: those pairs still differ
on `type_exp_null` and `type_iat_null`. Those two cases carry the same kind of
extraction-rule artefact, because go-jose's typed `NumericDate` pointer turns
`null` into ABSENT. That was found only after (a)–(e) were run, so variant (f)
below was added to show its effect. Definitions (b) and (c) were not changed.

### (d) The 12 policy-side × verifier-side pairs

```
(d) policy-side x verifier-side pairs with >=1 VALUE differential on iss or sub: 8 of 12
(d) policy-side x verifier-side pairs whose VALUE differentials are on exp/iat only: 4 of 12
(d) policy-side x verifier-side pairs in neither group: 0 of 12
(d) policy-side x verifier-side pairs with >=1 VALUE differential on iss or sub, excluding type_sub_null: 6 of 12
```

Per pair (`results/exploratory/d_policy_x_verifier.csv`):
- The four exp/iat-only pairs are each OPA entry against golang-jwt, and each OPA entry against Rust jsonwebtoken.
- Of the eight iss/sub pairs, the two involving go-jose differ on `sub` only through `type_sub_null`. That is why the count falls to 6 when `type_sub_null` is excluded.

### (e) Values that depend on platform float-to-integer conversion

go-jose v2's `NumericDate` parses the literal as a float64 and converts it with
`int64(f)`. The Go specification leaves that conversion implementation-defined
when `f` is outside the `int64` range. This run was on darwin/arm64, where the
value saturates. The script finds each such case by checking whether the
float64 that Go parsed (taken from `go-encjson-struct`'s record for the same
case) lies outside the `int64` range while go-jose accepted the input.

```
(e) cases whose go-gojose exp/iat value depends on platform float-to-int64 conversion: num_exp_2p63 (exp: float64 9.223372036854776e+18 -> 9223372036854775807); num_exp_2p64p1 (exp: float64 1.8446744073709552e+19 -> 9223372036854775807); num_iat_2p63 (iat: float64 9.223372036854776e+18 -> 9223372036854775807); num_iat_2p64p1 (iat: float64 1.8446744073709552e+19 -> 9223372036854775807)
(e) primary metric without go-gojose differentials on those cases: 60 of 66
(e) pairs that depend only on the platform-dependent go-gojose values: none
(e-coarse) primary metric with those 4 cases removed entirely: 56 of 66
(e-coarse) pairs that drop out (their differentials on these cases do not involve go-gojose): [('py-json', 'rs-jsonwebtoken'), ('py-json', 'rs-serdejson'), ('py-pyjwt', 'rs-jsonwebtoken'), ('py-pyjwt', 'rs-serdejson')]
```

The precise figure (60 of 66) is the relevant one: no pair's VALUE differential
depends only on the platform-dependent go-jose values.

The coarse figure (56) removes the four cases altogether, so it also drops
differentials that are not platform-dependent. For example, on `num_exp_2p64p1`,
CPython keeps 18446744073709551617 as an exact integer, while serde_json, being
above the `u64` range, holds the binary64 value 18446744073709551616.

### (f) Added after (a)–(e): excluding all go-jose null-versus-ABSENT artefacts

A (case, pair) differential is excluded here if `go-gojose` is in the pair and,
for every differing field, `go-gojose` reports ABSENT while the other parser
reports `null`.

```
(f) cases carrying a go-gojose null-vs-ABSENT artefact: type_exp_null, type_iat_null, type_sub_null
(f) pairs with >=1 VALUE differential on iss or sub, excluding null-vs-ABSENT artefacts: 35 of 66
(f) pairs with >=1 VALUE differential on any field, excluding number-representation-only and null-vs-ABSENT artefacts: 35 of 66
(f) pairs in the any-field set without an iss or sub differential: none
(f) policy-side x verifier-side pairs with >=1 VALUE differential on iss or sub, excluding null-vs-ABSENT artefacts: 6 of 12
```

## Reading these numbers

- The pre-registered primary metric remains **60 of 66** (`results/summary/metrics.csv`).
- Every figure in this file is a post-hoc breakdown chosen after seeing the data, so it carries no confirmatory weight.
- Removing number-representation-only differentials and the go-jose null-versus-ABSENT artefacts leaves 35 of 66 pairs that disagree on at least one of the five claims. In all 35, the remaining disagreement is on `iss` or `sub`.
