# parser-differential-pilot

A small pre-registered pilot measurement of parser differentials across both
sides of cloud-native authorization.

- Pre-registration: [`docs/PREREGISTRATION.md`](docs/PREREGISTRATION.md) (commit `3499fcb9219f502defd964b7c854625f9a713599`; amendment `0085724fd7bf2944300874f8127911cd3fcde175`)
- Timing evidence: [`docs/TIMING_EVIDENCE.md`](docs/TIMING_EVIDENCE.md)
- Prediction outcomes: [`docs/PREDICTION_OUTCOMES.md`](docs/PREDICTION_OUTCOMES.md)
- Limitations: [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md). Deviations: [`docs/DEVIATIONS.md`](docs/DEVIATIONS.md). Summary: [`docs/SUMMARY.md`](docs/SUMMARY.md)

## Question

Do the JSON and JWT parsers used on both sides of cloud-native authorization
(policy layers and verifiers) interpret the same ambiguous input differently?
How often does the disagreement land in the fields that decide a security
outcome (`iss`, `sub`, `aud`, `exp`, `iat`)?

The framing is components that each enforce part of one security decision but
disagree about the input. Parser differentials are an established LangSec
topic, and this pilot claims no novelty. Results describe how each parser
handles each input. They do not state or imply that any product, deployment or
combination of these libraries is vulnerable or affected.

## Method

- **Parsers.** 12, at exact pinned versions (`results/ENVIRONMENT.md`):
  - policy-side: OPA v1.21.2 `json.unmarshal`, and OPA `io.jwt.verify_rs256` + `io.jwt.decode`;
  - verifier-side: golang-jwt v5.3.0, go-jose v2.6.3 (the version pinned in Kubernetes v1.36.5), PyJWT 2.15.1, jose 6.2.12, jsonwebtoken 9.0.3 (npm), jsonwebtoken 11.1.0 (Rust);
  - general-purpose: Go `encoding/json` (struct decoding), CPython `json`, Node.js `JSON.parse`, serde_json 1.0.154.
- **Corpus v1.** 137 hand-built payloads in 8 categories (control, duplicate keys, case-variant keys, Unicode escapes, numbers for `exp`/`iat`, nested duplicates in `aud`, syntax/encoding, type confusion). Each one is also wrapped as a validly signed RS256 token made with a test-only key, so only payload parsing is under test. The corpus is frozen by `corpus/SHA256SUMS`.
- **Observation.** For each (input, parser) the harness records ACCEPT or REJECT. For an ACCEPT it also records the value of each of the five claims, or ABSENT.
- **Classification.** For each (input, parser pair) the outcome is AGREE, ACCEPTANCE differential (one accepts), VALUE differential (both accept and at least one claim differs), or BOTH-REJECT. The pre-registered equality rules apply: exact numeric value, code-point-exact strings, and a string `aud` treated as equal to a one-element array, with a strict variant reported alongside.

## Headline results (corpus v1, 1,644 observations, 66 parser pairs)

From `results/summary/metrics.csv` and `results/summary/per_field.csv`:

| Metric | aud rule: RFC (primary) | aud rule: strict |
|---|---|---|
| **Pairs with ≥1 VALUE differential on iss/sub/aud/exp/iat** | **60 of 66** | 60 of 66 |
| Pairs with ≥1 ACCEPTANCE differential | 61 of 66 | 61 of 66 |
| Policy-side × verifier-side pairs with ≥1 VALUE differential | 12 of 12 | n/a |
| Policy-side × verifier-side pairs with ≥1 ACCEPTANCE differential | 12 of 12 | n/a |

| Field | Pairs with ≥1 VALUE differential | …of which one side ABSENT | strict aud |
|---|---|---|---|
| iss | 31 | 11 | 31 |
| sub | 31 | 21 | 31 |
| aud | 11 | 11 | 21 |
| exp | 57 | 21 | 57 |
| iat | 57 | 21 | 57 |

- **Predictions.** All 22 pre-registered predictions held (`docs/PREDICTION_OUTCOMES.md`). They were informed by reading library source before any execution, so the perfect hit rate mainly confirms that reading (see `docs/LIMITATIONS.md` §7).
- **Pairs with no VALUE differential.** Exactly 6 pairs had none, and each pair shares an underlying decoder: CPython `json`/PyJWT, the two OPA entries, serde_json/Rust jsonwebtoken, and the three pairs among Node.js `JSON.parse`, jose and jsonwebtoken.
- **What drove the differentials** (from the per-category, per-field and per-pair tables):
  - number representation: exact integer, IEEE-754 double, arbitrary-precision decimal, or go-jose's truncation to `int64`;
  - case-insensitive key matching in Go `encoding/json` struct decoding;
  - Unicode edge cases (lone surrogates, raw surrogate bytes);
  - acceptance differences on duplicate keys (rejected by go-jose v2's JSON fork and, for some claims, by Rust jsonwebtoken), BOMs, `NaN`/`Infinity` literals and type confusion.

Full tables: `results/summary/SUMMARY.md`, `per_category.csv`, `per_field.csv`,
`per_pair.csv`, `per_pair_policy_x_verifier.csv`, `per_parser_acceptance.csv`.

## Reproduce

Requirements: Go 1.26.3, Python 3.13 (CPython), Node.js 24, Rust 1.99 (see `results/ENVIRONMENT.md`).

```sh
shasum -a 256 -c corpus/SHA256SUMS          # verify corpus v1
python3 -m unittest discover -s tests       # equality-rule unit tests (synthetic values)
# Data collection: refuses to run if results/raw/ already holds data,
# so run it on a fresh clone with results/raw/*.jsonl removed.
scripts/run_all.sh
# Analysis only, from the committed raw results:
python3 scripts/classify.py
python3 scripts/check_predictions.py
python3 scripts/summarize.py
python3 scripts/render_reports.py
```

`scripts/build_corpus.py` and `scripts/build_tokens.py` regenerate the corpus
and tokens byte for byte. The key in `testdata/keys/` is **test-only**.

## Layout

- `corpus/`: frozen corpus v1 (`MANIFEST.csv`, payloads, `tokens/`, `SHA256SUMS`)
- `harness/`: one harness per language, each with a lockfile
- `results/raw/`: raw observations (one JSONL per parser)
- `results/pairs.jsonl`: per-(input, pair) classifications
- `results/summary/`: generated tables
- `scripts/`: builders, runner, analysis
- `tests/`: unit tests for the equality and classification rules
