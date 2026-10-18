# parser-differential-pilot

A small pre-registered measurement of whether 12 JSON and JWT parsers read the same signed token the same way.

## TL;DR

- **Question.** When one component checks a token and another component makes an authorization decision from it, do their parsers read the same bytes the same way?
- **What was tested.** 12 parsers, in Go, Python, Node.js and Rust, each ran on 137 hand-built, validly signed tokens.
- **Headline (pre-registered).** 60 of the 66 parser pairs disagreed on the value of at least one security-relevant claim for at least one input. All 22 pre-registered predictions held. A post-hoc (not pre-registered) look finds 40 of 66 pairs that disagree on who issued the token or who it is about, and 35 of 66 after removing a go-jose extraction artefact.
- **What this means.** These libraries, called in isolation, can interpret the same bytes differently. It does not show that any product or deployment is vulnerable.

## The problem

A JSON Web Token (JWT) carries a JSON object called the payload. Each member of that object is a **claim**. This study looks at five standard claims (RFC 7519):

| Claim | Meaning |
|---|---|
| `iss` | issuer: who created the token |
| `sub` | subject: who the token is about |
| `aud` | audience: who the token is meant for |
| `exp` | expiry time |
| `iat` | issued-at time |

One authorization decision is often split across components. On the **verifier side**, a library checks the token's signature and hands the claims to an application. On the **policy side**, a policy engine reads claims to decide whether a request is allowed. A **parser differential** is a case where two parsers read the same input differently. One parser accepts what the other rejects, or both accept but extract different values.

**Worked example.** This is corpus case `case_iss_lower_then_upper` ([`corpus/case_iss_lower_then_upper.json`](corpus/case_iss_lower_then_upper.json)). It has a lower-case `iss` key and, at the end, an upper-case `ISS` key:

```json
{"iss":"https://issuer.example","sub":"user-1","aud":"api.example","exp":4102444800,"iat":1700000000,"ISS":"https://attacker.example"}
```

What two parsers extracted as `iss`, taken from [`results/raw/`](results/raw/):

| Parser (role) | Outcome | `iss` it reported |
|---|---|---|
| Go `encoding/json`, decoding into a struct (general-purpose) | ACCEPT | `https://attacker.example` |
| Open Policy Agent `json.unmarshal` (policy side) | ACCEPT | `https://issuer.example` |

Go's struct decoding matches keys without regard to case, so the later `ISS` member wins. The policy engine looks up the exact name `iss`. Every other parser in the study also reported `https://issuer.example`.

The same kind of split also occurs directly between the policy side and the verifier side. In case `uesc_iss_value_lone_surrogate`, the `iss` value ends in the escape `\ud800`, which is half of a UTF-16 surrogate pair. The OPA entries replace it with the Unicode replacement character, while Node.js `jsonwebtoken` keeps the lone surrogate.

**Why it matters.** Suppose a verifier checks the signature and the issuer, and a policy engine then makes its decision from its own reading of the same payload. If the two read different issuers, each component has checked a different token. A valid signature does not help, because both components agree the bytes are authentic. They disagree about what the bytes say.

Parser differentials are an established topic in Language-theoretic Security (LangSec). Well-known examples include the Android "Master Key" bug, where two ZIP parsers disagreed about duplicate entries, and Apple's "Psychic Paper", where two property-list parsers disagreed about an app's entitlements. JSON interoperability across parsers has also been surveyed before. This pilot claims no novelty. It applies a pre-registered, fully scripted measurement to one specific set of libraries.

## What was tested

### Parsers

Exact versions are pinned in lockfiles and listed in [`results/ENVIRONMENT.md`](results/ENVIRONMENT.md).

| Parser | Version | Language | Role |
|---|---|---|---|
| Open Policy Agent `json.unmarshal` | v1.21.2 | Go | policy side |
| Open Policy Agent `io.jwt.verify_rs256` + `io.jwt.decode` | v1.21.2 | Go | policy side |
| golang-jwt | v5.3.0 | Go | verifier side |
| go-jose | v2.6.3 | Go | verifier side |
| PyJWT | 2.15.1 | Python | verifier side |
| jose (npm) | 6.2.12 | Node.js | verifier side |
| jsonwebtoken (npm) | 9.0.3 | Node.js | verifier side |
| jsonwebtoken (crate) | 11.1.0 | Rust | verifier side |
| `encoding/json`, struct decoding | go1.26.3 | Go | general-purpose |
| `json` | CPython 3.13.9 | Python | general-purpose |
| `JSON.parse` | Node.js v24.5.0 | Node.js | general-purpose |
| serde_json | 1.0.154 | Rust | general-purpose |

General-purpose parsers are plain JSON decoders that applications and JWT libraries build on. 12 parsers give 66 unordered pairs. 12 of those pairs are policy side × verifier side.

### Corpus

Corpus v1 has 137 hand-built payloads in 8 categories ([`corpus/MANIFEST.csv`](corpus/MANIFEST.csv) lists every case):

| Category | Cases | What it probes |
|---|---|---|
| control | 5 | ordinary payloads that every parser should read the same way |
| duplicate-key | 11 | the same claim name appears twice, with a different value or `null` |
| case-variant | 18 | keys such as `ISS`, `Iss` or `ſub` (with U+017F) instead of the exact name |
| unicode-escape | 19 | keys and values written with `\u` escapes, including lone surrogates and NUL |
| number | 36 | unusual `exp`/`iat` numbers: very large, fractional, exponent forms, `NaN`, leading zeros |
| nested-duplicate | 9 | odd `aud` arrays: repeated entries, nested arrays, mixed types |
| syntax | 20 | byte-level variations: BOMs, other encodings, trailing data, comments, invalid UTF-8 |
| type-confusion | 19 | a claim with an unexpected JSON type, such as a numeric `iss` or a string `exp` |

**Every token is validly signed.** Each payload is wrapped, byte for byte, in an RS256 token signed with a throwaway test key ([`testdata/keys/`](testdata/keys/)). Signature checks therefore always pass, and only payload parsing is under test. Every optional claim check that a library lets callers switch off (expiry, audience and so on) is switched off.

## How it was done

1. **Observation per (input, parser).** Each parser ran once on each input. The harness recorded ACCEPT or REJECT. For ACCEPT, it also recorded the value of each of the five claims, or ABSENT if the parser exposed no value.
2. **Classification per (input, parser pair):**
   - **AGREE:** both accept and all five claims are equal.
   - **ACCEPTANCE differential:** exactly one of the two accepts.
   - **VALUE differential:** both accept, and at least one claim differs.
   - **BOTH-REJECT:** both reject.
3. **Equality rules**, fixed in advance:
   - Types are strict: `"123"` is not `123`, and `null` is not ABSENT.
   - Numbers compare by exact mathematical value. A parser that rounds `9007199254740993` to the nearest double holds a different value from one that keeps it exactly.
   - Strings compare by exact Unicode code points, with no normalisation or case folding.
   - A string `aud` equals a one-element array holding that string (RFC 7519 §4.1.3). A strict variant that treats them as different is also reported.

The full rules are in [`docs/PREREGISTRATION.md`](docs/PREREGISTRATION.md) §4–§6.

## Results

### Pre-registered results

These metrics and predictions were fixed before any parser ran. The numbers come from [`results/summary/`](results/summary/).

| Metric | Result |
|---|---|
| **Primary:** pairs with ≥1 VALUE differential on `iss`/`sub`/`aud`/`exp`/`iat` | **60 of 66** |
| Pairs with ≥1 ACCEPTANCE differential | 61 of 66 |
| Policy side × verifier side pairs with ≥1 VALUE differential | 12 of 12 |
| Policy side × verifier side pairs with ≥1 ACCEPTANCE differential | 12 of 12 |

The strict `aud` rule gives the same two pair counts: 60 and 61 of 66.

Pairs with ≥1 VALUE differential, by claim:

| Claim | Pairs | …of which one side ABSENT | Strict `aud` rule |
|---|---|---|---|
| `iss` | 31 | 11 | 31 |
| `sub` | 31 | 21 | 31 |
| `aud` | 11 | 11 | 21 |
| `exp` | 57 | 21 | 57 |
| `iat` | 57 | 21 | 57 |

The 6 pairs with no VALUE differential each share an underlying decoder, for example CPython `json` and PyJWT.

**Predictions.** All 22 pre-registered predictions held ([`docs/PREDICTION_OUTCOMES.md`](docs/PREDICTION_OUTCOMES.md)). They were written after reading each library's documentation and source code, before running anything. The perfect hit rate therefore mainly confirms that reading. It is not evidence for a broader hypothesis.

### Exploratory results (post-hoc, not pre-registered)

This analysis was designed after the pre-registered results were seen. It carries no confirmatory weight. Details: [`docs/EXPLORATORY.md`](docs/EXPLORATORY.md); numbers: [`results/exploratory/numbers.txt`](results/exploratory/numbers.txt).

- **Identity claims.** 40 of 66 pairs disagree on the value of `iss` or `sub` for at least one input.
- **After removing extraction artefacts: 35 of 66.** go-jose decodes claims into a typed struct, which cannot hold `null`. The pre-registered rule reports that as ABSENT, while other parsers report `null`. That is a property of the extraction rule, not a parsing difference. Removing it leaves 35 of 66.
- **What drives the full count of 60.** Most `exp`/`iat` disagreements come from number representation: exact integer, 64-bit floating point, exact decimal, or go-jose's conversion to a 64-bit integer. Removing number-representation-only differentials and the go-jose artefacts leaves the same 35 of 66 pairs, and all 35 disagree on `iss` or `sub`.
- **What drives the 35.**
  - Case-insensitive key matching in Go `encoding/json` struct decoding.
  - Unicode edge cases: a `\u`-escaped lone surrogate in a value, and raw UTF-8-encoded surrogate bytes. Some parsers keep the surrogate. Others substitute the replacement character.
- **Duplicate keys** produced accept/reject splits only, never VALUE differentials. Where the second occurrence had a different value, every parser that accepted the input took the last one (predictions P4 and P6, which are pre-registered).

Detailed tables: [`results/summary/SUMMARY.md`](results/summary/SUMMARY.md), [`results/summary/per_pair.csv`](results/summary/per_pair.csv), [`results/summary/per_pair_policy_x_verifier.csv`](results/summary/per_pair_policy_x_verifier.csv), [`results/summary/per_category.csv`](results/summary/per_category.csv), [`results/exploratory/`](results/exploratory/).

## What this does not show

- **Isolated parsers, not deployments.** Each library was called alone, with one API and one configuration. Real systems add gateways, re-serialisation, validation and size limits. Whether any differential survives such a chain was not tested.
- **Disagreement is not exploitability.** A differential shows that two parsers read the same bytes differently. It does not show that any product, deployment or combination of these libraries is vulnerable. Pairs are not weighted by how often they are used together, and many never are.
- **A hand-built corpus, not prevalence.** The counts depend on which 137 cases were chosen. They say nothing about how often such inputs occur.
- **Version- and platform-specific.** Results hold for the pinned versions on macOS arm64. Some go-jose values for out-of-range numbers depend on the CPU architecture.

Full list: [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).

## How to trust this result

**Pre-registration** means writing down the question, method, metrics and predictions, and fixing them with an independent timestamp, before collecting any data. That way the analysis cannot be adjusted to fit the results.

- **Pre-registration pushed before any data.** Commit `3499fcb9219f502defd964b7c854625f9a713599` reached GitHub at **2026-10-17T08:57:22Z**. That time is GitHub's server-side push record from the `/activity` endpoint, not the local clock ([`docs/TIMING_EVIDENCE.md`](docs/TIMING_EVIDENCE.md)). The repository was private at that time and is public now.
- **Raw results committed before analysis.** The raw parser output was pushed before any classification or summary script ran.
- **Frozen corpus.** Every corpus file and token is hashed in [`corpus/SHA256SUMS`](corpus/SHA256SUMS), and the hash list is also in the pre-registration. The corpus has not changed since.
- **Deviations logged.** Four procedural deviations are recorded in [`docs/DEVIATIONS.md`](docs/DEVIATIONS.md). None changed a prediction, a classification or equality rule, a metric, a parser pin or a corpus file.
- **All numbers script-generated.** No number in the results was typed by hand.

Timeline (push times from GitHub's `/activity` endpoint):

| Order | Commit | Content | Pushed (UTC) |
|---|---|---|---|
| 1 | `3499fcb` | Pre-registration: question, parsers, corpus, rules, predictions | 2026-10-17T08:57:22Z |
| 2 | `0085724` | Pre-registration amendment, before data collection | 2026-10-17T09:13:09Z |
| 3 | `7889750` | Raw results, all parsers | 2026-10-17T09:16:08Z |
| 4 | `6be9f3a` | Pre-registered analysis and prediction outcomes | 2026-10-17T09:19:12Z |
| 5 | `e39db6c` | Exploratory analysis (post-hoc) | 2026-10-17T09:34:49Z |
| 6 | `a9fb655` | Documentation corrections and a portability fix | 2026-10-17T10:53:24Z |

## Reproduce

**Prerequisites:** Go 1.26.3, Python 3.13 (CPython), Node.js 24 with npm, Rust 1.99 with cargo, and `shasum`. Exact versions are in [`results/ENVIRONMENT.md`](results/ENVIRONMENT.md).

**Check the corpus and the equality rules:**

```sh
shasum -a 256 -c corpus/SHA256SUMS
python3 -m unittest discover -s tests
```

**Full run** (builds all harnesses from their lockfiles, runs all 12 parsers, then runs `classify.py`, `summarize.py` and `check_predictions.py`). The script refuses to run if `results/raw/` already holds data, so start from a fresh clone:

```sh
rm results/raw/*.jsonl
PYTHON=python3.13 scripts/run_all.sh
```

`PYTHON` selects the interpreter used to create the Python harness's virtual environment. It defaults to `python3`.

**Analysis only**, from the committed raw results:

```sh
python3 scripts/classify.py
python3 scripts/check_predictions.py
python3 scripts/summarize.py
python3 scripts/render_reports.py
python3 scripts/exploratory.py    # post-hoc, not pre-registered
```

On the committed raw data, these commands reproduce every committed output byte for byte.

## Repository map

- [`corpus/`](corpus/): frozen corpus v1: payloads, signed tokens in `tokens/`, `MANIFEST.csv`, `SHA256SUMS`.
- [`harness/`](harness/): one harness per language (Go, Go with OPA, Python, Node.js, Rust), each with a lockfile.
- [`results/`](results/): raw output per parser (`raw/`), per-pair classifications (`pairs.jsonl`), generated tables (`summary/`), post-hoc tables (`exploratory/`), environment (`ENVIRONMENT.md`).
- [`scripts/`](scripts/): corpus and token builders, the runner, and the analysis scripts.
- [`testdata/`](testdata/): the test-only signing key pair.
- [`tests/`](tests/): unit tests for the equality and classification rules.
- [`docs/PREREGISTRATION.md`](docs/PREREGISTRATION.md): the pre-registered question, parsers, corpus, rules and predictions, plus the amendment made before data collection.
- [`docs/TIMING_EVIDENCE.md`](docs/TIMING_EVIDENCE.md): GitHub's server-side records of when the pre-registration was pushed.
- [`docs/PREDICTION_OUTCOMES.md`](docs/PREDICTION_OUTCOMES.md): each prediction with its outcome and the script output that decided it.
- [`docs/DEVIATIONS.md`](docs/DEVIATIONS.md): procedural deviations from the pre-registered plan.
- [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md): what the results do and do not cover.
- [`docs/EXPLORATORY.md`](docs/EXPLORATORY.md): the post-hoc analysis, clearly separated from the pre-registered one.
- [`docs/SUMMARY.md`](docs/SUMMARY.md): a short written summary of the results.

## Open question

Do real systems actually combine two parsers that disagree, on the same token, in one authorization decision? And if they do, does the disagreement survive the gateways, validation and re-serialisation in between? This pilot does not test either question.

## Author and citation

Rahul Chaudhary (GitHub: [raahulkurmi](https://github.com/raahulkurmi))

Suggested citation:

> Rahul Chaudhary. *parser-differential-pilot: a pre-registered pilot measurement of JSON and JWT parser differentials.* 2026. <https://github.com/raahulkurmi/parser-differential-pilot>
