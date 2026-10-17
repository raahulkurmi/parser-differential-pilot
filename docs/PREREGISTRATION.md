# Pre-registration: parser differentials across both sides of cloud-native authorization

Status: **Phase 1 (pre-registration)**. Nothing in this document comes from running
any parser on the corpus. Phase 2 (data collection) begins only after this
document, the corpus, the lockfiles and the harness are pushed in a single commit.
That commit's SHA and GitHub push time are the timestamp of this pre-registration.

Date written: 2026-10-17. Corpus version: **v1**.

---

## 1. Research question and framing

**Question.** Do the JSON and JWT parsers used on both sides of cloud-native
authorization interpret the same ambiguous input differently? Both sides means
policy layers (policy engines that read claims) and verifiers (libraries that
check a token and hand claims to an application). If they do, how often does the
disagreement land in the fields that decide a security outcome: `iss`, `sub`,
`aud`, `exp`, `iat`?

**Framing.** In a typical deployment, one security decision is split across
several components. A verifier checks a token's signature and extracts claims. A
policy layer reads claims, sometimes from the same bytes, to make an
authorization decision. Each component enforces part of one decision. This study
measures whether those components *disagree about the input*: does one accept
what another rejects, or do they read different values out of the same bytes? It
does not test whether any single parser is "buggy", and many observed behaviours
are permitted by RFC 8259, which leaves duplicate names, number range and
precision, and several other cases open to the implementation.

**Prior work.** Parser differentials are an established Language-theoretic
Security (LangSec) topic. They are well documented for JSON in general (for
example, published surveys of JSON interoperability across parsers) and for JWT
and JOSE libraries specifically. This pilot claims no novelty. Its contribution
is limited to a pre-registered, version-pinned measurement that is scoped to the
five registered claims and labels each parser policy-side or verifier-side.

---

## 2. Parsers under test (12)

All versions are exact and locked. Lockfiles: `harness/go/go.mod` + `go.sum`,
`harness/go-opa/go.mod` + `go.sum`, `harness/python/requirements.txt` (hashes),
`harness/node/package-lock.json`, `harness/rust/Cargo.lock`.

### 2.1 Toolchains

| Toolchain | Version | Notes |
|---|---|---|
| Go | go1.26.3 darwin/arm64 | `GOEXPERIMENT` empty, so `encoding/json` is the v1 implementation (`decode.go` is built with `//go:build !goexperiment.jsonv2`) |
| CPython | 3.13.9 (Anaconda build, Clang 20.1.8) | `json` C accelerator present (`json.scanner.c_make_scanner is not None`) |
| Node.js | v24.5.0 | |
| Rust | rustc 1.99.1, cargo 1.99.1 (Homebrew) | edition 2024 |
| OS | macOS 26.6.2, arm64 | Go's float-to-int64 conversion of out-of-range values is platform-specific (see §9) |

### 2.2 Parsers

| ID | Library @ version | Role | API exercised | Justification (source) |
|---|---|---|---|---|
| `go-encjson-struct` | Go `encoding/json` (go1.26.3) | general-purpose | `json.Unmarshal` into a struct with fields tagged `iss`/`sub`/`aud`/`exp`/`iat` (type `json.RawMessage`, each re-decoded into `any`) | The standard Go decoder, and the way Go services usually consume claims (tagged structs). <https://pkg.go.dev/encoding/json> |
| `go-golangjwt` | `github.com/golang-jwt/jwt/v5` v5.3.0 | verifier-side | `jwt.ParseWithClaims(token, jwt.MapClaims{}, key, WithValidMethods(RS256), WithoutClaimsValidation())` | Widely used Go JWT verifier. v5.3.0 is the version in Kubernetes v1.36.5's `go.mod`, line 160 (`// indirect`). <https://github.com/golang-jwt/jwt> |
| `go-gojose` | `gopkg.in/go-jose/go-jose.v2` v2.6.3 | verifier-side | `jwt.ParseSigned` then `tok.Claims(pub, &jwt.Claims{})` (typed claims) | Kubernetes v1.36.5 verifies service-account tokens with this library. Version pinned at **`go.mod` line 83** of kubernetes/kubernetes tag v1.36.5 (commit `ad950d1cc78b0183c476bd4d3f1934c104229727`): <https://github.com/kubernetes/kubernetes/blob/v1.36.5/go.mod#L83>. Use: <https://github.com/kubernetes/kubernetes/blob/v1.36.5/pkg/serviceaccount/jwt.go#L339> (`ParseSigned`) and `#L365` (`tok.Claims(key.PublicKey, public, private)`). |
| `go-opa-json` | Open Policy Agent `github.com/open-policy-agent/opa` v1.21.2 | policy-side | Rego query `x := json.unmarshal(input.raw); is_object(x)` | A policy that decodes raw JSON with the `json.unmarshal` builtin (`v1/topdown/encoding.go`, which calls `util.UnmarshalJSON`). <https://www.openpolicyagent.org/docs/policy-reference/builtins/encoding> |
| `go-opa-jwt` | OPA v1.21.2 | policy-side | Rego query `io.jwt.verify_rs256(input.token, input.cert) == true; [_, x, _] := io.jwt.decode(input.token)` | The common Rego pattern for checking a token and reading its claims inside policy (`v1/topdown/tokens.go`, `extractJSONObject`). <https://www.openpolicyagent.org/docs/policy-reference/builtins/tokens> |
| `py-json` | CPython 3.13.9 `json` | general-purpose | `json.loads(<bytes>)` | Python's standard decoder; PyJWT decodes payloads with it. <https://docs.python.org/3.13/library/json.html> |
| `py-pyjwt` | PyJWT 2.15.1 (cryptography 50.0.2, cffi 2.1.1, pycparser 3.11) | verifier-side | `jwt.decode(token, pub, algorithms=["RS256"], options=…)`; every `verify_*` option except `verify_signature` set to `False`, `require=[]` | Widely used Python JWT verifier. <https://github.com/jpadilla/pyjwt> |
| `node-json` | Node.js v24.5.0 `JSON.parse` | general-purpose | `JSON.parse(buffer.toString('utf8'))` | ECMAScript's built-in decoder; both Node JWT libraries decode payloads with it. <https://tc39.es/ecma262/#sec-json.parse> |
| `node-jose` | `jose` 6.2.12 (npm) | verifier-side | `compactVerify(token, key, {algorithms:['RS256']})` then `decodeJwt(token)` | Widely used JOSE library. `decodeJwt` runs the same strict `TextDecoder` + `JSON.parse` step as `jwtVerify` (`dist/webapi/lib/jwt_claims_set.js` line 56) but skips the time checks that `jwtVerify` cannot turn off. <https://github.com/panva/jose> |
| `node-jsonwebtoken` | `jsonwebtoken` 9.0.3 (npm; jws 4.0.1, jwa 2.0.1) | verifier-side | `jsonwebtoken.verify(token, pem, {algorithms:['RS256'], ignoreExpiration:true, ignoreNotBefore:true})` | Widely used Node JWT verifier. <https://github.com/auth0/node-jsonwebtoken> |
| `rs-serdejson` | `serde_json` 1.0.154 (default features only: no `preserve_order`, no `arbitrary_precision`) | general-purpose | `serde_json::from_slice::<Value>` | The de facto Rust JSON decoder. <https://github.com/serde-rs/json> |
| `rs-jsonwebtoken` | `jsonwebtoken` 11.1.0 (crate; features `use_pem`, `rust_crypto`; rsa 0.9.10) | verifier-side | `decode::<Map<String, Value>>` with `Validation::new(RS256)`, `required_spec_claims = {}`, `validate_exp = validate_nbf = validate_aud = false`, `leeway = 0` | Widely used Rust JWT verifier. <https://github.com/Keats/jsonwebtoken> |

Role counts: policy-side 2, verifier-side 6, general-purpose 4. That gives 66
unordered parser pairs, of which 12 are policy-side × verifier-side.

**Why OPA is in a separate Go module.** OPA v1.21.2 requires golang-jwt v5.3.1.
Go's minimal version selection would therefore lift `go-golangjwt` off the
Kubernetes-matched v5.3.0. Keeping OPA in `harness/go-opa` leaves every
verifier-side version exactly as pinned. The shared encoder `canon.go` is
duplicated byte for byte, and `scripts/check_harness_sync.py` enforces that.

**Common verifier configuration.** Every JWT library verifies the RS256
signature and is restricted to the RS256 algorithm. Every optional claim check
the public API lets us switch off (time, audience, issuer, subject, required
claims) is switched off. The study measures interpretation, not policy. Where a
library still type-checks or decodes claims for its own validation even with
checks off (for example `rs-jsonwebtoken`'s internal `ClaimsForValidation`, or
`go-gojose`'s typed struct), that behaviour is part of what is measured.

---

## 3. Corpus (v1)

### 3.1 Layout

- `corpus/<id>.json`: the payload bytes for one case (137 files).
- `corpus/tokens/<id>.jwt`: the same payload inside a validly signed RS256 JWS (137 files).
- `corpus/MANIFEST.csv`: columns `id, category, description, expected ambiguity`, one row per case.
- `corpus/SHA256SUMS`: SHA-256 of all 275 files above (also reproduced in Appendix A).
- `scripts/build_corpus.py` and `scripts/build_tokens.py` regenerate every file byte for byte. They assemble payloads from literal text and never parse them.

The corpus is **frozen** once this commit is pushed. Any later addition becomes
a new corpus version (v2, …) in a separate directory, labelled and reported
separately. It is never merged into v1 results.

### 3.2 Categories (137 cases)

Baseline payload (`ctl_baseline`):
`{"iss":"https://issuer.example","sub":"user-1","aud":"api.example","exp":4102444800,"iat":1700000000}`.
Wherever a case needs a second, different value it uses:
`iss` `"https://attacker.example"`, `sub` `"admin"`, `aud` `"other-api.example"`, `exp` `9999999999`, `iat` `1`.

| Category | n | Contents |
|---|---|---|
| control | 5 | baseline; reversed member order; only iss+sub; `{}`; all four legal whitespace characters |
| duplicate-key | 11 | for each of the 5 fields: duplicate with a different value last; duplicate with `null` last; plus `iss` three times |
| case-variant | 18 | for each field: upper-case key only; lower then upper; upper then lower; `Iss` only; `ſub` (U+017F) only; `iss` then `iſs` |
| unicode-escape | 19 | for each field: first character `\u`-escaped (alone; and as a later duplicate); fully escaped `iss`; `ISS`; `iss\u0000` and `iss\ud800` as later keys; escaped, lone-surrogate, NUL-containing, escaped-solidus and surrogate-pair *values* |
| number | 36 | for each of `exp` and `iat`: `1e10`, `1.5`, 2^53+1, 2^63, 2^64+1, `-1`, `-0`, `1E9`, `4102444800.0`, `4.1024448e9`, `1e400`, `1e-400`, `4102444800.0000001`, `NaN`, `Infinity`, `0123`, `+1`, `0x10` |
| nested-duplicate | 9 | `aud` arrays with duplicate entries; objects with duplicate members inside `aud`; nested arrays; mixed types; empty array; null element; `aud` twice with array then string |
| syntax | 20 | UTF-8 BOM; UTF-16LE with BOM; UTF-16BE without BOM; trailing `x`; trailing second object; trailing whitespace; trailing NUL; leading NBSP; form feed as whitespace; trailing comma (object, array); line and block comments; single quotes; unquoted key; raw TAB in string; invalid UTF-8 byte; overlong UTF-8 in a key; UTF-8-encoded surrogate; top-level array |
| type-confusion | 19 | `aud` as one-element array / number / object / null / bool; `exp`/`iat` as numeric string; `exp` as non-integer string / bool / null / array / object; `iss` as number / array / object; `sub` as number / null / bool; `iat` null |

The full list, with a description and the expected ambiguity for each case, is
in `corpus/MANIFEST.csv`.

### 3.3 Token construction

Every token is built by `scripts/build_tokens.py` as follows:

1. `header` = exactly the 27 bytes `{"alg":"RS256","typ":"JWT"}`. The header is identical for every case and is not under test.
2. `payload` = the bytes of `corpus/<id>.json`, used unchanged. They are never parsed or re-serialised.
3. `b64url` = RFC 4648 §5 base64url without `=` padding.
4. `signing_input` = `b64url(header) || "." || b64url(payload)` (ASCII).
5. `signature` = RSASSA-PKCS1-v1_5 with SHA-256 over `signing_input`, using `testdata/keys/TEST_ONLY_rs256_private.pem` (Python `cryptography` 50.0.2).
6. File content = `signing_input || "." || b64url(signature) || "\n"`. Harnesses strip surrounding whitespace before use.

RS256 is deterministic, so rerunning the script reproduces the tokens exactly.
I confirmed this by building the corpus and tokens twice and diffing the two
trees. The key pair is a throwaway RSA-2048 key generated with OpenSSL 3.0.18,
committed under `testdata/keys/` and marked **TEST-ONLY** (see
`testdata/keys/README.md`). Because every signature is valid, only payload
parsing is under test.

### 3.4 Which input each parser receives

The "input" in every (input, parser) observation is the payload byte string.
- JSON parsers (`go-encjson-struct`, `go-opa-json`, `py-json`, `node-json`, `rs-serdejson`) receive the raw bytes of `corpus/<id>.json`, delivered in the parser's natural form: Go `[]byte`; OPA a Go `string` holding the same bytes, as `input.raw`; Python `bytes`; Node `Buffer.toString('utf8')`; Rust `&[u8]`.
- JWT libraries receive `corpus/tokens/<id>.jwt`, which carries those bytes as its payload.

---

## 4. Observation rules (per input, per parser)

- **ACCEPT** means the parser's documented call returns without error *and* yields a JSON object (or, for typed decoders, populates the claims struct).
  **REJECT** means any error or exception, including a non-object top-level value.
  The harness records the error text but does not use it for classification.
- For an ACCEPT, the harness records the value of each of `iss`, `sub`, `aud`, `exp`, `iat`: the value the library exposes to the application through the API in §2.2, or **ABSENT** if the library exposes no value for that name.
  - Raw-map parsers (`go-golangjwt`, both OPA entries, `py-*`, `node-*`, `rs-*`) report an exact-name lookup in the decoded object.
  - `go-encjson-struct` reports what Go's struct decoding put in each tagged field (its own key-matching rules apply). A field still `nil` is ABSENT; an explicit `null` is kept as `null`.
  - `go-gojose` reports the typed `jwt.Claims` fields. `Issuer`/`Subject` equal to `""` are ABSENT (the typed struct cannot tell `""` from absent, and no corpus case uses an empty string for these claims). A `nil` `Audience` or `NumericDate` pointer is ABSENT; a non-nil `Audience` is reported as an array of strings; a `NumericDate` as an integer.

### 4.1 Canonical encoding (written by every harness)

Each harness writes one JSON line per (case, parser) to `results/raw/<parser>.jsonl`:
`{"schema":1,"case":…,"parser":…,"outcome":"ACCEPT"|"REJECT","error":…,"fields":{…}|null}`.
Each field value is one of:

| Encoded form | Meaning |
|---|---|
| `{"t":"absent"}` | ABSENT |
| `{"t":"null"}` | JSON null present |
| `{"t":"bool","v":…}` | boolean |
| `{"t":"string","cp":[…]}` | string as a sequence of Unicode code points after decoding. Lone surrogates appear as their code point (0xD800–0xDFFF). A raw byte that is not valid UTF-8 and survives into a Go string appears as −(byte+1). |
| `{"t":"number","kind":"int","v":"<decimal>"}` | exact integer held by the library (Python `int`, Rust `u64`/`i64`, go-jose `NumericDate`) |
| `{"t":"number","kind":"f64","bits":"<16 hex>"}` | IEEE-754 binary64 bit pattern held by the library (Go `float64`, JS number, Python `float`, Rust `f64`) |
| `{"t":"number","kind":"decimal","v":"<text>"}` | arbitrary-precision decimal text held by the library (OPA/Go `json.Number`) |
| `{"t":"array","v":[…]}` / `{"t":"object","v":[[key,value],…]}` | composite values |
| `{"t":"other","v":"…"}` | anything else, compared by its text |

---

## 5. Value equality (fixed before running)

Implemented in `scripts/pdp_common.py` (`norm`, `field_value`). Unit tests on
hand-written synthetic values are in `tests/test_classification.py`.

1. **Types are strict.** Values of different JSON types are never equal: `"123"` ≠ `123`, `true` ≠ `1`, `null` ≠ ABSENT. The only exception is rule 4.
2. **Numbers** compare by their exact mathematical value.
   - `int` → that integer. `decimal` → the exact rational value of the decimal text (so `1E9` = `1000000000`, `4102444800.0` = `4102444800`). `f64` → the exact rational value of that binary double. For example, the double nearest 0.1 is *not* equal to the decimal `0.1`.
   - Hence **`1e9` equals `1000000000`** whenever both libraries hold that value exactly (true for f64, int and decimal). A library that rounds 2^53+1 to 2^53 holds a different value from one that keeps 2^53+1 exactly.
   - `-0` equals `0`. `+Infinity` equals `+Infinity`, and `-Infinity` equals `-Infinity`. All NaNs are equal to each other. Infinity and NaN are never equal to any finite value, including an exact decimal `1e400`.
3. **Strings** are equal iff their decoded code-point sequences are identical (byte-exact after decoding). There is no Unicode normalisation and no case folding, so U+FFFD ≠ a lone surrogate, and `"a\u0000b"` ≠ `"a"`.
4. **`aud`, primary rule (RFC 7519 §4.1.3):** a string `aud` value `s` is treated as the one-element array `[s]`. Arrays compare element by element, in order and by length (`["a","b"]` ≠ `["b","a"]`, `["a","a"]` ≠ `["a"]`). **Sensitivity rule (`strict`):** a string and an array are different values. Both rules are computed. The primary rule decides every pre-registered metric and prediction; the strict rule is reported alongside as a sensitivity analysis.
5. **Objects** are equal iff they have the same set of (key, value) members under these rules. Member order is ignored.
6. Arrays and objects nested inside a field value follow the same rules recursively.

---

## 6. Classification and metrics

Per (input, parser pair), for each of the 66 unordered pairs:
- **AGREE**: both ACCEPT, and all five fields are equal under §5.
- **ACCEPTANCE differential**: exactly one of the two ACCEPTs.
- **VALUE differential**: both ACCEPT and at least one of the five fields differs. The analysis records which fields differ and, for each, whether one side is ABSENT.
- **BOTH-REJECT**: both REJECT.

**Primary metric.** The number of parser pairs, out of 66, that show at least
one VALUE differential on a security-relevant field (`iss`, `sub`, `aud`, `exp`
or `iat`) on at least one input in corpus v1, using the primary `aud` rule.

**Secondary metrics.**
- The same count for ACCEPTANCE differentials (out of 66).
- Both counts under the strict `aud` rule.
- Both counts restricted to each role combination, in particular the 12 policy-side × verifier-side pairs.
- Per category: pairs with at least one VALUE / ACCEPTANCE differential, and class totals.
- Per field: pairs with at least one VALUE differential on that field, and how many of those involve an ABSENT side.
- Per pair: case counts for each class.
- Per parser: acceptance counts by category.

---

## 7. Predictions

These were written before any execution. They are informed only by reading
library documentation and source code. Each one is checked by a function of the
same name in `scripts/check_predictions.py`, from `results/raw/*.jsonl` and
`results/pairs.jsonl`. **All predictions will be reported, including those that
fail.** "Accepting parser" means a parser whose outcome is ACCEPT for that case.

- **P1 (primary).** Between **50 and 63** of the 66 pairs, inclusive, show at least one VALUE differential. Point expectation: about 60.
- **P2.** Between **54 and 64** of the 66 pairs, inclusive, show at least one ACCEPTANCE differential.
- **P3.** Every parser ACCEPTs all 5 control cases, and every pair AGREEs on them.
- **P4.** On `dup_{iss,sub,aud,exp,iat}_diff` and `dup_iss_triple`, every accepting parser reports the *last* occurrence of the duplicated field. No accepting parser is first-wins.
- **P5.** `go-gojose` REJECTs all 11 duplicate-key cases (its JSON fork rejects duplicate names). `rs-jsonwebtoken` REJECTs `dup_{iss,sub,aud,exp}_{diff,null}` and `dup_iss_triple`, and ACCEPTs `dup_iat_diff` and `dup_iat_null`. All other 10 parsers ACCEPT all 11 duplicate-key cases.
- **P6.** The duplicate-key category contains **zero** VALUE differentials. All disagreement there is ACCEPTANCE.
- **P7.** On `case_{f}_upper_only` (each of the 5 fields) and `case_iss_title_only`, `go-encjson-struct` reports the renamed field as present (non-ABSENT), and every other accepting parser reports it ABSENT.
- **P8.** On `case_sub_longs_only` (`ſub`), `go-encjson-struct` reports `sub` present, and every other accepting parser reports it ABSENT.
- **P9.** Every VALUE differential in the case-variant category involves `go-encjson-struct`. No pair without it disagrees on a case-variant input.
- **P10.** On `uesc_{f}_first_char` (each field) and `uesc_iss_all_escaped`, every accepting parser reports the same value it reports on `ctl_baseline`. Also, each parser treats `uesc_{f}_dup_after` exactly as it treats `dup_{f}_diff`: same outcome, and the same field value if it ACCEPTs.
- **P11.** On `num_exp_2p53p1`, `py-json` reports `exp` = 9007199254740993 exactly and `node-json` reports 9007199254740992.
- **P12.** On `num_exp_1_5`, `go-gojose` ACCEPTs and reports `exp` = 1 (truncation to integer), while `py-json` reports 1.5.
- **P13.** On `num_{exp,iat}_{nan,infinity}`, exactly `py-json` and `py-pyjwt` ACCEPT. The other 10 REJECT.
- **P14.** On `syn_bom_utf8`, the accepting set is exactly {`py-json`, `py-pyjwt`, `node-jose`}.
- **P15.** All 12 parsers REJECT `syn_comment_line`, `syn_comment_block_inside`, `syn_trailing_comma_object`, `syn_trailing_comma_array`, `syn_single_quotes` and `syn_unquoted_key`.
- **P16.** All 12 parsers REJECT `syn_trailing_garbage`, `syn_trailing_object` and `syn_trailing_nul`.
- **P17.** On `type_exp_string` and `type_iss_number`, `go-gojose` REJECTs and `py-json` ACCEPTs.
- **P18.** At least **10 of the 12** policy-side × verifier-side pairs show at least one VALUE differential.
- **P19.** The number of pairs with a VALUE differential on `exp` is at least the number for each of `iss`, `sub` and `aud`, and the same holds for `iat`.
- **P20.** On `num_exp_overflow` (`1e400`), `go-opa-json` and `py-json` both ACCEPT and report different `exp` values: an exact decimal versus +Infinity.
- **P21.** On `syn_raw_surrogate_utf8`, `py-json` and `go-golangjwt` both ACCEPT and report different `sub` values.
- **P22.** The pairs with **no** VALUE differential are exactly these six: `py-json`–`py-pyjwt`, `go-opa-json`–`go-opa-jwt`, `rs-serdejson`–`rs-jsonwebtoken`, `node-json`–`node-jose`, `node-json`–`node-jsonwebtoken`, `node-jose`–`node-jsonwebtoken`.

---

## 8. Analysis plan (scripts that produce every number)

Every reported number is produced by these scripts from the raw files. No
number is edited by hand.

| Step | Script | Input → output |
|---|---|---|
| 0 | `scripts/build_corpus.py`, `scripts/build_tokens.py`, `scripts/hash_corpus.py` | (phase 1 only) → `corpus/` and `corpus/SHA256SUMS` |
| 1 | `scripts/run_all.sh` | checks `corpus/SHA256SUMS` and the `canon.go` sync; builds each harness from its lockfile; runs each of the 12 parsers **once** over all 137 cases → `results/raw/<parser>.jsonl` (12 × 137 = 1,644 records) plus `results/raw/ENVIRONMENT.txt`. Refuses to run if `results/raw/` already holds data. |
| 2 | `scripts/classify.py` | `results/raw/*.jsonl` → `results/pairs.jsonl` (137 × 66 = 9,042 lines; primary and strict `aud` classes). Fails if any (case, parser) record is missing, duplicated or malformed. |
| 3 | `scripts/summarize.py` | raw + pairs → `results/summary/{metrics,per_category,per_field,per_pair,per_parser_acceptance}.csv` and `SUMMARY.md` |
| 4 | `scripts/check_predictions.py` | raw + pairs → `results/summary/predictions.csv` and `PREDICTIONS.md` (HOLDS / FAILS with evidence, for P1–P22) |

Harness entry points: `harness/go/` (`go-encjson-struct`, `go-golangjwt`,
`go-gojose`), `harness/go-opa/` (`go-opa-json`, `go-opa-jwt`),
`harness/python/harness.py` (`py-json`, `py-pyjwt`), `harness/node/harness.mjs`
(`node-json`, `node-jose`, `node-jsonwebtoken`), `harness/rust/`
(`rs-serdejson`, `rs-jsonwebtoken`).

**Phase 1 verification (no execution against the corpus).** Every harness
compiles or passes a syntax check:
- `go build` and `go vet` in both Go modules
- `cargo build --release --locked`
- `node --check harness.mjs`
- `python -m py_compile harness.py`

No harness binary has been executed. The only code run in phase 1 was:
the corpus/token/hash builders (they write bytes and never parse them);
`openssl` for key generation; the dependency installers; and the unit tests in
`tests/`, which use synthetic values only.

**Deviations.** If phase 2 exposes a harness defect (a crash, or a record that
contradicts the API documented in §2.2), the fix goes in a new commit and is
listed in a "Deviations" section of the results, with the original raw output
kept alongside. The predictions, equality rules and metrics in this document are
not changed after the push.

---

## 9. Ethics and disclosure

- Only the parsers themselves are tested, each in isolation, on local inputs. No deployed service, cloud account or third-party system is contacted. The keys are test-only.
- `docs/DISCLOSURE_NOTES.md` is git-ignored from the first commit (checked with `git check-ignore` before committing). It holds private notes and never reaches the public repository.
- Public outputs report headline results as aggregate counts. Per-library tables describe the observed parsing behaviour of a specific library version, which is what reproducibility requires. They do not call any library or third-party product vulnerable, and they do not connect any behaviour to a specific deployed product.
- If a disagreement looks exploitable in a specific real product, it is recorded only in `docs/DISCLOSURE_NOTES.md`, and work stops for the project owner's decision before anything else is done or published.

---

## 10. Limitations (draft)

1. **Isolated parsers, not deployed configurations.** Each library is called with one API and one configuration (§2.2), with claim validation off. A real deployment chains specific components with their own options, validation and pre-processing (gateways, sidecars, admission webhooks). Whether a differential can be reached in such a chain is not measured.
2. **Hand-built corpus, not exhaustive.** 137 cases chosen by hand across 8 categories. Counts depend on which cases were included; absence of a differential means only that none was found on these inputs. No fuzzing or grammar-based generation.
3. **Version- and platform-specific.** Results hold for the exact versions, toolchains and OS/architecture in §2. In particular, Go's conversion of an out-of-range float to `int64` (used by go-jose's `NumericDate`) is implementation-specific, so results for 2^63 and 2^64+1 on darwin/arm64 may differ on other architectures.
4. **Pair counts are not exploitability.** A VALUE or ACCEPTANCE differential shows that two components can disagree. It does not show that any real system is vulnerable. Pairs are not weighted by how often the two components are actually deployed together, and many pairs never are.
5. **Harness choices shape the result.** The extraction rules (typed vs raw claims, how bytes are delivered, ABSENT for go-jose empty strings) are judgement calls, fixed here in advance. Other reasonable choices could give different counts.
6. **Policy side is narrow.** Both policy-side entries are OPA, and they share one JSON decoding path (`io.jwt.decode` calls the `json.unmarshal` implementation). Other policy engines are not represented.
7. **Exact-value equality is strict.** Rule §5.2 counts numerically tiny differences (for example a decimal versus its nearest double) as VALUE differentials, whatever their practical effect. Per-field and per-case breakdowns are reported so this can be judged.

---

## 11. Amendments before data collection (2026-10-17)

This section was added after the pre-registration commit
`3499fcb9219f502defd964b7c854625f9a713599` was pushed (2026-10-17T08:57:22Z; see
`docs/TIMING_EVIDENCE.md`). Data collection has not started. It changes no
prediction, classification or equality rule, metric, parser pin or corpus file.

**(a) Prediction provenance.** **P5** and **P6** were revised after reading the
README and source of go-jose v2.6.3's JSON fork (`gopkg.in/go-jose/go-jose.v2/json`).
That source shows two things. The fork rejects any object containing duplicate
member names. It also matches member names case-sensitively, unlike Go's
`encoding/json`.
- *P5, earlier draft:* only `rs-jsonwebtoken` rejects some duplicate-key cases, and every other parser, including `go-gojose`, accepts all of them.
  *As registered:* `go-gojose` rejects all 11 duplicate-key cases, and `rs-jsonwebtoken`'s pattern is as stated in §7.
- *P6, earlier draft:* on `dup_iss_null` and `dup_sub_null`, `go-gojose` keeps the first non-null value while raw-map parsers report `null`, giving a VALUE differential.
  *As registered:* the duplicate-key category contains zero VALUE differentials.

Both revisions were made before the pre-registration commit and before any
harness was run on the corpus. No harness had been run on any input at all.
The case-sensitive matching finding left **P9** unchanged, because it already
assumed that `go-gojose` matches case-sensitively. The source reading confirmed
that assumption rather than changing it. No other prediction was edited after
it was first written into `scripts/check_predictions.py` or this document.

**(b) Wording rule for all public outputs.** Results describe how each parser
handles each input. No output states or implies that any product, deployment,
or combination of these libraries is vulnerable or affected. Tables of
policy-side × verifier-side pairs describe disagreement between parsers, not
between deployed systems.

---

## Appendix A. SHA-256 of every corpus file and MANIFEST.csv

`MANIFEST.csv`: `eff3dd2c6779579d95f28464974c24f4cae67bd8d0768571471a110399cda4fe`

`corpus/SHA256SUMS` (the list below as one file): `11ea1ce31135e20ff31119a8f1c74dde10d8f3a09c5fd6254521a954e71247c9`

```
eff3dd2c6779579d95f28464974c24f4cae67bd8d0768571471a110399cda4fe  corpus/MANIFEST.csv
9a45921815c314569dddc7b90602cc3275bcb47f264af59b3bc46d310a22821e  corpus/case_aud_lower_then_upper.json
e071b523b7f355ea03b20ec5206fe0ab19707ede2dfae41821d8e002c79b079f  corpus/case_aud_upper_only.json
6fdb70925c56d3b35392fb660957e237fc341087930728ea75f01778e37daf15  corpus/case_aud_upper_then_lower.json
122c042d4cde2864bfd3bea3812fe080d1e2ada823aa66bfaf3f1bfb8766af86  corpus/case_exp_lower_then_upper.json
eee4c239dd06ea60057ab3abba2184b5c3fa5304c15a4cbcffe2a09f253adcec  corpus/case_exp_upper_only.json
1faa7d2e1950bde0b7871064434340e00bc728c981f29335d9fd8cc66a3b5170  corpus/case_exp_upper_then_lower.json
af49bf013cd3f1a870882bc017eb210e0d54ef230500861042f48946c33acd7d  corpus/case_iat_lower_then_upper.json
5ecda4ad5039d2db139245c4c742cab1a51d3f739618fde8136de76cdb2142ec  corpus/case_iat_upper_only.json
42589cadb078cb18296daf573a2f52a7e010d02e8c0ec4a7db2ea32961e14b42  corpus/case_iat_upper_then_lower.json
115494a939757955dd224bceb8c9c53be48db392dbe25c63c6f3ef67e9d984d6  corpus/case_iss_longs_after.json
7fda34df08aae77a3e609adca9e2eeed5c4285d21ef8b4c03ca4fe5825e60077  corpus/case_iss_lower_then_upper.json
46177ca3c931d2788a98b5e979a479e5115f44c36b45db625184eef7a0075813  corpus/case_iss_title_only.json
45def5152a30e6b3a8b7d7ca331ced32c512164ee7aafe9dbeb92440b1e66b94  corpus/case_iss_upper_only.json
cc3a58cdb17def6320be24f682e3053fa081730b01257bfb12df6c5e975cdd98  corpus/case_iss_upper_then_lower.json
5ea6f2cce4834a7e9c54296d9ab60430ac524a58ace1039116fb122500a51cf3  corpus/case_sub_longs_only.json
0b644ed4414a00e68162501beecbe148c814588cb19d1ab30153abb0be62a5da  corpus/case_sub_lower_then_upper.json
e2aa8c6aca42d36c4412e30a8e02eeaf2b5663b25ba1f02e736d9516b6769026  corpus/case_sub_upper_only.json
bca0e913073286561a489a1872e8dbf8ba00ae5b941b1e259d71c37ce0443815  corpus/case_sub_upper_then_lower.json
afcae8039118707d0a94449d8a190e5e2e0d445691d791a4d5a58bd90da0d44c  corpus/ctl_baseline.json
44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a  corpus/ctl_empty_object.json
d104ffdaa69cb4f249ca92abc33a7682cab47740e5e09588ce676d8d5c68d1c3  corpus/ctl_minimal_iss_sub.json
068bd104ecb04dca085d9fd496a284e272b9dc5cbb8c889d67160b064b9bf5ba  corpus/ctl_reordered.json
77ded16272ee020103c73a7b8a399d0ed7ad09203fdd565b6330743999500c15  corpus/ctl_whitespace.json
b1c85a7b32e82ce5ea7c7bc8da0a61b8863a079b54920916ca91af9965497243  corpus/dup_aud_diff.json
823773c2c63b62fa381c0c3ddc7f11e5fb411f837f87993ca169711362995147  corpus/dup_aud_null.json
bb52fcb44b858ced029e23fca2af5b8819f1d78b730ad9ea2d0ea689d997edae  corpus/dup_exp_diff.json
55bcdd9c5fe410595fd1240ee44fb541c0b552f65148c099a8cf5acffcecc2c7  corpus/dup_exp_null.json
039775e51198b724106e1ca34bb1bd927db81bd857f66001932cb691d6afbed8  corpus/dup_iat_diff.json
a74056911d29ded53151f25a4d5b7dcf535de2821c2947cbb267f6d531d5fc39  corpus/dup_iat_null.json
469a72e31b8230b6af414bf278eec8902662f2beba46b08af51f2e2a31718690  corpus/dup_iss_diff.json
0cc9266a91fa9173f36ed2f5890af967ef0b3fdd9010f64b63c004a24295cbc5  corpus/dup_iss_null.json
554c541da86ae4e490481a4f1379d4c73aa3eae76cfd3cef6f807bc32ffcb9aa  corpus/dup_iss_triple.json
d5e8e8d7e5e521e7c1076d6bc28b7581f7b64b3947e5d74013eea84a96c3146f  corpus/dup_sub_diff.json
35710d7b69833fe422d7a47c98b80cedff528d1b945b19252a8f3d7a155e6419  corpus/dup_sub_null.json
35f5bcfe5739cf6d496ae653a9501cfb61c0125c7436ea15568ab076fe9376d0  corpus/nest_aud_array_dup_entries.json
2696a68712a51d885549a89f66f2e78fd2994c7e302ce37aa03b0ca8519f8a58  corpus/nest_aud_array_mixed_types.json
e6d3d0e5497ed2eebbe08a4ebfd34ddf9bfe13a3f44002399c00ee7a777a33ff  corpus/nest_aud_array_obj_dup.json
b78cdc02cac6da519b380365da40fd3fb154f3ab329c48033fb68788d880758c  corpus/nest_aud_array_two.json
4fb00ba52051a777bf2dd2e39b382419b67cf616282521efef773befd06cf513  corpus/nest_aud_array_with_null.json
e6229d25670d751b75d67aa7ae476760ec5d0c9af5f86697a6a46e258e6e0651  corpus/nest_aud_dup_array_then_string.json
86156e0dfece4c470137ecb00a1d8847e8b04e67360dbf10f74d248b5db4e732  corpus/nest_aud_empty_array.json
4d97c2e7c8b762a27cf17dfbdfa78cd5ec7841852717977149cf5f2277a0d760  corpus/nest_aud_nested_array.json
b1d3ce7078ab5cf2769ddebacbf1ba8c042c36d825c98c118100ce1ac1a7de9b  corpus/nest_aud_object_dup_keys.json
be1289f1783cc3d58af5d582df060d51615dba4595aea4ad594d21b9793fefa7  corpus/num_exp_1_5.json
1516ff23e11e8dad20aea1111b9e8053ec024bd0930f85cf499d992dc4534e45  corpus/num_exp_1e10.json
94168f93d1c190458ab119d3431facf037ff208ec19687968f46082bdfa0172c  corpus/num_exp_2p53p1.json
d212a63e3aa0ac5a63202f14ec340bd1239fea25ad732113710010cd6e826c2e  corpus/num_exp_2p63.json
315d12474fa3013ce62b0f9ee77c98570b50f313255b92fc10cc4f5754874ffb  corpus/num_exp_2p64p1.json
2eae05893764123e1f2f1bafed2c229b91ebc91981f49fbdc62747d727793155  corpus/num_exp_exp_form.json
3b4c3a28131d8dca8a820ba0f01c5a80efeae4e9d8d6731dbfdeee330a6b4f90  corpus/num_exp_exp_upper.json
5bafe9030a33ce4679541ec12044cd567b08ec349c0acca8600e96bb6af46cae  corpus/num_exp_float_int.json
0e2489495e481ca40435a28e7e7a377c31a2ff5c617040bfdc73aaa9382cb6ed  corpus/num_exp_hex.json
a10113251918264f0afdbb05987b8647a97ec0274a4d421ac2aae08b9ad54f06  corpus/num_exp_infinity.json
d031578f851aaee99004d2ee9293970abf5d9d022f1a354dc5e1dc9b97e6774a  corpus/num_exp_leading_zero.json
c6db46c1a2b89c5f1193654995fbc9dc1be6955991023d435da4a0382dfe46a4  corpus/num_exp_nan.json
fd14be4c2049e9525861b11fa7ce505c1e2dd375263ca9c30dafd4351bd74add  corpus/num_exp_neg1.json
bf323b4bfe5883739723ca1e1406a6cb9d1d536cfaf85bc021e3afa5ed32a73f  corpus/num_exp_negzero.json
8fa8c413232d1a330648f5b8a7bf4b165f04b81b8c1e5a6f7ba0a4e57b3af8fd  corpus/num_exp_overflow.json
0ea88282cdc0afdbf4bf6afd99c09ff709a85dc03822161f3c914baa034630ca  corpus/num_exp_plus.json
a6af0c165b9821d49f8731e04f576f9d05826194c0ed76f54c6774f58aa3bad4  corpus/num_exp_precision.json
35903513f12b4f6a59cf4f09e8c7649ed3f2dd3c0c491e1e8b8f81c26ce3678d  corpus/num_exp_underflow.json
884e365f0745aa5ff872cdcaac3cc1971b9dbf1ddd3d9105d9587d8160894780  corpus/num_iat_1_5.json
c58adfd7e7ef69d0b80d11079f3091dc37d949be4bcd47cebc5cea79defa3318  corpus/num_iat_1e10.json
ed3e81499f722b328be23d3e75380c24e7afe761f3614ad246510d596850536a  corpus/num_iat_2p53p1.json
372d99031fd9c3796847c8d4e0a1283b1c3d62287b45b331c2ec45d3b03b4849  corpus/num_iat_2p63.json
4bdc3890fb112190c9f5dc0f181242ee882d1ff4d747fd21356e4e2879e70841  corpus/num_iat_2p64p1.json
3589a4f7cb2c5499d588ccb23699a2a4e86121bbbd2c28423543abcf994ab7dc  corpus/num_iat_exp_form.json
b2591ea16fe9c33c6df78417eaa81fd46ce8931b5806d68e9bcf0ce55272f3df  corpus/num_iat_exp_upper.json
aa722ecbc7f30b0589a7230483f94cc23ccb869c2bb9a936362517bd4d19c574  corpus/num_iat_float_int.json
3cb54bdda7f9b205d453d92e3d365ef6e9efa2e2c5f6a5ebf59bfcdbda3a99b1  corpus/num_iat_hex.json
a10f4ed4a23755d3a6141962400a13f4242822b1b7535b75691a01d822271a71  corpus/num_iat_infinity.json
0ebc3c7cb7dba23a2bda360efc5ddc3cde8485b6b0f894fc48712c775042d172  corpus/num_iat_leading_zero.json
a8e1d8c6e6013856474e3e78764df6a90db8c8c176c434338d6368d8ba8d5fb7  corpus/num_iat_nan.json
5525c61ea4261582edc31895f60ef9c73a5accb704a71f5235870f384c47b8de  corpus/num_iat_neg1.json
2ceeb872e61b195e356e0462084c0b033ea5a3575fc4c79ed44336845eebd209  corpus/num_iat_negzero.json
b79f416e54e6d68fb2359b8dbcfff755da0913cd3fc776c72fbc1e7859e5c951  corpus/num_iat_overflow.json
dcc9b10a3a3b864231b76d2417aa12f7906ae21b8c963976c7a0136923d7e858  corpus/num_iat_plus.json
15f0b0ff908780ca04ad55ad228fd9abc900858a433fe77195498e4059412784  corpus/num_iat_precision.json
cf36087679e38a82beb1ab519d42df76f4fccc9a35009bce3a44776aa08dcc58  corpus/num_iat_underflow.json
fa84113a3a4a31a01cce59f80b8f440d40b86a572cddd5076ae0eca6443d575f  corpus/syn_bom_utf8.json
fa092965de889a201ca624dc798d7a6c2cab3db2823f925895d50012971ae4b8  corpus/syn_comment_block_inside.json
bc8f39a116f8ba9bc61aedf7920f1080272fb98a420bf54d9860e900b714a3ee  corpus/syn_comment_line.json
a17a6dc91d0a746668b790e0ff9da7e352e4ceec7b79324ce40a47401ae4fe8b  corpus/syn_formfeed_ws.json
5708fc1b1df0ca5c14bd1882317647e8d63cc841a542203d16ff7c749ea093b9  corpus/syn_invalid_utf8_in_value.json
9c55b11926768d1ec4bda72f1b41b4de08bfedf97236230a27ea53a9cdef1aa2  corpus/syn_leading_nbsp.json
d614dbc5eddc90b4dfc39c977715a19e6339883973b58141f0d4a390f8523d10  corpus/syn_overlong_utf8_key_after.json
eeff40c468a02ce0db68f2bb03e6f5fa19059f9c77aa2095cb17a2bf43466057  corpus/syn_raw_control_char_in_string.json
df1ebfd3890f8890bc1986012737c023ca3cd06f71191e65baedaa7d59ac660b  corpus/syn_raw_surrogate_utf8.json
c06635b438a4ed60e4dfa4aa9d19e228427307350f58ff50764c6e1ff220ccc0  corpus/syn_single_quotes.json
a3754ce97ff7006dfc05a78e8edf0cf4c014466e899e63dd2bb1552fdd1b37d3  corpus/syn_top_level_array.json
da8bd61736487f9b1bbcfe6e28e9a2b20bbba315616e45ba00f6cfb263a8a52b  corpus/syn_trailing_comma_array.json
0bb854ad1f5e918ea05a22df8e5e569f475503c8a0f2e55f99617fd2c540608f  corpus/syn_trailing_comma_object.json
1200db9119442b3a7b0bf75ec1198ee99ba0354d25a6713f85ad0e6c3494bf9d  corpus/syn_trailing_garbage.json
763a72e9ac383d102079ab3c33d33e79d7680a3a50c6092db41e2db19c378770  corpus/syn_trailing_nul.json
c4c3b16e620765047b72cfe60fee4056a92e152d92907f46f6dc6b445f2916eb  corpus/syn_trailing_object.json
912c02176f443ec2a8b4dd66533e8a1de1322601d315c86c9f6d42d0dd58bef0  corpus/syn_trailing_whitespace.json
9d2e3cfc42c3ee13d5cac046125e34c3bb6641fa4fe6d39e9067144317b96f26  corpus/syn_unquoted_key.json
a9dd6dc3fd93202dab9ded6dfc9a220cedd4373330e2fe48c0d21bce93de96be  corpus/syn_utf16be_nobom.json
94b081855738dac3260e8e65447dc2ab525ada06b775aa9630780df29610710c  corpus/syn_utf16le_bom.json
a152e3eb41409fbf39d113e46cd8b5cb79dd09708a2902ab504778930629f514  corpus/tokens/case_aud_lower_then_upper.jwt
03433e379233a1041695c40e2cbe5480252ed93a4d6a8678f7417533e3741377  corpus/tokens/case_aud_upper_only.jwt
239ca9ad03c22ad802398c84b11a32a37c129908a042d1a0728d5a0825bb1cff  corpus/tokens/case_aud_upper_then_lower.jwt
e69dac862653ec9aa70f159cf9304242c845fb0075253d2a8dbfb06af7e7114e  corpus/tokens/case_exp_lower_then_upper.jwt
197d86b936e6ca2db27a1ce2172e2476b2882e7d1f3c5ec5aaffb9234abf5c68  corpus/tokens/case_exp_upper_only.jwt
a55b5ce3da13ffc4a9bdb1a5cc46c90ce4edf0c34e708dd1ca8c2e5a275e3cb5  corpus/tokens/case_exp_upper_then_lower.jwt
bd66bb822ffbbb17a084246711096272b92416336261346df4a07fd8a445640a  corpus/tokens/case_iat_lower_then_upper.jwt
7b381734dd22164c3522fe1d05e57a589a041900455a8bf144a893e548eee1a3  corpus/tokens/case_iat_upper_only.jwt
1aefda878b7969079164ec9340cdf850e6964ff5452e10217435596f8a69d588  corpus/tokens/case_iat_upper_then_lower.jwt
f584c2f05e0c00aafba23caef8e21c8c2a9afd8e89faf71d5c9c5971b5441018  corpus/tokens/case_iss_longs_after.jwt
5031f7b69932db9ae95a9e49343bd8ba1fe4297117359f941cdaed41edc5e1f1  corpus/tokens/case_iss_lower_then_upper.jwt
b76f389e242e1890c67f48fbadf725dd3c8e1df8f187a6dc575c0e49cc4bf143  corpus/tokens/case_iss_title_only.jwt
0eecfeaba706bddeacc091a6a87b57b3e67d0544178f9f31938a11ff283529b1  corpus/tokens/case_iss_upper_only.jwt
5fc3b6ecad204189b8c726a3c81cee14a6a9db5ba81fd10c63c6f599fb2e9509  corpus/tokens/case_iss_upper_then_lower.jwt
375ea4fece5857e774c152c1af56c38321ca20f0c1c0a2b42663d231f479ecb7  corpus/tokens/case_sub_longs_only.jwt
91d743a2ae776d2099009fcc7f0f6685affd5ae4cf6c5397e7faef3263831e03  corpus/tokens/case_sub_lower_then_upper.jwt
c0df2ab0d5130676429c0a81123496e76b3a9af23f7e97c50bbdf102ebb38d26  corpus/tokens/case_sub_upper_only.jwt
178017ae64115c8959c63ceed9b2daeca0e2357d21392faa40dbc382348b7c2b  corpus/tokens/case_sub_upper_then_lower.jwt
b8b640b4f29d0ade9656fdeba96d8a92fec443582c0e770da9418453fe44b59a  corpus/tokens/ctl_baseline.jwt
2de4a17ef61bedb5b088d15c6803fbe630b276d22cba9c62efd5d227260912df  corpus/tokens/ctl_empty_object.jwt
374118a93c9273c2df8c8ad4fd178e24a64bf56fb9976ae46be48bd6a2f9cb5e  corpus/tokens/ctl_minimal_iss_sub.jwt
edb2b752b4cea8459753e2699742cc8a3feb159797bfcab20e5da1fd744f3919  corpus/tokens/ctl_reordered.jwt
14a086a15f76fd1a133f9b482936fbd01c22e1af0cad3ccaa7b40d6a22f3a501  corpus/tokens/ctl_whitespace.jwt
087a548d794898f9faa03d807d9e199bdc27f508d2bfdc03d3f6a293955a9c7e  corpus/tokens/dup_aud_diff.jwt
1dedde675ad5b7bf4107311f4141a4b330ac2899f84dbdfc09e5e17c4506d956  corpus/tokens/dup_aud_null.jwt
bf0b222e0b06cebf970e4219a6062eddfef11ddaa3d461bb9cb225f8822b09e5  corpus/tokens/dup_exp_diff.jwt
35c0f413cb9a220f48b731a538b1ea2aaa42b20a40fb05e7a8bfa6210a0131c4  corpus/tokens/dup_exp_null.jwt
b57ac66a6071f76fbd8cedf1b720052aa8c6b5b05af05269f2a8304f77c50643  corpus/tokens/dup_iat_diff.jwt
270672489d6109c88bccbf4f57cb6dd0d3ebfd6395aa145fcd43116e68fca3d3  corpus/tokens/dup_iat_null.jwt
ac16b741adc76b531deaf0f3a81664af163e399e46ea78b64016ef92e25a9abf  corpus/tokens/dup_iss_diff.jwt
a03b5f826c3b4ea2881c889314b32789eda96b1d3feb4dd631291244c9a05995  corpus/tokens/dup_iss_null.jwt
a2eee01e2f65598f2a8864a27ae768ce29ef063f9b4b2e49f4613dffccd6edad  corpus/tokens/dup_iss_triple.jwt
658b10f648c2fe01337ec01357c29481970f05bf1083ef4ec2d08e263a8d1d28  corpus/tokens/dup_sub_diff.jwt
4201867bfbbcac13aec1b3bc1a9bf4dadcc60fb0d9db4dc88d5fe6c86f015603  corpus/tokens/dup_sub_null.jwt
5fe399e8a6b820ff9c6b2dbc98577dd01232bd70f4329ce4c30b514ed9883922  corpus/tokens/nest_aud_array_dup_entries.jwt
5f8bb8607b9630491af04de23c70548d37935475546da5a6fd9e60c40907a9db  corpus/tokens/nest_aud_array_mixed_types.jwt
83908a5ad2d027ac063cab58d4c590e6dec357bef3c1cae2fb7a0a4beca2c4bd  corpus/tokens/nest_aud_array_obj_dup.jwt
9637f20f7e5b092e991e5863190cf458b4ed191ca3d0ac78cbd4123caaa98e54  corpus/tokens/nest_aud_array_two.jwt
9bb139f4c4541e17c63409231e68d31c6470844a3fe2507e9b94cb759245cb93  corpus/tokens/nest_aud_array_with_null.jwt
77a86435deb6fde8b0a5ce3051189b2e199e9dac9bf528122a8cb831800b986f  corpus/tokens/nest_aud_dup_array_then_string.jwt
b62a4fa709fc6a436c8422f79945b2d22cafdea8efd65e105af4d1e6194b71d2  corpus/tokens/nest_aud_empty_array.jwt
83b4bd300cbaca220abfb8787400b7bcbdb8d4396084b824a1e09759503551a6  corpus/tokens/nest_aud_nested_array.jwt
b1163f7f0d80ba954d358e3ca392bb9bf1fc16c4c046348f26956b8ba74d8b52  corpus/tokens/nest_aud_object_dup_keys.jwt
c9c996f74ecaa2881f4a8ab1c077100f3aa44fb9d2b4a28e530587320dd01fb5  corpus/tokens/num_exp_1_5.jwt
399e097c12829896014cd8317e9167af44bebf15c5ebab2011ee53813785b681  corpus/tokens/num_exp_1e10.jwt
d19546fd38f098605179b493d3d5daf6280c77433e60a778e3e7834ea8d30adc  corpus/tokens/num_exp_2p53p1.jwt
9907d29cd38520b414a8b49f2f967a75c56eeca1cdf7a54beace42d8b220ad79  corpus/tokens/num_exp_2p63.jwt
f453ce3bd8a7d03f4fc7d9db5be8ed7e9692c9bba0cfd54997bf868aff5f48d7  corpus/tokens/num_exp_2p64p1.jwt
f8d72f14b3455571d83d183e0db9ad24b0b06a1ae4cc5e98d4314b4fd8f649f8  corpus/tokens/num_exp_exp_form.jwt
2a0a25478e9fc57e0704b3dc69d46170d2669b85109b49577858297d3167b318  corpus/tokens/num_exp_exp_upper.jwt
aa96b52c2e6e7794f725602c86e9af192bbfa28de65ce1b1bb8309619a148e08  corpus/tokens/num_exp_float_int.jwt
db73a1190df70a4b50f17bd8e8be3750fdeb76dd8baa143169c14b909810ff9a  corpus/tokens/num_exp_hex.jwt
05cbebe11164396072a1b0a6334b75c4a0297ee7755fef9a01af190225f46d47  corpus/tokens/num_exp_infinity.jwt
1460b2e9899adbef30211530b75aee96aaaba04a96d376e4b2eb9a87412c3990  corpus/tokens/num_exp_leading_zero.jwt
1af4186917df6fa0179ef1bb2c909caf74184e407801a831335c640a108eb72c  corpus/tokens/num_exp_nan.jwt
5e5a4377ba7668898619b4d2e8c742c8a8ee879454cdf018d14becaee61bb78d  corpus/tokens/num_exp_neg1.jwt
fab6da9e3233926afe1dcb66f0b1097e4bec868cf6bba0761012f04fe41daf00  corpus/tokens/num_exp_negzero.jwt
9355aba1e065ca5d16dcd81e0a2e18e798a53cdc5ee8d6b42d9b35815eaa6d63  corpus/tokens/num_exp_overflow.jwt
a7dc4ba06c51d7edbc6c9b6a805a5f1984d95b882e5943a9ace5a2f5ade05c8b  corpus/tokens/num_exp_plus.jwt
00cfdb87a7993eee53f5dd830eb85d70921ed94d003eb439630b56d1698bfd17  corpus/tokens/num_exp_precision.jwt
befdd3a93afe228dd070d33c572b4cf91329590e208f0e154c5ea7dd4995c3eb  corpus/tokens/num_exp_underflow.jwt
f3a90e8c0ef591e9418275e1eff12178acf08a7809d9ca847051a9a0ee0e3580  corpus/tokens/num_iat_1_5.jwt
e842840b33f1d70578d75e58884ada7390b0d7fafc9e1aefc62a27a26383b7d8  corpus/tokens/num_iat_1e10.jwt
d7289ab18f438ad15c3d23bed1f5441da715b3bee738ce25517f2ac73eb4d34e  corpus/tokens/num_iat_2p53p1.jwt
c105679f881ec44ea28fb660fc8d90ba2da45423d39a8d851172d6b8a3a172b1  corpus/tokens/num_iat_2p63.jwt
0bab92ee02ef836b2a52269ce9f1ff11df1332748d08991e14d331902ef57459  corpus/tokens/num_iat_2p64p1.jwt
8333c4507e01eb313140143d932e9f98e2d68056f697d9053731f243626faf61  corpus/tokens/num_iat_exp_form.jwt
2298ad5b713acccc44a4817304ade76b12e28cc4fc7cbea54f187902c7b08d69  corpus/tokens/num_iat_exp_upper.jwt
176e3727038ac4b0ae2185c2482f9a410322a82ede75527a3c2d634dee537fe7  corpus/tokens/num_iat_float_int.jwt
ac1c3b7eca313b71c2fd0e77df419e4006fc9f86b4fce84ce1873b0e9e1f53b1  corpus/tokens/num_iat_hex.jwt
0774da3556dea7c5468914dc6e29b54519a393b78deb41f97078d9b5dec7b80e  corpus/tokens/num_iat_infinity.jwt
ec662f5a717121a1eb629bc46303bab75b822968af3482fffc3357705f22b967  corpus/tokens/num_iat_leading_zero.jwt
ee17e8929f5e93e3a7c1061d31a5611ee13d3068af641f72109626b8dad50c6a  corpus/tokens/num_iat_nan.jwt
ec1ee2fe5d723cd3b1fd3a25823807fbe3861d2cbeb763ff5377a918275e4cd3  corpus/tokens/num_iat_neg1.jwt
89be526dfa38a5c14a9827bf221b5d9057e9ce09f30ff13a313fc6623edf4384  corpus/tokens/num_iat_negzero.jwt
f1bc29d8691a893c0e6f7a1e80e8d0d7fe26047ad55cb588d1c000602fa8e8f4  corpus/tokens/num_iat_overflow.jwt
a033cfb75b7f0bdf6966f3d6ea8e5ce6f78bc606ef93c8a705b79a798d85bf3d  corpus/tokens/num_iat_plus.jwt
f51e47212c3f3660e13285c4fa92a6756fcb44d9658b827641e5333e69f01689  corpus/tokens/num_iat_precision.jwt
ca9da993f8ce60d231ba0057e7010737c0ebe9b56289a3433fb069f2f4135ef6  corpus/tokens/num_iat_underflow.jwt
b7eff5910cf6391af4917a0f07eca72cc79662e152e20888a1ac12438fad53d2  corpus/tokens/syn_bom_utf8.jwt
18fbae4170b12ee0ff673f3c993b94bc2abdeb6130d216ab84b605a28ddaf676  corpus/tokens/syn_comment_block_inside.jwt
a0b557830c7d4fbd369d1b19e46b1f41d551c57f9ac5ff0a0605d7759da50b13  corpus/tokens/syn_comment_line.jwt
03acb74f778c2c8621b8a251b2ed95a693ce3bf4891125d2abd8e2b6874f139c  corpus/tokens/syn_formfeed_ws.jwt
2393400d312cc35701eaf19bd8957d9b1265eba7b1ef1bf1fa8c6d1532e7dcff  corpus/tokens/syn_invalid_utf8_in_value.jwt
3065fd74052925556484082b36a993822ab530192827058f23e55fd0c500cffb  corpus/tokens/syn_leading_nbsp.jwt
d586af302d89207b8b19b87780838bbf742cb8d4be25009bbfd3cd0f18d5a901  corpus/tokens/syn_overlong_utf8_key_after.jwt
102700419de2a36868aca88ab3dfd3df084d1438e7770be9bd6a34a85cdc3ff6  corpus/tokens/syn_raw_control_char_in_string.jwt
f581ac48477e7f51b5a7cee8b13b1d1db314524a6fb4cbf9f4c30d7e9a748d47  corpus/tokens/syn_raw_surrogate_utf8.jwt
d56ea756d3c6944bfce7ea9ca1cd1faf95e839f9b3209411ecd28b993cbefd0c  corpus/tokens/syn_single_quotes.jwt
b752330c2fc174fd452e55337a6000f652c8bfc1e060e8cd066c40c9e76d9b9a  corpus/tokens/syn_top_level_array.jwt
d419ff7e3440a855962a2a88159d85a9be68ddc66fc274782b4c5de432b6c134  corpus/tokens/syn_trailing_comma_array.jwt
39b9284f4f254526cb64defbcb06a2bd6ac5c231435c1a01c89d792a150b9f75  corpus/tokens/syn_trailing_comma_object.jwt
1ae0e2bd49d85a35819894a6edbfcf96544b7991e7b1304d2bfcf566efc4edc1  corpus/tokens/syn_trailing_garbage.jwt
88248ec89e3fd6fc7ebb67b9799e35651dce87699974436b370b6cc50fb180d9  corpus/tokens/syn_trailing_nul.jwt
2c244d32416c3905ccdd1950690a41c38926c8d1e4481487c8ae014707efbfb0  corpus/tokens/syn_trailing_object.jwt
123f61901e38d3a6855ed42fe5d9a8e06acfe1fdcfe3158e98cebcfd062a18c1  corpus/tokens/syn_trailing_whitespace.jwt
d963777936f10ba132e911bf77331f44f869631b00b9f91c09793af0b426900e  corpus/tokens/syn_unquoted_key.jwt
09d5be398b6bfd8d6d1cc5841c6f0729502f3fc85d377d57d3e28354e48aff0b  corpus/tokens/syn_utf16be_nobom.jwt
3ea89dffda79e9bd8dc3ddbae10491f9785e43e5cdf41181c205c2d42b48722f  corpus/tokens/syn_utf16le_bom.jwt
18365ca91c8a016cdac0aea24dfde287c7e5d24848c02161d3ddac470c415a57  corpus/tokens/type_aud_bool.jwt
4afe0450a33d3572eadf3c6b97a7496f7b6d4d0dce453ec07da6c4ec1520afa2  corpus/tokens/type_aud_null.jwt
b5c97d32f3bd3ea18d99853e198be70fe7246f27f654ef519da10ff385a7a626  corpus/tokens/type_aud_number.jwt
c3b4f3850a59cefb3534fd2944c3370f3db67d9b3fff1d6926b152fa7dede04d  corpus/tokens/type_aud_object.jwt
903beb5992c590e5f34b44f007d779f7050d7117d43041a48c52aeaea0c62641  corpus/tokens/type_aud_single_array.jwt
900d8adf04e18183b3303a0a6bb53173f5693db06ca0fab62d9e0264d5bf20a4  corpus/tokens/type_exp_array.jwt
a7b65eedc45be65a934f73a80fbf44d974563f4c5cdcfbbb8f314f9cd46fa790  corpus/tokens/type_exp_bool.jwt
85ea24e42030c654e33e58ce216d4044f07d7286707472d8f6f0dc4c188dbbb4  corpus/tokens/type_exp_null.jwt
2e8c4130a088f6d46bf3ee8b6cb1c5492c737547af6582522c7f97f0a43ab2ca  corpus/tokens/type_exp_object.jwt
8f18e3704e61b1bd5eaf9d8cbbf90218693234e9a17e34c34b0b8a9843b2b5cb  corpus/tokens/type_exp_string.jwt
3a5a9fc42a16b45ac8a721d00bff0c31daf70cd3d663cf42807bb1eae30d4cb1  corpus/tokens/type_exp_string_float.jwt
e4a0970d09b84fab4f05c2f0c83eb9a1e7bf1edc5fdfb053a6b532f4c57b4f56  corpus/tokens/type_iat_null.jwt
735396b5d20cbc82d455518460dcd5735b6d046e07b4324b4dfb4252c2056a64  corpus/tokens/type_iat_string.jwt
fd03f24431fd2d4e615cdd554857f77add88891a8360a05a932a57f6ae53fa33  corpus/tokens/type_iss_array.jwt
79ee51b95f021416a7e62d909ce13df7ada12961600de150ca2b9c85839685a0  corpus/tokens/type_iss_number.jwt
ea0eaa847647c32f327e79a51a2f71c4c8c973d2047d2b063be8d07bccf123ff  corpus/tokens/type_iss_object.jwt
8e8f785d936d87f6e4ead0e91ee4ae6dd2d15f34efad146d03a3f6a39b2c0152  corpus/tokens/type_sub_bool.jwt
78cb0aed4dfacc21c4572d5276abfb1b8c7e2b52b4a6c6ad55b451d18494b891  corpus/tokens/type_sub_null.jwt
14df5135370b28aa97ee382692237e31c21f07db6e99f86db427f79d480063a2  corpus/tokens/type_sub_number.jwt
087a548d794898f9faa03d807d9e199bdc27f508d2bfdc03d3f6a293955a9c7e  corpus/tokens/uesc_aud_dup_after.jwt
b8b640b4f29d0ade9656fdeba96d8a92fec443582c0e770da9418453fe44b59a  corpus/tokens/uesc_aud_first_char.jwt
bf0b222e0b06cebf970e4219a6062eddfef11ddaa3d461bb9cb225f8822b09e5  corpus/tokens/uesc_exp_dup_after.jwt
b8b640b4f29d0ade9656fdeba96d8a92fec443582c0e770da9418453fe44b59a  corpus/tokens/uesc_exp_first_char.jwt
b57ac66a6071f76fbd8cedf1b720052aa8c6b5b05af05269f2a8304f77c50643  corpus/tokens/uesc_iat_dup_after.jwt
b8b640b4f29d0ade9656fdeba96d8a92fec443582c0e770da9418453fe44b59a  corpus/tokens/uesc_iat_first_char.jwt
b8b640b4f29d0ade9656fdeba96d8a92fec443582c0e770da9418453fe44b59a  corpus/tokens/uesc_iss_all_escaped.jwt
ac16b741adc76b531deaf0f3a81664af163e399e46ea78b64016ef92e25a9abf  corpus/tokens/uesc_iss_dup_after.jwt
267300d79364d940cb0db419500d027e625a9b2ef5b34307ea02aa2e55288310  corpus/tokens/uesc_iss_escaped_solidus.jwt
b8b640b4f29d0ade9656fdeba96d8a92fec443582c0e770da9418453fe44b59a  corpus/tokens/uesc_iss_first_char.jwt
a95bd925916ef7b7e00432c2d2d0b889ff8ad8378b81701d4a07536cfbcf6b91  corpus/tokens/uesc_iss_lone_surrogate_after.jwt
cb98a30a8424c610d43a03f0de748b22a88f3b580b71b87ed165973430d4a787  corpus/tokens/uesc_iss_nul_suffix_after.jwt
0eecfeaba706bddeacc091a6a87b57b3e67d0544178f9f31938a11ff283529b1  corpus/tokens/uesc_iss_upper_escaped_only.jwt
b8b640b4f29d0ade9656fdeba96d8a92fec443582c0e770da9418453fe44b59a  corpus/tokens/uesc_iss_value_escaped.jwt
94a1e92de681807a79e05f6320c0610490d8b81fdc7e8e166d8e872e146fdf5a  corpus/tokens/uesc_iss_value_lone_surrogate.jwt
658b10f648c2fe01337ec01357c29481970f05bf1083ef4ec2d08e263a8d1d28  corpus/tokens/uesc_sub_dup_after.jwt
b8b640b4f29d0ade9656fdeba96d8a92fec443582c0e770da9418453fe44b59a  corpus/tokens/uesc_sub_first_char.jwt
3841ca35a0d8a20676ecc8b051d24866e10a9648e3a85ef155ebdc4ace8263ed  corpus/tokens/uesc_sub_surrogate_pair.jwt
cfc0dc01018b5477221830bc1bee56829ac2bb8d2aa53923035e575dcc106f9d  corpus/tokens/uesc_sub_value_nul.jwt
04610b5656027f850b6d80344584fbbdd3d974cbaf66da08243de5b543581402  corpus/type_aud_bool.json
0b06686acd339430c9b7b93384670d490942983d97b0e9c9156b666c6a0cc718  corpus/type_aud_null.json
a35120215e8a24ecf7b3029c48a361632ced16d3e00e434ff2d8fab0b969d518  corpus/type_aud_number.json
ffb29c0a3f87da646ba15bf16fb5f06f14f868252cd1401c4f7af9a0f9d1eec3  corpus/type_aud_object.json
cc65814c1a4e49a3a5b5520abf2fecf45bf05dd18df71f90d4e5349f560ca6f0  corpus/type_aud_single_array.json
61e63d48cdf86e2adbe0e7d81a7c6333f9d7784a138d4f1d0553252fc767aace  corpus/type_exp_array.json
522adbeca224b79aa02161492a0f11f5a1f6d658c2dd13406ed91e36e23f8965  corpus/type_exp_bool.json
49e4776c131ef4f7b81890112dfef4a404082bc2382a8fc2ae15b36dbb9202ba  corpus/type_exp_null.json
7ee1dc63c0f314cb4a3e66e8b2ac9d914a47f49f8e2b984ccf315364131702ba  corpus/type_exp_object.json
cf12c4fac9dca9669a73200907f1eab0ea383795270838b1083710f5be73b659  corpus/type_exp_string.json
e7f22473bd87d2af5806f5d0ed3636455ff2f5a9a56241037c67e85e076220b6  corpus/type_exp_string_float.json
8d0bad51c2690293087100a380c03357c631d82aec308b586183a0d686ef7a67  corpus/type_iat_null.json
489fd8dbe3d43ee00e004b93d02592b105b30c2c0b3297377be7515d949058bb  corpus/type_iat_string.json
79b87d0d728a6983c46a991d1bc3ac8b078945a039b7ee935d7bfd5e764cffb0  corpus/type_iss_array.json
74a39c10db741d47eedc6686bfa29c9a01aa233d5d6602b7e892e948c7453f68  corpus/type_iss_number.json
c4f1cec583f0a6ed74235db0366df4e557389cae4f4e95c8539a4dadf4ad5fd3  corpus/type_iss_object.json
199b9110ed004931fff16baa32afd7c9f9668a764c06ba66419e3b404a0a283a  corpus/type_sub_bool.json
105332d3811aee6bda586d05cafb03b3f5fee48c1d66648bf536ab7397b451ca  corpus/type_sub_null.json
8bc5dbb03c08c553d50119a560f93f4f29442e852cbfe5e5f5d6e903c433ae75  corpus/type_sub_number.json
b1c85a7b32e82ce5ea7c7bc8da0a61b8863a079b54920916ca91af9965497243  corpus/uesc_aud_dup_after.json
afcae8039118707d0a94449d8a190e5e2e0d445691d791a4d5a58bd90da0d44c  corpus/uesc_aud_first_char.json
bb52fcb44b858ced029e23fca2af5b8819f1d78b730ad9ea2d0ea689d997edae  corpus/uesc_exp_dup_after.json
afcae8039118707d0a94449d8a190e5e2e0d445691d791a4d5a58bd90da0d44c  corpus/uesc_exp_first_char.json
039775e51198b724106e1ca34bb1bd927db81bd857f66001932cb691d6afbed8  corpus/uesc_iat_dup_after.json
afcae8039118707d0a94449d8a190e5e2e0d445691d791a4d5a58bd90da0d44c  corpus/uesc_iat_first_char.json
afcae8039118707d0a94449d8a190e5e2e0d445691d791a4d5a58bd90da0d44c  corpus/uesc_iss_all_escaped.json
469a72e31b8230b6af414bf278eec8902662f2beba46b08af51f2e2a31718690  corpus/uesc_iss_dup_after.json
7b4e13d7a904339f0178d55bfb9b2e72989ee4d6c57a916c755854f8b597843e  corpus/uesc_iss_escaped_solidus.json
afcae8039118707d0a94449d8a190e5e2e0d445691d791a4d5a58bd90da0d44c  corpus/uesc_iss_first_char.json
f8ccfeeb2fdee386c18e4ed47edb8c0e70a5080ba5f3cd1d160f3284290ef477  corpus/uesc_iss_lone_surrogate_after.json
54da962a7f5e326efb577d7de45997a1f1457a012b7b1fd2efc0f329f9ed75f8  corpus/uesc_iss_nul_suffix_after.json
45def5152a30e6b3a8b7d7ca331ced32c512164ee7aafe9dbeb92440b1e66b94  corpus/uesc_iss_upper_escaped_only.json
afcae8039118707d0a94449d8a190e5e2e0d445691d791a4d5a58bd90da0d44c  corpus/uesc_iss_value_escaped.json
16925771acd0fbe073409976bfeed4db1803172d75ea6f0c5d3b77578eb5da62  corpus/uesc_iss_value_lone_surrogate.json
d5e8e8d7e5e521e7c1076d6bc28b7581f7b64b3947e5d74013eea84a96c3146f  corpus/uesc_sub_dup_after.json
afcae8039118707d0a94449d8a190e5e2e0d445691d791a4d5a58bd90da0d44c  corpus/uesc_sub_first_char.json
44b4316f92c56fcd9239bb78a8605c266ef8298fac5619773057044af349f1d0  corpus/uesc_sub_surrogate_pair.json
b63dea943bfcd14a3468b9c283c305b6d4469b5321749dd02e929c7b40a1d4ab  corpus/uesc_sub_value_nul.json
```
