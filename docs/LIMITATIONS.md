# Limitations

These limitations apply to every result in this repository. Results describe how
each parser handles each input. They do not describe any product or deployment.

## 1. Isolated parsers, not deployed configurations

Each library was called in isolation, with one API and one configuration (see
`docs/PREREGISTRATION.md` §2.2), and with all optional claim validation turned
off. A deployed system chains particular components, each with its own options,
validation, size limits and pre-processing (for example a gateway that
re-serialises JSON before a policy engine sees it). This study does not measure
whether any differential can be reached through such a chain. The
policy-side × verifier-side tables describe disagreement between two parsers,
not between two deployed systems.

## 2. Hand-built corpus, not exhaustive

Corpus v1 has 137 hand-written cases in 8 categories. Every count depends on
which cases were included. For example, 36 cases target `exp`/`iat` numbers,
and that is reflected in the per-field counts. A pair with no differential here
has no differential on these inputs only. No fuzzing or grammar-based
generation was used.

## 3. Version- and platform-specific results

The results hold for the exact library versions, toolchains and platform
recorded in `results/ENVIRONMENT.md` (darwin/arm64). One known platform
dependency appeared in the data: go-jose v2's `NumericDate` converts a float to
`int64`, and on this platform out-of-range values (2^63, 2^64+1) saturate to
`9223372036854775807`. Other architectures may produce a different value. Other
versions of any library may behave differently.

## 4. Disagreement is not exploitability

A VALUE or ACCEPTANCE differential shows that two parsers interpret the same
bytes differently. It does not show that any product, deployment or
combination of these libraries is vulnerable or affected. Pair counts are not
weighted by how often two components are actually deployed together, and many
pairs never are. Many of the differentials involve inputs that a conforming
JWT issuer would never produce (for example `exp` = `1e400`). They also involve
behaviours that RFC 8259 leaves to the implementation (duplicate names, number
range and precision).

## 5. Measurement choices shape the counts

The pre-registered extraction and equality rules are judgement calls, and they
affect the totals:
- **Numbers are compared by exact value.** A library that keeps 2^53+1 exactly and one that rounds it to the nearest double count as different. So does an exact decimal against its nearest double. Most pairs that differ on `exp`/`iat` differ on number representation. The per-field and per-case tables let readers judge how much of the headline count this accounts for.
- **Typed decoders.** For go-jose's typed claims, `""` and a `null` `iss`/`sub` are reported as ABSENT, so `type_sub_null` produces a differential between go-jose and the raw-map parsers.
- **`aud`.** The primary rule treats a string as equal to a one-element array (RFC 7519). The strict sensitivity rule gave the same pair counts (60 and 61), but a different per-field count for `aud` (21 rather than 11 pairs).

## 6. Narrow policy side

Both policy-side entries are OPA v1.21.2, and they share one JSON decoding path
(`io.jwt.decode` calls the `json.unmarshal` implementation). As predicted (P22),
they never disagreed with each other. Other policy engines are not represented.

## 7. Predictions were informed by source reading

All 22 pre-registered predictions held. They were written after reading each
library's documentation and source (without executing anything), so this
largely confirms that reading. It is not a test of a broader hypothesis, and a
perfect hit rate should not be read as evidence of anything beyond that.

## 8. Deviations

Three procedural deviations are recorded in `docs/DEVIATIONS.md`:
- D1: the analysis steps were deferred until the raw results were committed;
- D2: the environment dump containing the local hostname was not committed;
- D3: a formatting-only report script was added.

None changed a prediction, rule, pin, corpus file or number.
