# parser-differential-pilot

A pre-registered pilot measurement. Do the JSON and JWT parsers used on both
sides of cloud-native authorization (policy layers and verifiers) interpret the
same ambiguous input differently, and how often in the claims that decide a
security outcome (`iss`, `sub`, `aud`, `exp`, `iat`)?

**Status: phase 1 (pre-registration).** No parser has been run on the corpus yet.

- [`docs/PREREGISTRATION.md`](docs/PREREGISTRATION.md): question, parsers and pinned versions, corpus and hashes, classification rules, predictions, analysis plan, ethics, limitations
- [`corpus/`](corpus/): frozen corpus v1 (137 payloads, 137 signed tokens, `MANIFEST.csv`, `SHA256SUMS`)
- [`harness/`](harness/): one harness per language, each with a lockfile
- [`scripts/`](scripts/): corpus builders, the phase 2 runner and the analysis scripts
- [`testdata/keys/`](testdata/keys/): **test-only** RSA key used to sign the corpus tokens

Parser differentials are an established LangSec topic. This repository claims
no novelty. It reports parsing behaviour of specific library versions tested in
isolation and does not claim that any product is vulnerable.
