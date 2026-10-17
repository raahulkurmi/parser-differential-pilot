# Data-collection environment (corpus v1)

Taken from `results/raw/ENVIRONMENT.txt`, which `scripts/run_all.sh` writes
during collection. That file is not committed because its `uname` line contains
the machine's hostname (see `docs/DEVIATIONS.md`, D2). Everything else in it is
reproduced here unchanged.

| Item | Value |
|---|---|
| Collection time (UTC) | 2026-10-17T09:15:25Z (start) to 2026-10-17T09:15:32Z (end, `date_utc`) |
| Repository commit checked out during collection | `0085724fd7bf2944300874f8127911cd3fcde175` |
| Corpus | v1, verified against `corpus/SHA256SUMS` (SHA-256 `11ea1ce31135e20ff31119a8f1c74dde10d8f3a09c5fd6254521a954e71247c9`) immediately before the run |
| OS / kernel | Darwin 25.6.0 (`xnu-12377.161.14~5/RELEASE_ARM64_T8132`), arm64; macOS 26.6.2 |
| Go | `go version go1.26.3 darwin/arm64`; `GOOS=darwin GOARCH=arm64`, `GOEXPERIMENT` empty |
| Python | `3.13.9 \| packaged by Anaconda, Inc. \| (main, Oct 21 2025, 19:11:29) [Clang 20.1.8 ]`; `json` C scanner present |
| Node.js | `v24.5.0` |
| rustc | `rustc 1.99.1 (58cf8f9c3 2026-10-13) (Homebrew)` |
| cargo | `cargo 1.99.1 (5f94df478 2026-08-27) (Homebrew)` |

Library versions, from the committed lockfiles (installed with `go build
-mod=readonly`, `cargo build --locked`, `npm ci`, `pip install
--require-hashes`):

| Parser ID | Library @ version |
|---|---|
| go-encjson-struct | Go `encoding/json` (go1.26.3) |
| go-golangjwt | github.com/golang-jwt/jwt/v5 v5.3.0 |
| go-gojose | gopkg.in/go-jose/go-jose.v2 v2.6.3 |
| go-opa-json, go-opa-jwt | github.com/open-policy-agent/opa v1.21.2 |
| py-json | CPython 3.13.9 `json` |
| py-pyjwt | PyJWT 2.15.1 (cryptography 50.0.2, cffi 2.1.1, pycparser 3.11) |
| node-json | Node.js v24.5.0 `JSON.parse` |
| node-jose | jose 6.2.12 |
| node-jsonwebtoken | jsonwebtoken 9.0.3 (jws 4.0.1, jwa 2.0.1) |
| rs-serdejson | serde_json 1.0.154 |
| rs-jsonwebtoken | jsonwebtoken 11.1.0 (rsa 0.9.10) |

Raw output: `results/raw/<parser>.jsonl`. There are 12 files with 137 records
each (1,644 in total), and every parser process exited with status 0.
