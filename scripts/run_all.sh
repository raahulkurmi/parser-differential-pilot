#!/usr/bin/env bash
# Phase 2 data collection. NOT TO BE RUN during pre-registration (phase 1).
#
# 1. verifies the frozen corpus against corpus/SHA256SUMS
# 2. builds every harness from its lockfile
# 3. runs each of the 12 parsers once over the whole corpus -> results/raw/<parser>.jsonl
# 4. records the toolchain environment -> results/raw/ENVIRONMENT.txt
# 5. derives pairs, summary tables and prediction results from those files only
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -n "$(ls -A results/raw 2>/dev/null | grep -v '^.gitkeep$' || true)" ]; then
  echo "results/raw is not empty; refusing to overwrite collected data" >&2
  exit 1
fi

shasum -a 256 -c corpus/SHA256SUMS --quiet
python3 -I scripts/check_harness_sync.py

PUB=testdata/keys/TEST_ONLY_rs256_public.pem
(cd harness/go && go build -mod=readonly -o harness-go .)
(cd harness/go-opa && go build -mod=readonly -o harness-go-opa .)
(cd harness/rust && cargo build --release --locked)
(cd harness/node && npm ci --ignore-scripts)
if [ ! -x harness/python/.venv/bin/python ]; then
  "${PYTHON:-python3}" -m venv harness/python/.venv
fi
harness/python/.venv/bin/pip install --require-hashes --no-deps -r harness/python/requirements.txt

for p in go-encjson-struct go-golangjwt go-gojose; do
  harness/go/harness-go -parser "$p" -corpus corpus -pubkey "$PUB" > "results/raw/$p.jsonl"
done
for p in go-opa-json go-opa-jwt; do
  harness/go-opa/harness-go-opa -parser "$p" -corpus corpus -pubkey "$PUB" > "results/raw/$p.jsonl"
done
for p in py-json py-pyjwt; do
  harness/python/.venv/bin/python -I harness/python/harness.py --parser "$p" --corpus corpus --pubkey "$PUB" > "results/raw/$p.jsonl"
done
for p in node-json node-jose node-jsonwebtoken; do
  (cd harness/node && node harness.mjs --parser "$p" --corpus ../../corpus --pubkey "../../$PUB") > "results/raw/$p.jsonl"
done
for p in rs-serdejson rs-jsonwebtoken; do
  harness/rust/target/release/pdp-rust-harness --parser "$p" --corpus corpus --pubkey "$PUB" > "results/raw/$p.jsonl"
done

{
  echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "uname: $(uname -a)"
  echo "go: $(go version)"
  echo "go_env: $(go env GOOS GOARCH GOEXPERIMENT | tr '\n' ' ')"
  echo "python: $(harness/python/.venv/bin/python -c 'import sys,json; print(sys.version.replace(chr(10)," "), "c_scanner=", json.scanner.c_make_scanner is not None)')"
  echo "node: $(node --version)"
  echo "rustc: $(rustc --version)"
  echo "cargo: $(cargo --version)"
  echo "git_commit: $(git rev-parse HEAD)"
} > results/raw/ENVIRONMENT.txt

python3 scripts/classify.py
python3 scripts/summarize.py
python3 scripts/check_predictions.py
