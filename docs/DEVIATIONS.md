# Deviations from the pre-registered procedure

Pre-registration: commit `3499fcb9219f502defd964b7c854625f9a713599`, amended
(before data collection) in `0085724fd7bf2944300874f8127911cd3fcde175`. No
prediction, classification or equality rule, metric, parser pin or corpus file
was changed. The corpus was verified against `corpus/SHA256SUMS` (all 275
files matched) immediately before collection.

Phase 2 had **no** harness crashes, no timeouts and no output that the
classifier could not place:
- every parser process exited with status 0;
- there are exactly 137 records per parser (1,644 in total), all well-formed;
- no value was encoded as `{"t":"other"}`.

The deviations below are procedural.

## D1. Analysis steps of `scripts/run_all.sh` deferred until the raw results were committed

- **What happened.** `scripts/run_all.sh` collects data (lines 1–56) and then, in the same run, calls `classify.py`, `summarize.py` and `check_predictions.py` (lines 58–60). The project owner's phase 2 instructions required the raw outputs to be committed and pushed *before* any classification or summary script ran.
- **What was done.** Lines 1–56 were executed unchanged, as `bash -c "$(sed -n 1,56p run_all.sh)"` from inside `scripts/`, so that the script's own `cd "$(dirname "$0")/.."` resolves to the repository root. That covered: corpus hash check; `canon.go` sync check; builds from lockfiles; one run of each of the 12 parsers; and the environment dump. The raw outputs were committed and pushed as `7889750b92d0f30edae0fe13e4f9d31a530ce380`. The three analysis scripts were then run unchanged, in the order `classify.py`, `check_predictions.py`, `summarize.py`.
- **Why.** This is the most conservative way to satisfy both constraints. The data-collection commands are byte-identical to the pre-registered ones, and the raw data was committed and pushed to GitHub (then a private repository) before any analysis ran, with a server-side push timestamp (the `/activity` endpoint described in `docs/TIMING_EVIDENCE.md`). The analysis scripts read only the raw files and do not depend on each other's outputs, except that `classify.py` runs first, so running them in a different order cannot change any number.

## D2. `results/raw/ENVIRONMENT.txt` not committed

- **What happened.** The environment dump's `uname -a` line includes the collection machine's local hostname, which embeds a hardware-address-like identifier.
- **What was done.** The file was left exactly as written but is not committed. It was added to `.gitignore` in the raw-results commit. Every other line is reproduced unchanged in `results/ENVIRONMENT.md`, with the `uname` line shown without the hostname.
- **Why.** Publishing a local machine identifier serves no reproducibility purpose. No result depends on the file. The analysis scripts read only `results/raw/*.jsonl`.

## D3. Formatting script added after pre-registration

- **What happened.** The pre-registered analysis plan has no step that writes `docs/PREDICTION_OUTCOMES.md`, and none that writes a separate policy-side × verifier-side table.
- **What was done.** I added `scripts/render_reports.py`. It computes nothing. It copies each prediction's pre-registered wording and its verdict and evidence verbatim from `results/summary/predictions.csv`, mapping HOLDS→HELD and FAILS→FAILED. It also filters `results/summary/per_pair.csv` down to the rows whose `roles` column is `policy-side x verifier-side`.
- **Why.** This avoids typing any number or verdict by hand.

## D4. Portability fix to the interpreter path in `scripts/run_all.sh` (post-hoc)

- **What happened.** Line 26 of `scripts/run_all.sh` created the Python virtual environment with a hard-coded interpreter path, `/opt/anaconda3/bin/python3`, that exists only on the collection machine.
- **What was done.** After data collection, and after the results and exploratory analysis were committed, the path was replaced with `${PYTHON:-python3}`. Data collection had used the original line; `results/ENVIRONMENT.md` records the interpreter it ran (CPython 3.13.9, Anaconda build).
- **Why.** So that the script runs on other machines. The change touches only that one line. It changes no logic, and the analysis does not use `scripts/run_all.sh`. Re-running `classify.py`, `summarize.py`, `check_predictions.py`, `exploratory.py` and `render_reports.py` from the committed raw results after the change produced byte-identical outputs.

## Observations that are not deviations

These follow the pre-registered rules but affect how the results should be read.

- `type_sub_null` produces a `sub` VALUE differential between `go-gojose` and every other accepting parser. The cause is the pre-registered extraction rule (§4): go-jose's typed `Subject` string cannot hold `null`, so it decodes to `""`, which the rule reports as ABSENT, while raw-map parsers report `null`.
- On `num_{exp,iat}_2p63` and `num_{exp,iat}_2p64p1`, `go-gojose` reports `9223372036854775807`. This is Go's float-to-`int64` conversion saturating on darwin/arm64, as anticipated in Limitation 3 of the pre-registration.
