# Carryglass

A native property runner and a small evidence instrument for Faultline's original four arithmetic functions. Created by Sergio Rodriguez.

**[Open the instrument](index.html) · [Recorded run](evidence/report.json) · [Reduced replay](evidence/replay.json)**

Carryglass adds a new experiment alongside the original September record. It does not edit the fixture, original build script, Ghidra exports, provenance, or original verification script.

## Reproduce the native experiment

Requires Windows, an **x64 Python 3.10+ interpreter**, and Clang with lld-link. An ARM64 Python process cannot load the x64 fixture DLLs. The runner compiles only this repository's unchanged `fixture.c`; uploaded replay files never supply DLL paths, shell commands, or source code.

From the repository root, with the x64 interpreter selected as `python`:

```powershell
python -B -m unittest discover -s carryglass -p test_runner.py -v
python -B carryglass/runner.py --clang 'C:/Program Files/LLVM/bin/clang.exe'
python -B carryglass/runner.py --replay carryglass/evidence/replay.json
python -B verify_records.py
```

Each native command rebuilds O0 and O2 into ignored `dist/carryglass/native/`, checks the five original source hashes, records compiler flags, and validates each DLL against the build's SHA-256 before loading it. Strict compilation uses `-Wall -Wextra -Werror -Wconversion -Wsign-conversion` in addition to the original freestanding, no-entry-point link settings. No downloaded binary is loaded.

The default report and reduced witness are written to `dist/carryglass/report.json` and `dist/carryglass/replay.json`. To replace the checked-in experiment record deliberately:

```powershell
python -B carryglass/runner.py --output carryglass/evidence/report.json
```

`--samples N` sets the inputs **per seeded stream**, within 1–100,000. It does not change the 4,913 boundary triples. A mismatching replay exits 1; malformed input or a failed native build exits 2. Unit tests and `verify_records.py` run without native DLL support.

## What was executed on 21 October 2026

Clang **22.1.8**, target `x86_64-pc-windows-msvc`, x64 CPython **3.14.0**. The checked-in report contains the complete compiler string, flags, input seeds, runner/test source hashes, original source hashes and binary identities.

| Observation | O0 | O2 |
|---|---:|---:|
| Exhausted Boolean inputs | 256 | 256 |
| Legacy Boolean disagreements | 254 | 254 |
| Canonical Boolean errors | 0 | 0 |
| Range triples | 17,201 | 17,201 |
| Legacy range false accepts | 4,570 | 4,570 |
| Legacy range false rejects | 0 | 0 |
| Corrected range disagreements | 0 | 0 |
| Metamorphic native calls | 61,530 | 61,530 |
| Metamorphic disagreements | 0 | 0 |

There were **zero O0/O2 disagreements across 34,914 direct function-result comparisons**. Both strict-warning rebuilt DLL SHA-256 values match the original recorded binaries. The unchanged `verify_records.py` passed its five-source-hash, two-binary-identity and eight-function-record checks.

The range corpus combines the Cartesian product of 17 boundary values with 4,096 inputs from each seed: `20261021`, `12648430`, `24301`. Each seeded stream alternates uniform triples, carry-boundary triples, and valid intervals. Streams can repeat inputs; the table counts executed inputs, not unique coverage. These are deterministic experiments, not an exhaustive proof over uint32 triples.

The independent oracle uses Python integer subtraction after validating the start offset. It never masks, wraps, or calls the native implementation. Valid-range metamorphic checks grow the total, shorten the count, advance the offset while preserving the endpoint, move the start left, and construct a representable endpoint one beyond the total. The last relation excludes overflowing endpoints explicitly. Each relation is checked against the integer oracle and both native range functions.

## Reduction has a defined meaning

The reducer starts at `(total=16, offset=4294967295, count=2)` and preserves a specific failure: native legacy acceptance while the mathematical oracle rejects. It reaches `(0, 4294967294, 2)` in **16 predicate calls per build**, including the starting-input check and final candidate scan.

Candidates change exactly one coordinate to a strictly smaller value selected from `0`, `1`, `floor(x/2)`, `x−1`, or `x & (x−1)`. At the recorded fixed point, none of those candidates preserves the failure. This is **candidate-1-minimality**, not global minimality and not a claim about all possible multi-coordinate edits. The hard budget is 2,048 predicate calls; budget exhaustion returns the last failing input with the minimality flag false.

The 19 portable unit tests cover failure preservation, fixed-point candidates, budget exhaustion, benign controls, the oracle and relation domains, deterministic streams, all four replay signatures, duplicate keys, malformed/deep JSON, invalid UTF-8, nonfinite values, size limits, Boolean-as-integer coercion, narrowing and invalid return values. Native adapter validation happens before any DLL call.

## Browser evidence instrument

```powershell
python -m http.server 8891 --bind 127.0.0.1
```

Open `http://127.0.0.1:8891/carryglass/`. Six recorded cases show the mathematical sum, low 32 bits, native returns at O0/O2, and the independent oracle. The red carry cell leaves the visible word when stepping the trace. Motion begins only with **Run trace**, stops when hidden or offscreen, and respects reduced-motion preferences. The face, bit cells and scan texture are original CSS geometry; there are no remote image, font or script requests.

The browser can display a replay with the matching fixture hash. Imported return values are labeled as **recorded claims**; loading a JSON file does not execute native code or authenticate those claims. Use the Python `--replay` command to rebuild and compare them. Python applies the authoritative strict parser, including duplicate-key rejection.

An optional browser check is in `check-browser.cjs` (Node.js, the `playwright` package, and installed Microsoft Edge). With the loopback server running:

```powershell
node carryglass/check-browser.cjs
```

The recorded browser check passed all six cases, replay loading, malformed replay rejection, step/play/pause, reduced motion and 1440/390/320-pixel layouts. There were zero page errors and only loopback asset requests. Screenshots and browser results are generated under ignored `dist/carryglass/`.
