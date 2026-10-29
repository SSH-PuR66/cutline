# Faultline

**Created and maintained by [Sergio Rodriguez (SSH-PuR66)](https://github.com/SSH-PuR66).**

[Watch the overflow mechanism in Attack Atlas](https://sergrdz.pages.dev/labs/attack-atlas/#faultline) · [Read the C fixture](labs/binary-boundary/fixture.c) · [Inspect native results](labs/binary-boundary/native-tests.json)

[![Faultline: a segmented computer worm of smoked glass memory blocks carries a crimson signal along its spine.](assets/faultline-worm.png)](https://sergrdz.pages.dev/labs/binary-boundary/)

Original project artwork generated for Sergio Rodriguez; illustration, not execution evidence.

Previously published as Cutline. Repository URLs and fixture paths remain stable.

**New native experiment: [Carryglass](carryglass/README.md)** — three seeded streams, boundary and metamorphic checks, bounded counterexample reduction, strict replay validation, and a recorded evidence browser. [Open the instrument](carryglass/index.html) · [Inspect the run](carryglass/evidence/report.json).

**Recorded structure desk:** compare O0/O2 instruction, block and edge counts against their binary identities; select a basic block to isolate its actual assembly addresses. Keyboard navigation and opt-in edge illustrations use the same recorded graph. [Open the desk](https://sergrdz.pages.dev/labs/binary-boundary/) · [Verification record](labs/binary-boundary/structure-browser-check.json).

**[Parserglass](parserglass/README.md):** ten bounded synthetic ELF specimens compare a strict section-completeness policy with a pinned pyelftools parser. Original corpus, observer and recorded outcomes; upstream authorship stays with its contributors.

### Reverse engineering a range check that accepts the impossible

`total=16, offset=4294967295, count=2` passes a legacy uint32 range check. Addition wraps to 1 before the comparison. The corrected function rejects the input before adding.

I wrote four C functions, built them at O0 and O2, recovered their control flow with Ghidra, and compared native execution with an independent integer reference. The instrument puts source, decompiled C, instruction bytes, and counterexamples on the same desk.

[Open the instrument](https://sergrdz.pages.dev/labs/binary-boundary/) · [Source fixture](labs/binary-boundary/fixture.c) · [Recorded native results](labs/binary-boundary/native-tests.json) · [Full method](labs/binary-boundary/README.md)

**Research type:** original controlled experiment. **Stack:** C, Clang, Ghidra, Python. **Question:** which assumptions survive compilation and recovery?

## Observed results

The original experiment was recorded on **12 September 2026**. A fresh native rebuild and run on **27 September 2026** reproduced these results for **each** optimization level:

| Check | Inputs per build | Legacy disagreements | Corrected disagreements |
|---|---:|---:|---:|
| Canonical encoded Boolean | Every byte: 256 | 254 | 0 |
| Unsigned range bound | 21,728 triples | 6,855 false accepts; 0 false rejects | 0 |

The range set contains the Cartesian product of 12 boundary values plus 20,000 random triples from seed `20260911`. The complete uint32 triple space was not exhausted. Both rebuilt DLL hashes matched the original record. Fresh Ghidra 12.1.3 exports also matched the original O0/O2 JSON records, including recovered code, instructions, and control-flow destinations.

For example, `total=16, offset=4294967295, count=2` passes the legacy range check because unsigned addition wraps to 1. The corrected check rejects it before adding. Ghidra also infers different return widths for the canonical Boolean decoder across the two builds; native calls using the original source signature retain the same result.

These are inert, original fixtures. They establish behavior on the tested inputs, not a vulnerability in another product. Browser inputs evaluate JavaScript arithmetic; they do not execute a DLL or Ghidra.

## Reproduce

Use Windows with an x64 Python interpreter, Clang with lld-link, and an official Ghidra distribution with its required JDK. An ARM64 Windows host can use an x64 Python interpreter under emulation. From this repository root:

```powershell
./labs/binary-boundary/build-fixture.ps1 -Clang 'C:/Program Files/LLVM/bin/clang.exe'
python -B ./labs/binary-boundary/test_fixture.py ./dist/binary-boundary/native-test-run.json
./labs/binary-boundary/analyze-fixture.ps1 -GhidraHome 'C:/path/to/ghidra_12.1.3_PUBLIC'
python -B ./verify_records.py
```

The native test loads only the freshly built local fixtures. It is not an unknown-binary sandbox. Generated DLLs, import libraries, analysis projects, and tool caches stay in ignored `dist/`. The Ghidra script refreshes the two published analysis JSON files; inspect that diff when using another tool version.

For the browser desk, run `python -m http.server 8787 --bind 127.0.0.1` from this directory and open `http://127.0.0.1:8787/labs/binary-boundary/`.

`python -B verify_records.py` also runs on platforms without the native toolchain. It checks the five recorded source hashes, exact named functions, instruction counts, control-flow destinations, and agreement between the recorded binary hashes. Passing it establishes record consistency only.

### Attack the evidence reader — 28 October 2026

The saved-record verifier now applies a fixed five-file source allowlist, bounded reads and duplicate-key rejection before following the records. Deleting the source map no longer silently removes the source checks. It validates the exact O0/O2 build set, program identities, sizes, corpus arithmetic and example results, then checks unique block starts, contiguous instruction addresses, x64 instruction-byte lengths, disjoint instruction ranges and graph destinations.

The [24 adversarial record tests](test_verify_records.py) preserve the original evidence and corrupt isolated temporary copies. They cover duplicate members, Boolean-as-integer fields, oversized/deep/malformed JSON, an empty source map, path replacement, changed sources, duplicate builds/functions/blocks, wrong binary identities, address gaps, dangling edges, impossible counts and false arithmetic witnesses. The unmodified original records pass with **5 source hashes, 2 binary identities, 8 functions and 76 instruction records**. The existing 19 portable Carryglass tests also pass.

```sh
python -B -m unittest -v test_verify_records
python -B verify_records.py
python -B -m unittest discover -s carryglass -p test_runner.py
```

The [CI workflow](.github/workflows/records.yml) runs record checks on Python 3.12 and 3.14. This update strengthens inspection of saved evidence; it does not rerun Clang/Ghidra, decode instruction bytes, prove that text matches machine code, authenticate the publisher, or turn a self-consistent record into proof of execution. The original fixture, binary records and provenance remain unchanged.

### Bound the decoder before reading evidence

Fourteen additional [decoder regressions](test_verify_records.py) test the whole JSON document, including metadata that the record verifier does not otherwise use. Ten rejection expectations failed against the prior reader; all fourteen now pass, alongside the original 24 saved-record checks. The [before/after record](evidence/parser-budget-2026-10-28.json) names the tested prior commit and source hashes. These are local input-contract defects, not a demonstrated remote exploit or a measured memory-exhaustion attack.

The reader now rejects structural nesting beyond 24 container levels before calling `json.loads`. After decoding, it enforces 50,000 total nodes, 8,192 members per container, and 262,144 UTF-8 bytes per text value. Integer tokens have at most 20 digits; float tokens have at most 64 characters and must remain finite. Escaped unpaired surrogates are rejected in keys and values. The existing 2,000,000-byte file cap still bounds input reads. Finite floating metadata, uint64 seed tokens, valid surrogate pairs and delimiters inside strings are retained as positive controls; typed evidence fields still apply their stricter existing checks.

Original native and Ghidra records remain unchanged and pass the strengthened reader with five source hashes, two binary identities, eight functions and 76 instructions. Parsing consistency does not authenticate those records or execute their contents.

## Contents and provenance

- `labs/binary-boundary/fixture.c`: original four-function source.
- `build-fixture.ps1`, `test_fixture.py`: build and native reference comparison.
- `ExportBoundary.java`, `analyze-fixture.ps1`: original Ghidra exporter and launcher.
- `analysis-O0.json`, `analysis-O2.json`, `native-tests.json`: recorded outputs.
- `provenance.json`: original tool versions, input hashes, and method limits.
- `verification-2026-09-27.json`: fresh reproduction record.
- `index.html`, `desk.css`, `desk.js`, `model.js`: standalone browser instrument.

The nested layout preserves the original scripts and their byte hashes. The package adapts only browser navigation and documentation for a standalone checkout. See [NOTICE.md](NOTICE.md) for source attribution and rights. No third-party binaries or libraries are bundled.
