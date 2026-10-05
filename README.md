# Cutline

Previously published as Binary Boundary. The repository name and presentation changed; fixture paths, recorded source inputs, and their byte hashes retain their original identity.

Four C functions, two compiler builds, and the difference between a recovered type and a source contract.

I wrote small Boolean decoders and unsigned range checks, compiled them at O0 and O2, recovered their control flow with Ghidra, and called the native functions against an independent integer reference. The browser desk keeps source, decompilation, instruction bytes, and counterexamples together.

[Open the published instrument](https://sergrdz.pages.dev/labs/binary-boundary/) · [Read the experiment](labs/binary-boundary/README.md)

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

## Contents and provenance

- `labs/binary-boundary/fixture.c`: original four-function source.
- `build-fixture.ps1`, `test_fixture.py`: build and native reference comparison.
- `ExportBoundary.java`, `analyze-fixture.ps1`: original Ghidra exporter and launcher.
- `analysis-O0.json`, `analysis-O2.json`, `native-tests.json`: recorded outputs.
- `provenance.json`: original tool versions, input hashes, and method limits.
- `verification-2026-09-27.json`: fresh reproduction record.
- `index.html`, `desk.css`, `desk.js`, `model.js`: standalone browser instrument.

The nested layout preserves the original scripts and their byte hashes. The package adapts only browser navigation and documentation for a standalone checkout. See [NOTICE.md](NOTICE.md) for source attribution and rights. No third-party binaries or libraries are bundled.

