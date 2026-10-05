# Cutline

An original controlled reverse-engineering study linking native execution, Ghidra output and a browser instrument. Four exported functions contrast permissive/canonical Boolean decoding and wrapping/bounded unsigned range checks. The code has no input/output, imported functions, entry point or unsafe memory operations. It is not an exploit or a third-party vulnerability finding.

## Reproduce on Windows x64

Use a Windows x64 Python build (including x64 emulation on an ARM64 host), Clang with lld-link, and an official Ghidra release with its required JDK. Adjust the two tool paths to your installations:

```powershell
./build-fixture.ps1 -Clang 'C:/Program Files/LLVM/bin/clang.exe'
python -B test_fixture.py
./analyze-fixture.ps1 -GhidraHome 'C:/path/to/ghidra_12.1.3_PUBLIC'
```

The scripts derive the repository root from their own location. Native binaries and Ghidra projects are written beneath the repository's ignored `dist/binary-boundary/` directory. Old projects are preserved. The launcher gives Ghidra local cache/settings/temp directories under that same output path using process-scoped JDK options, restored on exit; this avoids Windows app-container path redirection without changing Ghidra security checks. Do not run the native test script against a replaced or untrusted DLL: it loads the two locally compiled fixtures. It is not a sandbox for unknown executables.

`fixture.c` is the original source. `ExportBoundary.java` is an original Ghidra post-analysis script. It exports only the four named functions, fails if any are missing or fail decompilation, records program identity and the binary SHA-256, and preserves recovered instruction addresses, bytes, decompiled C and block destinations. Parameter types or signatures are not corrected before decompilation. The exported function names remain visible in the PE export table.

The native test uses every byte value and 21,728 range triples per build: the Cartesian product of 12 boundary values plus 20,000 deterministic random triples (seed 20260911). Python's integer sum supplies a reference without uint32 wrap. Both builds record 254 Boolean disagreements and 6,855 legacy false range accepts. Corrected outputs have no disagreements on those inputs. The full 32-bit triple space is not exhausted.

The graph UI reads the actual exported blocks; the graph layout itself is editorial. Selecting O0/O2 changes the recovered data. The editable input panel evaluates equivalent arithmetic using JavaScript BigInt; it does not execute a DLL or Ghidra in the browser. Native results remain separately labelled and tied to the DLL hash. The page rejects disagreement between native-test and Ghidra artifact hashes; this is cross-file consistency, not a cryptographic trust chain or signed attestation.

## Observed decompiler discrepancy

Ghidra 12.1.3 infers `uint` for `canonical_boolean` at O0 and `ulonglong` at O2, both using the invalid bit pattern `0xffffffff`. The original exported function returns a 32-bit `int`, and native tests using that source-defined signature observe `-1` for all invalid byte values in both builds. The range function also receives inferred signed parameters despite unsigned original source. Decompiled C-like text is an interpretation and must not silently replace the original type contract.

## Published artifacts

- `analysis-O0.json`, `analysis-O2.json`: recorded Ghidra output.
- `native-tests.json`: recorded native test aggregates and counterexamples.
- `provenance.json`: exact tool versions, release hash, fixture hashes and method limits.
- Source, build/test scripts and the original exporter are public. DLLs, unknown samples, archives and local Ghidra projects are excluded from website deployment.

Serve the repository over HTTP and open `labs/binary-boundary/`. The page uses only local files, no market/account connection and no third-party JavaScript. Keyboard controls, a motion toggle, reduced-motion preference and hidden-page animation suspension are supported.

## Primary references

- [Ghidra 12.1.3 official release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.3_build)
- [Ghidra headless analyzer documentation](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md)
- [Clang Users Manual](https://clang.llvm.org/docs/UsersManual.html)
- [Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
