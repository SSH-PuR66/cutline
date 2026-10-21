# Source attribution

Cutline, originally published as Binary Boundary, was created for Sergio Rodriguez's portfolio. The controlled C fixture, Ghidra export script, native regression script, browser instrument, and documentation are original project work. This standalone package preserves the recorded source inputs from the September 2026 experiment.

Ghidra, Clang/LLVM, Python, and the JDK are external tools. Their implementations are not included in this repository. Decompiled listings and instruction records were generated from the original fixture using those tools; they are not decompilation of a third-party program.

Primary tool references:

- [Ghidra official release used in the original experiment](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.3_build)
- [Ghidra headless analyzer documentation](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.3_build/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md)
- [Clang Users Manual](https://clang.llvm.org/docs/UsersManual.html)
- [Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)

The source directory supplied for this package did not contain a license grant. Copyright 2026 Sergio Rodriguez. No additional license is granted by this notice.

## Recorded structure desk, 21 October 2026

The original address-selection and structural-comparison implementation takes design inspiration from [Ghidra's disassembly, decompilation and graph views](https://github.com/NationalSecurityAgency/ghidra/blob/master/README.md) and [Recurse's address navigation and binary-analysis interface](https://github.com/Recurse-Labs/recurse/blob/master/README.md). No upstream code, interface assets or artwork were copied. This browser does not embed either product or run a disassembler; it displays the existing fixture's recorded Ghidra exports.

The new worm image is original artwork generated for Sergio Rodriguez. See [the artwork record](assets/faultline-worm-artwork.md). It illustrates the project and is not execution evidence.

