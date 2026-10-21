# Parserglass

Original corpus and observer by **Sergio Rodriguez**. Upstream parser: [pyelftools](https://github.com/eliben/pyelftools), maintained by Eli Bendersky and contributors. No upstream authorship is reassigned.

This study asks a narrow question: does receiving section bytes establish that the declared ELF section and compressed stream were complete? Ten synthetic ELF64 specimens compare a strict completeness policy with the actual `ELFFile.get_section(2).data()` result at commit `5a04389392e25d8128e1acb59828a0a85be791b1`.

## Recorded observations

| Specimen | Strict policy | Parser observation |
|---|---|---|
| Plain section, valid | Accept | 144 bytes |
| Plain section declares 148 stored bytes, only 144 present | Reject | Returns 144; reports 148 |
| zlib section, valid | Accept | 144 bytes |
| zlib checksum trailer absent | Reject | Returns 144 bytes |
| Trailing bytes after complete zlib stream | Reject | Returns 144 bytes |
| Logical size declares 143; stream contains 144 | Reject | Returns 143 bytes |
| Logical size declares 145; stream contains 144 | Reject | `ELFCompressionError` |
| Invalid zlib header | Reject | zlib error |
| Valid empty compressed section | Accept | 0 bytes |
| Truncated section table | Reject | `ELFParseError` |

Four observations differ from this study's strict policy. The policy is deliberately separate from the upstream contract. These observations establish neither a new vulnerability nor exploitability. The upstream [security policy](https://github.com/eliben/pyelftools/blob/5a04389392e25d8128e1acb59828a0a85be791b1/SECURITY.md) explicitly says the project is not intended as a security boundary. No disclosure or issue has been submitted.

The practical consequence for an evidence viewer is specific: displayed byte count and parser success do not establish stream completeness. Check stored bounds, decompressor end-of-stream, unused data, and the logical length before treating a parsed section as complete evidence.

## Reproduce

Python 3.10+ and Git; no packages are installed and no third-party input is executed. Run from this directory:

```powershell
git clone https://github.com/eliben/pyelftools.git upstream
git -C upstream checkout --detach 5a04389392e25d8128e1acb59828a0a85be791b1
python -B -m unittest -v test_probe.py
python -B probe.py --upstream ./upstream --output report.json
```

Each specimen runs in a fresh Python subprocess with a five-second timeout. Inputs are bounded to 8 KiB, declared logical output to 4 KiB, and stream reads to 128 calls of at most 16 KiB. The fixed corpus creates no executables, performs no DWARF linked-file loading, and has no network requests. The observer verifies the pinned upstream commit and rejects tracked source modifications before running.

`report.json` records every input hash, original probe hash, observed outcome, read-call count, interpreter version, and the exact upstream parser/security-policy hashes. Errors are recorded as errors, not successful empty sections. The read budget and timeout are bounds on these synthetic specimens, not a sandbox for arbitrary hostile files.

Source reading: [`Section.data()`](https://github.com/eliben/pyelftools/blob/5a04389392e25d8128e1acb59828a0a85be791b1/elftools/elf/sections.py) and [`ELFFile`](https://github.com/eliben/pyelftools/blob/5a04389392e25d8128e1acb59828a0a85be791b1/elftools/elf/elffile.py).
