"""A bounded synthetic ELF corpus. No file execution or external DWARF loading."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import zlib

UPSTREAM = "https://github.com/eliben/pyelftools"
REVISION = "5a04389392e25d8128e1acb59828a0a85be791b1"
MAX_INPUT = 8192
MAX_READ = 16384
MAX_CALLS = 128
MAX_OUTPUT = 4096
PAYLOAD = b"parserglass: bounded local specimen\n" * 4


class BudgetStream(io.BytesIO):
    def __init__(self, data: bytes):
        if len(data) > MAX_INPUT:
            raise ValueError("input budget exceeded")
        super().__init__(data)
        self.calls = 0

    def read(self, size: int = -1) -> bytes:
        self.calls += 1
        if self.calls > MAX_CALLS or size > MAX_READ:
            raise ValueError("read budget exceeded")
        return super().read(size)


def elf(payload: bytes, *, compressed: bool = False,
        declared_size: int | None = None, declared_storage: int | None = None) -> bytes:
    names = b"\0.shstrtab\0.sample\0"
    offset = 64 + 3 * 64 + len(names)
    data = payload
    if compressed:
        size = len(PAYLOAD) if declared_size is None else declared_size
        if not 0 <= size <= MAX_OUTPUT:
            raise ValueError("declared output budget exceeded")
        data = struct.pack("<IIQQ", 1, 0, size, 1) + payload
    header = b"\x7fELF\x02\x01\x01" + bytes(9)
    header += struct.pack("<HHIQQQIHHHHHH", 1, 62, 1, 0, 0, 64, 0, 64, 0, 0, 64, 3, 1)
    string_section = struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, 256, len(names), 0, 0, 1, 0)
    sample = struct.pack("<IIQQQQIIQQ", 11, 1, 0x800 if compressed else 0,
                         0, offset, len(data) if declared_storage is None else declared_storage,
                         0, 0, 1, 0)
    return header + bytes(64) + string_section + sample + names + data


def corpus() -> dict[str, bytes]:
    packed = zlib.compress(PAYLOAD)
    return {
        "plain-valid": elf(PAYLOAD),
        "plain-short-storage": elf(PAYLOAD, declared_storage=len(PAYLOAD) + 4),
        "zlib-valid": elf(packed, compressed=True),
        "zlib-missing-checksum": elf(packed[:-4], compressed=True),
        "zlib-trailing-data": elf(packed + b"TAIL", compressed=True),
        "zlib-short-declaration": elf(packed, compressed=True, declared_size=len(PAYLOAD) - 1),
        "zlib-long-declaration": elf(packed, compressed=True, declared_size=len(PAYLOAD) + 1),
        "zlib-invalid-header": elf(bytes([packed[0] ^ 0xff]) + packed[1:], compressed=True),
        "zlib-empty-valid": elf(zlib.compress(b""), compressed=True, declared_size=0),
        "section-table-truncated": elf(PAYLOAD)[:240],
    }


def reference(data: bytes) -> dict:
    """Explicit completeness policy for this three-section fixture grammar."""
    try:
        if len(data) < 256 or len(data) > MAX_INPUT:
            return {"accepted": False, "reason": "table-or-input-bound"}
        fields = struct.unpack_from("<IIQQQQIIQQ", data, 192)
        flags, offset, size = fields[2], fields[4], fields[5]
        if offset > len(data) or size > len(data) - offset:
            return {"accepted": False, "reason": "section-storage-bound"}
        stored = data[offset:offset + size]
        if flags & 0x800:
            if len(stored) < 24:
                return {"accepted": False, "reason": "compression-header-short"}
            kind, reserved, declared, align = struct.unpack_from("<IIQQ", stored)
            if kind != 1 or reserved != 0 or align != 1 or declared > MAX_OUTPUT:
                return {"accepted": False, "reason": "compression-header-policy"}
            decoder = zlib.decompressobj()
            decoded = decoder.decompress(stored[24:], MAX_OUTPUT + 1)
            if not decoder.eof:
                return {"accepted": False, "reason": "zlib-stream-incomplete"}
            if decoder.unused_data or decoder.unconsumed_tail:
                return {"accepted": False, "reason": "zlib-extra-data"}
            if len(decoded) != declared:
                return {"accepted": False, "reason": "logical-size-mismatch"}
        else:
            decoded = stored
        return {"accepted": True, "bytes": len(decoded), "sha256": hashlib.sha256(decoded).hexdigest()}
    except (ValueError, struct.error, zlib.error) as error:
        return {"accepted": False, "reason": type(error).__name__}


def observe(upstream: Path, case: str) -> dict:
    sys.path.insert(0, str(upstream))
    from elftools.elf.elffile import ELFFile
    stream = BudgetStream(corpus()[case])
    try:
        parsed = ELFFile(stream, stream_loader=None)
        section = parsed.get_section(2)
        if section.data_size > MAX_OUTPUT:
            raise ValueError("logical output budget exceeded")
        result = section.data()
        return {"accepted": True, "bytes": len(result), "reported_bytes": section.data_size,
                "sha256": hashlib.sha256(result).hexdigest(), "read_calls": stream.calls}
    except Exception as error:
        return {"accepted": False, "error_type": type(error).__name__, "read_calls": stream.calls}


def run(upstream: Path) -> dict:
    revision = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    if revision != REVISION:
        raise ValueError(f"expected upstream revision {REVISION}, received {revision}")
    dirty = subprocess.check_output(["git", "-C", str(upstream), "status", "--porcelain", "--untracked-files=no"], text=True)
    if dirty.strip():
        raise ValueError("upstream tracked source must be clean")
    rows = []
    for name, data in corpus().items():
        try:
            child = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()),
                                    "--upstream", str(upstream), "--case", name],
                                   capture_output=True, text=True, timeout=5, check=True)
            observed = json.loads(child.stdout)
        except subprocess.TimeoutExpired:
            observed = {"accepted": None, "error_type": "Timeout"}
        rows.append({"id": name, "input_bytes": len(data), "input_sha256": hashlib.sha256(data).hexdigest(),
                     "reference": reference(data), "observed": observed})
    sources = ["elftools/elf/elffile.py", "elftools/elf/sections.py", "SECURITY.md"]
    return {"schema_version": 1, "project": "Parserglass", "author": "Sergio Rodriguez",
            "upstream": UPSTREAM, "revision": revision, "python": sys.version.split()[0],
            "source_hashes": {p: hashlib.sha256((upstream / p).read_bytes()).hexdigest() for p in sources},
            "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "limits": {"input_bytes": MAX_INPUT, "logical_output_bytes": MAX_OUTPUT,
                       "read_size": MAX_READ, "read_calls": MAX_CALLS, "case_seconds": 5},
            "scope": "Synthetic local parser observations; strict reference policy is not an upstream contract. No novelty or exploitability claim.",
            "cases": rows}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--case", choices=tuple(corpus()))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = observe(args.upstream.resolve(), args.case) if args.case else run(args.upstream.resolve())
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8", newline="\n")
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
