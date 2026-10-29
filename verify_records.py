"""Check published-record consistency. Does not replace the native experiment."""
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent
LAB = ROOT / "labs" / "binary-boundary"
EXPECTED = {"legacy_boolean", "canonical_boolean", "legacy_range", "bounded_range"}
SOURCES = {"fixture.c", "build-fixture.ps1", "analyze-fixture.ps1", "ExportBoundary.java", "test_fixture.py"}
MAX_RECORD_BYTES = 2_000_000
U32_MAX = (1 << 32) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strict_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "Duplicate JSON member")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("Non-finite JSON number")

    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_RECORD_BYTES + 1)
    require(len(raw) <= MAX_RECORD_BYTES, "Record exceeds size limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        raise ValueError("Malformed record JSON") from exc
    require(type(value) is dict, "Record must be an object")
    require(type(value.get("schema_version")) is int and value["schema_version"] == 1,
            "Unsupported record schema")
    return value


def integer(value, minimum=0, maximum=U32_MAX):
    require(type(value) is int and minimum <= value <= maximum, "Invalid integer field")
    return value


def digest(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
            "Invalid SHA-256 encoding")
    return value


def address(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{1,16}", value) is not None,
            "Invalid instruction address")
    return int(value, 16)


def sequence(value, minimum=0, maximum=4096):
    require(type(value) is list and minimum <= len(value) <= maximum, "Invalid list size")
    return value


def builds_by_optimization(rows):
    sequence(rows, 2, 2)
    require(all(type(row) is dict for row in rows), "Invalid build record")
    require({row.get("optimization") for row in rows} == {"O0", "O2"},
            "Build set must contain O0 and O2 exactly once")
    return {row["optimization"]: row for row in rows}


def validate_native(native):
    boundaries = sequence(native["boundary_values"], 1, 256)
    for value in boundaries:
        integer(value)
    require(len(set(boundaries)) == len(boundaries), "Duplicate boundary input")
    integer(native["seed"], 0, (1 << 64) - 1)
    count = len(boundaries) ** 3 + integer(native["random_triples"], 0, 1_000_000)
    builds = builds_by_optimization(native["builds"])
    for build in builds.values():
        digest(build["sha256"])
        integer(build["size_bytes"], 1, 100_000_000)
        require(integer(build["boolean_inputs"]) == 256, "Boolean corpus is incomplete")
        require(integer(build["range_inputs"]) == count, "Range corpus count differs")
        for name in ("legacy_boolean_disagreements", "canonical_boolean_errors"):
            integer(build[name], 0, 256)
        for name in ("legacy_range_false_accepts", "legacy_range_false_rejects", "bounded_range_errors"):
            integer(build[name], 0, count)
        require(build["legacy_range_false_accepts"] + build["legacy_range_false_rejects"] <= count,
                "Disagreement counts exceed the corpus")
        require(build["canonical_boolean_errors"] == build["bounded_range_errors"] == 0,
                "Recorded corrected behavior contains disagreements")
        for example in sequence(build["examples"], 1, 1024):
            total, offset, length = (integer(example[key]) for key in ("total", "offset", "count"))
            expected = int(offset <= total and length <= total - offset)
            wrapped = int(((offset + length) & U32_MAX) <= total)
            for name in ("mathematical", "bounded", "legacy"):
                integer(example[name], 0, 1)
            require(example["mathematical"] == example["bounded"] == expected
                    and example["legacy"] == wrapped, "Saved arithmetic example is inconsistent")
    return builds


def verify(lab=LAB):
    lab = Path(lab).resolve()
    provenance = strict_json(lab / "provenance.json")
    native = strict_json(lab / "native-tests.json")
    require(type(provenance["source_sha256"]) is dict
            and set(provenance["source_sha256"]) == SOURCES, "Source allowlist differs")
    for name in sorted(SOURCES):
        expected_digest = digest(provenance["source_sha256"][name])
        path = lab / name
        require(not path.is_symlink() and path.resolve().parent == lab, "Source path escaped fixture directory")
        with path.open("rb") as stream:
            raw = stream.read(1_000_001)
        require(len(raw) <= 1_000_000, "Source exceeds size limit")
        require(hashlib.sha256(raw).hexdigest() == expected_digest,
                f"Recorded source hash differs: {name}")
    builds = validate_native(native)
    artifacts = builds_by_optimization(provenance["artifacts"])
    instruction_total = 0
    for optimization in ("O0", "O2"):
        analysis = strict_json(lab / f"analysis-{optimization}.json")
        recorded_native, recorded_binary = builds[optimization], artifacts[optimization]
        require(digest(analysis["binary_sha256"]) == recorded_native["sha256"] == digest(recorded_binary["sha256"]),
                f"Binary identity differs across {optimization} records")
        require(integer(recorded_binary["size_bytes"], 1, 100_000_000) == recorded_native["size_bytes"],
                "Binary sizes differ across records")
        require(analysis["program"] == f"fixture-{optimization}.dll", "Wrong program identity")
        require(analysis["ghidra_version"] == provenance["ghidra_version"], "Ghidra versions differ")
        require(analysis["language"] == "x86:LE:64:default"
                and analysis["compiler_spec"] == "clangwindows", "Unexpected analysis target")
        functions = sequence(analysis["functions"], 4, 4)
        require(len(functions) == 4 and {row["name"] for row in functions} == EXPECTED,
                f"Unexpected function set in {optimization}")
        instruction_ranges = []
        for function in functions:
            blocks = sequence(function["blocks"], 1, 1024)
            addresses = {address(block["start"]) for block in blocks}
            require(len(addresses) == len(blocks), "Duplicate basic-block address")
            require(address(function["entry"]) in addresses, "Entry block is missing")
            require(sum(len(block["instructions"]) for block in blocks)
                    == integer(function["instruction_count"], 1, 8192),
                    "Instruction count differs from listing")
            require(type(function["decompiled_c"]) is str and bool(function["decompiled_c"].strip()),
                    "Recovered code is missing")
            for block in blocks:
                cursor = address(block["start"])
                for instruction in sequence(block["instructions"], 1, 8192):
                    require(address(instruction["address"]) == cursor, "Instruction address gap or overlap")
                    encoded = instruction["bytes"]
                    require(type(encoded) is str and re.fullmatch(
                        r"[0-9a-fA-F]{2}(?: [0-9a-fA-F]{2}){0,14}", encoded) is not None,
                        "Invalid x64 instruction bytes")
                    size = len(bytes.fromhex(encoded))
                    instruction_ranges.append((cursor, cursor + size))
                    cursor += size
                    require(cursor <= 1 << 64, "Instruction address overflows")
                    require(type(instruction["text"]) is str and bool(instruction["text"].strip()),
                            "Instruction text is missing")
                edges = set()
                for edge in sequence(block["edges"], 0, 1024):
                    target = address(edge["to"])
                    require(target in addresses, "A graph edge has no destination block")
                    require(type(edge["kind"]) is str and bool(edge["kind"].strip()), "Missing edge kind")
                    key = target, edge["kind"]
                    require(key not in edges, "Duplicate graph edge")
                    edges.add(key)
        instruction_ranges.sort()
        require(all(a[1] <= b[0] for a, b in zip(instruction_ranges, instruction_ranges[1:])),
                "Instruction ranges overlap")
        instruction_total += len(instruction_ranges)
    return {"source_hashes": 5, "binary_identities": 2, "functions": 8, "instructions": instruction_total}


def main():
    try:
        result = verify()
    except (ValueError, TypeError, KeyError, OSError, OverflowError, RecursionError, AttributeError):
        print("Record consistency failed: malformed, missing or inconsistent evidence.", file=sys.stderr)
        return 1
    print("Record consistency passed: " + json.dumps(result, sort_keys=True))
    print("This check does not execute native code or establish source authenticity.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
