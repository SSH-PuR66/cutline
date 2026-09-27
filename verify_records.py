"""Check published-record consistency. Does not replace the native experiment."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LAB = ROOT / "labs" / "binary-boundary"
EXPECTED = {"legacy_boolean", "canonical_boolean", "legacy_range", "bounded_range"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    provenance = json.loads((LAB / "provenance.json").read_text(encoding="utf-8"))
    native = json.loads((LAB / "native-tests.json").read_text(encoding="utf-8"))
    for name, digest in provenance["source_sha256"].items():
        require(hashlib.sha256((LAB / name).read_bytes()).hexdigest() == digest,
                f"Recorded source hash differs: {name}")
    for optimization in ("O0", "O2"):
        analysis = json.loads((LAB / f"analysis-{optimization}.json").read_text(encoding="utf-8"))
        recorded_native = next(row for row in native["builds"] if row["optimization"] == optimization)
        recorded_binary = next(row for row in provenance["artifacts"] if row["optimization"] == optimization)
        require(analysis["binary_sha256"] == recorded_native["sha256"] == recorded_binary["sha256"],
                f"Binary identity differs across {optimization} records")
        functions = analysis["functions"]
        require(len(functions) == 4 and {row["name"] for row in functions} == EXPECTED,
                f"Unexpected function set in {optimization}")
        for function in functions:
            blocks = function["blocks"]
            addresses = {block["start"] for block in blocks}
            require(function["entry"] in addresses, "Entry block is missing")
            require(sum(len(block["instructions"]) for block in blocks) == function["instruction_count"],
                    "Instruction count differs from listing")
            require(bool(function["decompiled_c"].strip()), "Recovered code is missing")
            for block in blocks:
                require(bool(block["instructions"]), "An exported block has no instructions")
                for instruction in block["instructions"]:
                    require(bool(bytes.fromhex(instruction["bytes"])), "Instruction bytes are empty")
                for edge in block["edges"]:
                    require(edge["to"] in addresses, "A graph edge has no destination block")
        require(recorded_native["canonical_boolean_errors"] == 0
                and recorded_native["bounded_range_errors"] == 0,
                "Recorded corrected behavior contains disagreements")
    print("Record consistency passed: 5 source hashes, 2 binary identities, 8 functions and their graph/listing records.")
    print("This check does not execute native code or establish source authenticity.")


if __name__ == "__main__":
    main()
