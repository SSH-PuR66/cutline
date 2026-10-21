"""Native property experiments for the four unchanged, local arithmetic fixtures."""
from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import itertools
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "labs" / "binary-boundary"
MAX = (1 << 32) - 1
SEEDS = (20261021, 0xC0FFEE, 0x5EED)
BOUNDARIES = (0, 1, 2, 3, 7, 8, 15, 16, 31, 255, 256, 65535, 65536,
              (1 << 31) - 1, 1 << 31, MAX - 1, MAX)
FUNCTIONS = ("legacy_boolean", "canonical_boolean", "legacy_range", "bounded_range")
FLAGS = ("--target=x86_64-pc-windows-msvc", "-std=c11", "-Wall", "-Wextra", "-Werror",
         "-Wconversion", "-Wsign-conversion", "-ffreestanding", "-fno-builtin",
         "-fno-stack-protector", "-shared", "-nostdlib", "-fuse-ld=lld",
         "-Wl,/noentry", "-Wl,/timestamp:0", "-Wl,/Brepro", "-Wl,/nodefaultlib")
REPLAY_LIMIT = 16384
SHRINK_LIMIT = 2048


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def integer(value: object, maximum: int = MAX) -> bool:
    return type(value) is int and 0 <= value <= maximum


def range_oracle(total: int, offset: int, count: int) -> int:
    # This formulation deliberately has no unsigned addition, masking or ctypes.
    return int(offset <= total and count <= total - offset)


def boolean_oracle(value: int) -> int:
    return value if value in (0, 1) else -1


def candidates(triple: tuple[int, int, int]):
    """Single-coordinate decreases only; never a claim of global minimality."""
    for index, value in enumerate(triple):
        values = {0, 1, value // 2, value - 1}
        if value:
            values.add(value & (value - 1))
        for smaller in sorted(v for v in values if 0 <= v < value):
            yield triple[:index] + (smaller,) + triple[index + 1:]


def reduce_failure(start: tuple[int, int, int], fails: Callable, budget: int = SHRINK_LIMIT):
    if len(start) != 3 or not all(integer(v) for v in start):
        raise ValueError("Reducer input must be a uint32 triple")
    if not integer(budget, SHRINK_LIMIT) or budget == 0:
        raise ValueError("Reducer budget must be 1..2048")
    calls = 1
    if not fails(start):
        raise ValueError("The starting input does not preserve the selected failure")
    current = start
    moves = [list(start)]
    while True:
        for candidate in candidates(current):
            if calls >= budget:
                return dict(input=list(current), calls=calls, candidate_1_minimal=False,
                            termination="budget", moves=moves)
            calls += 1
            if fails(candidate):
                current = candidate
                moves.append(list(current))
                break
        else:
            return dict(input=list(current), calls=calls, candidate_1_minimal=True,
                        termination="candidate fixed point", moves=moves)


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def exact_keys(value: object, keys: set[str], name: str):
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"Unexpected {name} fields")


def parse_replay(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or len(raw) > REPLAY_LIMIT:
        raise ValueError("Replay must be UTF-8 JSON no larger than 16 KiB")
    try:
        item = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicate_keys,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite number")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("Invalid replay JSON") from error
    exact_keys(item, {"schema", "function", "input", "expected", "recorded", "fixture_sha256"}, "replay")
    if item["schema"] != "carryglass.replay.v1" or item["function"] not in FUNCTIONS:
        raise ValueError("Unsupported replay schema or function")
    sha = item["fixture_sha256"]
    if not isinstance(sha, str) or len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
        raise ValueError("Fixture SHA-256 must be 64 lowercase hexadecimal digits")
    if item["function"].endswith("boolean"):
        exact_keys(item["input"], {"value"}, "input")
        if not integer(item["input"]["value"], 255):
            raise ValueError("Boolean input must be a byte")
        expected = boolean_oracle(item["input"]["value"])
    else:
        exact_keys(item["input"], {"total", "offset", "count"}, "input")
        if not all(integer(v) for v in item["input"].values()):
            raise ValueError("Range input must contain uint32 integers")
        expected = range_oracle(**item["input"])
    if type(item["expected"]) is not int or item["expected"] != expected:
        raise ValueError("Replay expected value differs from the independent oracle")
    exact_keys(item["recorded"], {"O0", "O2"}, "recorded")
    allowed = (-1, 0, 1) if item["function"] == "canonical_boolean" else (0, 1)
    if not all(type(v) is int and v in allowed for v in item["recorded"].values()):
        raise ValueError("Recorded return values are outside the fixture signature")
    return item


def source_identity() -> dict:
    provenance = json.loads((LAB / "provenance.json").read_text(encoding="utf-8"))
    actual = {name: digest(LAB / name) for name in provenance["source_sha256"]}
    if actual != provenance["source_sha256"]:
        raise ValueError("Original fixture provenance differs; build stopped")
    return actual


def build(clang: str, directory: Path) -> dict:
    sources = source_identity()
    directory.mkdir(parents=True, exist_ok=True)
    version = subprocess.run([clang, "--version"], check=True, capture_output=True,
                             text=True, timeout=30).stdout.strip()
    rows = []
    for opt in ("O0", "O2"):
        output = directory / f"fixture-{opt}.dll"
        command = [clang, *FLAGS, f"-{opt}", str(LAB / "fixture.c"), "-o", str(output)]
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
        rows.append(dict(optimization=opt, sha256=digest(output), size_bytes=output.stat().st_size))
    manifest = dict(compiler=version, flags=list(FLAGS), target="x86_64-pc-windows-msvc",
                    source_sha256=sources, builds=rows)
    (directory / "build.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


class Native:
    def __init__(self, directory: Path, opt: str, manifest: dict):
        if sys.platform != "win32" or struct.calcsize("P") != 8:
            raise ValueError("Native execution requires Windows and 64-bit x64 Python")
        path = directory / f"fixture-{opt}.dll"
        expected = next(row["sha256"] for row in manifest["builds"] if row["optimization"] == opt)
        if digest(path) != expected:
            raise ValueError("DLL identity differs from this local build manifest")
        try:
            self.dll = ctypes.CDLL(str(path))
        except OSError as error:
            raise ValueError("Cannot load x64 fixture; select the installed x64 Python interpreter") from error
        for name in FUNCTIONS:
            function = getattr(self.dll, name)
            function.argtypes = [ctypes.c_uint8] if name.endswith("boolean") else [ctypes.c_uint32] * 3
            function.restype = ctypes.c_int

    def call(self, name: str, args: tuple[int, ...]) -> int:
        if name not in FUNCTIONS:
            raise ValueError("Unknown fixture signature")
        maximum = 255 if name.endswith("boolean") else MAX
        if len(args) != (1 if name.endswith("boolean") else 3):
            raise ValueError("Unknown fixture signature")
        if not all(integer(value, maximum) for value in args):
            raise ValueError("Native input would narrow outside its declared domain")
        return getattr(self.dll, name)(*args)


def corpus(samples: int):
    yield "boundary Cartesian product", itertools.product(BOUNDARIES, repeat=3)
    for seed in SEEDS:
        rng = random.Random(seed)
        triples = []
        for index in range(samples):
            if index % 3 == 0:
                triple = tuple(rng.randrange(MAX + 1) for _ in range(3))
            elif index % 3 == 1:
                # Select both sides of the unsigned carry boundary without narrowing input.
                offset = rng.randrange(1, MAX + 1)
                count = min(MAX, max(0, (MAX + 1) - offset + rng.choice((-1, 0, 1))))
                triple = (rng.choice(BOUNDARIES), offset, count)
            else:
                total = rng.randrange(MAX + 1)
                offset = rng.randrange(total + 1)
                triple = (total, offset, rng.randrange(total - offset + 1))
            triples.append(triple)
        yield f"seed {seed}", triples


def transforms(triple):
    total, offset, count = triple
    if not range_oracle(*triple):
        return
    yield "grow total", (min(MAX, total + 1), offset, count), 1
    if count:
        yield "shorten count", (total, offset, count - 1), 1
        yield "advance within same end", (total, offset + 1, count - 1), 1
    if offset:
        yield "move start left", (total, offset - 1, count), 1
    # The transformed end stays representable, excluding overflow from this relation.
    if total < MAX:
        yield "one past total", (total, offset, total - offset + 1), 0


def make_replay(function: str, args: tuple, natives: dict, fixture_sha: str) -> dict:
    fields = ("value",) if function.endswith("boolean") else ("total", "offset", "count")
    item = dict(schema="carryglass.replay.v1", function=function, input=dict(zip(fields, args)),
                expected=boolean_oracle(*args) if function.endswith("boolean") else range_oracle(*args),
                recorded={opt: native.call(function, args) for opt, native in natives.items()},
                fixture_sha256=fixture_sha)
    return parse_replay(json.dumps(item).encode("utf-8"))


def experiment(directory: Path, manifest: dict, samples: int) -> tuple[dict, dict]:
    if not integer(samples, 100000) or samples == 0:
        raise ValueError("Samples per seed must be 1..100000")
    if source_identity() != manifest["source_sha256"]:
        raise ValueError("Build manifest does not describe the current original sources")
    natives = {opt: Native(directory, opt, manifest) for opt in ("O0", "O2")}
    groups = [(name, list(triples)) for name, triples in corpus(samples)]
    rows, examples = [], []
    cross_errors = 0
    for opt, native in natives.items():
        counts = dict(boolean_inputs=256, legacy_boolean_disagreements=0, canonical_boolean_errors=0,
                      range_inputs=0, legacy_false_accepts=0, legacy_false_rejects=0, bounded_errors=0,
                      metamorphic_native_calls=0, metamorphic_errors=0)
        grouped = []
        for value in range(256):
            counts["legacy_boolean_disagreements"] += native.call("legacy_boolean", (value,)) != boolean_oracle(value)
            counts["canonical_boolean_errors"] += native.call("canonical_boolean", (value,)) != boolean_oracle(value)
        for name, triples in groups:
            false_accepts = 0
            for triple in triples:
                expected = range_oracle(*triple)
                old, new = (native.call(fn, triple) for fn in ("legacy_range", "bounded_range"))
                counts["range_inputs"] += 1
                counts["legacy_false_accepts"] += old == 1 and expected == 0
                false_accepts += old == 1 and expected == 0
                counts["legacy_false_rejects"] += old == 0 and expected == 1
                counts["bounded_errors"] += new != expected
                for _, transformed, target in transforms(triple):
                    if range_oracle(*transformed) != target:
                        raise AssertionError("Invalid metamorphic relation")
                    for function in ("legacy_range", "bounded_range"):
                        counts["metamorphic_native_calls"] += 1
                        counts["metamorphic_errors"] += native.call(function, transformed) != target
            grouped.append(dict(name=name, inputs=len(triples), legacy_false_accepts=false_accepts))
        fails = lambda triple: native.call("legacy_range", triple) == 1 and range_oracle(*triple) == 0
        reduction = reduce_failure((16, MAX, 2), fails)
        rows.append(dict(optimization=opt, **counts, groups=grouped, reduction=reduction,
                         sha256=next(b["sha256"] for b in manifest["builds"] if b["optimization"] == opt)))
    for _, triples in groups:
        for triple in triples:
            for function in ("legacy_range", "bounded_range"):
                cross_errors += natives["O0"].call(function, triple) != natives["O2"].call(function, triple)
    for value in range(256):
        for function in ("legacy_boolean", "canonical_boolean"):
            cross_errors += natives["O0"].call(function, (value,)) != natives["O2"].call(function, (value,))
    for label, triple in (("carry escapes", (16, MAX, 2)), ("exact fit", (16, 8, 8)),
                          ("one past", (16, 8, 9)), ("empty interval", (0, 0, 0)),
                          ("maximum endpoint", (MAX, MAX, 0)),
                          ("reduced witness", tuple(rows[0]["reduction"]["input"]))):
        examples.append(dict(label=label, input=dict(zip(("total", "offset", "count"), triple)),
                             mathematical_sum=triple[1] + triple[2], sum_hex=f"0x{triple[1]+triple[2]:09X}",
                             low32_hex=f"0x{(triple[1]+triple[2]) & MAX:08X}",
                             expected=range_oracle(*triple), native={opt: {fn: n.call(fn, triple)
                             for fn in ("legacy_range", "bounded_range")} for opt, n in natives.items()}))
    passed = cross_errors == 0 and all(row["legacy_boolean_disagreements"] == 254 and
             row["legacy_false_accepts"] > 0 and row["legacy_false_rejects"] == 0 and
             row["canonical_boolean_errors"] == row["bounded_errors"] == row["metamorphic_errors"] == 0 and
             row["reduction"]["candidate_1_minimal"] for row in rows)
    report = dict(schema="carryglass.report.v1", recorded_at=datetime.now(timezone.utc).isoformat(),
                  passed=passed, python=sys.version, compiler=manifest["compiler"], flags=manifest["flags"],
                  source_sha256=manifest["source_sha256"], seeds=list(SEEDS), samples_per_seed=samples,
                  harness_sha256={name: digest(Path(__file__).parent / name)
                                  for name in ("runner.py", "test_runner.py")},
                  boundary_values=list(BOUNDARIES), builds=rows, optimization_disagreements=cross_errors,
                  optimization_comparisons=2 * (sum(len(t) for _, t in groups) + 256), examples=examples,
                  reducer=dict(budget=SHRINK_LIMIT, operators="one coordinate to 0, 1, floor(x/2), x-1, or x&(x-1), strictly smaller",
                               guarantee="No listed single-coordinate candidate preserves failure at the recorded fixed point; not globally minimal."),
                  limits=["Original inert arithmetic fixtures; no third-party vulnerability established.",
                          "All 256 byte inputs tested; uint32 triples sampled, not exhausted.",
                          "Recorded native runs are separate from the browser arithmetic model.",
                          "Hashes identify these local artifacts, not a signed attestation."])
    replay = make_replay("legacy_range", tuple(rows[0]["reduction"]["input"]), natives,
                         manifest["source_sha256"]["fixture.c"])
    return report, replay


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", default="C:/Program Files/LLVM/bin/clang.exe")
    parser.add_argument("--samples", type=int, default=4096)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "carryglass" / "report.json")
    parser.add_argument("--replay", type=Path, help="Validate and rerun an existing replay after rebuilding locally")
    args = parser.parse_args()
    if not integer(args.samples, 100000) or args.samples == 0:
        parser.error("--samples must be 1..100000")
    try:
        replay = None
        if args.replay:
            with args.replay.open("rb") as source:
                replay = parse_replay(source.read(REPLAY_LIMIT + 1))
        directory = ROOT / "dist" / "carryglass" / "native"
        manifest = build(args.clang, directory)
        if replay is not None:
            if replay["fixture_sha256"] != manifest["source_sha256"]["fixture.c"]:
                raise ValueError("Replay refers to a different fixture source")
            natives = {opt: Native(directory, opt, manifest) for opt in ("O0", "O2")}
            order = ("value",) if replay["function"].endswith("boolean") else ("total", "offset", "count")
            actual = make_replay(replay["function"], tuple(replay["input"][key] for key in order), natives,
                                 manifest["source_sha256"]["fixture.c"])
            matched = actual["recorded"] == replay["recorded"]
            print(json.dumps(dict(replayed=actual, recorded_results_match=matched), indent=2))
            return 0 if matched else 1
        report, replay = experiment(directory, manifest, args.samples)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        args.output.with_name("replay.json").write_text(json.dumps(replay, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(dict(passed=report["passed"], report=str(args.output), builds=report["builds"],
                              optimization_disagreements=report["optimization_disagreements"]), indent=2))
        return 0 if report["passed"] else 1
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"Carryglass stopped: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
