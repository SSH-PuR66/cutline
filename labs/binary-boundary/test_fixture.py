"""Exercise only this repository's freshly compiled pure-function fixture DLLs."""
import ctypes
import hashlib
import itertools
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[2]
U32_MAX = 2**32 - 1

def main():
    endpoints = [0, 1, 2, 254, 255, 256, 65535, 65536, 2**31-1, 2**31, U32_MAX-1, U32_MAX]
    triples = list(itertools.product(endpoints, repeat=3))
    rng = random.Random(20260911)
    triples.extend(tuple(rng.randrange(2**32) for _ in range(3)) for _ in range(20000))
    rows = []
    for opt in ("O0", "O2"):
        path = ROOT / "dist" / "binary-boundary" / f"fixture-{opt}.dll"
        dll = ctypes.CDLL(str(path))
        for name in ("legacy_boolean", "canonical_boolean"):
            getattr(dll, name).argtypes = [ctypes.c_uint8]
            getattr(dll, name).restype = ctypes.c_int
        for name in ("legacy_range", "bounded_range"):
            getattr(dll, name).argtypes = [ctypes.c_uint32] * 3
            getattr(dll, name).restype = ctypes.c_int
        bad_booleans = sum(dll.legacy_boolean(v) != (v if v < 2 else -1) for v in range(256))
        boolean_errors = sum(dll.canonical_boolean(v) != (v if v < 2 else -1) for v in range(256))
        false_accepts, false_rejects, bounded_errors = 0, 0, 0
        for total, offset, count in triples:
            expected = int(offset + count <= total)  # Python integer arithmetic does not wrap.
            old, new = dll.legacy_range(total, offset, count), dll.bounded_range(total, offset, count)
            false_accepts += old == 1 and expected == 0
            false_rejects += old == 0 and expected == 1
            bounded_errors += new != expected
        assert boolean_errors == 0 and bounded_errors == 0
        assert bad_booleans == 254 and false_accepts > 0 and false_rejects == 0
        examples = [dict(total=t, offset=o, count=n, mathematical=int(o+n<=t), legacy=dll.legacy_range(t,o,n), bounded=dll.bounded_range(t,o,n))
                    for t,o,n in [(16,U32_MAX,2),(16,8,8),(16,8,9),(0,0,0),(U32_MAX,U32_MAX,1)]]
        rows.append(dict(optimization=opt, sha256=hashlib.sha256(path.read_bytes()).hexdigest(), size_bytes=path.stat().st_size,
                         boolean_inputs=256, legacy_boolean_disagreements=bad_booleans, canonical_boolean_errors=boolean_errors,
                         range_inputs=len(triples), legacy_range_false_accepts=false_accepts,
                         legacy_range_false_rejects=false_rejects, bounded_range_errors=bounded_errors, examples=examples))
    report = dict(schema_version=1, method="Native ctypes calls to locally built x64 pure-function DLLs; independent unbounded-integer reference.",
                  seed=20260911, boundary_values=endpoints, random_triples=20000, builds=rows,
                  limitations=["Controlled fixtures, not a vulnerability claim about a third-party product.",
                               "All 256 byte values are exhausted; the 32-bit triple space is sampled, not exhausted.",
                               "No fixture dereferences input pointers or demonstrates exploitation."])
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "labs/binary-boundary/native-tests.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
