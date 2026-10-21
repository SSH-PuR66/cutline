"""Portable tests for the experiment's input boundaries and reduction claims."""
import copy
import itertools
import json
import unittest

from runner import (MAX, BOUNDARIES, FUNCTIONS, Native, boolean_oracle, candidates,
                    corpus, parse_replay, range_oracle, reduce_failure, transforms)


def wrapping_failure(triple):
    total, offset, count = triple
    return ((offset + count) & MAX) <= total and offset + count > total


def replay():
    return dict(schema="carryglass.replay.v1", function="legacy_range",
                input=dict(total=0, offset=MAX - 1, count=2), expected=0,
                recorded=dict(O0=1, O2=1), fixture_sha256="a" * 64)


def encoded(item):
    return json.dumps(item).encode("utf-8")


class OracleTests(unittest.TestCase):
    def test_all_byte_values_have_canonical_outcome(self):
        self.assertEqual([boolean_oracle(v) for v in range(256)], [0, 1] + [-1] * 254)

    def test_range_oracle_matches_unbounded_sum_at_every_boundary(self):
        for triple in itertools.product(BOUNDARIES, repeat=3):
            total, offset, count = triple
            self.assertEqual(range_oracle(*triple), int(offset + count <= total))

    def test_known_controls_and_carry(self):
        for triple, expected in [((16, 8, 8), 1), ((16, 8, 9), 0), ((0, 0, 0), 1),
                                 ((MAX, MAX, 0), 1), ((16, MAX, 2), 0), ((MAX, MAX, 1), 0)]:
            self.assertEqual(range_oracle(*triple), expected)

    def test_metamorphic_relations_stay_in_declared_domain(self):
        checks = 0
        for triple in itertools.product(BOUNDARIES, repeat=3):
            for name, changed, expected in transforms(triple):
                self.assertTrue(all(0 <= v <= MAX for v in changed), name)
                self.assertEqual(range_oracle(*changed), expected, name)
                checks += 1
        self.assertGreater(checks, 1000)

    def test_corpus_repeats_including_three_seed_groups(self):
        first = [(name, list(rows)) for name, rows in corpus(96)]
        second = [(name, list(rows)) for name, rows in corpus(96)]
        self.assertEqual(first, second)
        self.assertEqual(len(first), 4)
        self.assertEqual([len(rows) for _, rows in first], [4913, 96, 96, 96])
        self.assertTrue(all(0 <= v <= MAX for _, rows in first for row in rows for v in row))
        self.assertTrue(any(wrapping_failure(row) for row in first[1][1]))
        self.assertTrue(any(range_oracle(*row) for row in first[1][1]))


class ReducerTests(unittest.TestCase):
    def test_reduction_preserves_failure_and_candidate_local_minimality(self):
        for start in ((16, MAX, 2), (0, 1 << 31, 1 << 31), (MAX - 1, MAX, MAX)):
            result = reduce_failure(start, wrapping_failure)
            final = tuple(result["input"])
            self.assertTrue(result["candidate_1_minimal"])
            self.assertTrue(wrapping_failure(final))
            self.assertFalse(any(wrapping_failure(c) for c in candidates(final)))
            self.assertTrue(all(wrapping_failure(tuple(m)) for m in result["moves"]))
            for before, after in zip(result["moves"], result["moves"][1:]):
                self.assertEqual(sum(a != b for a, b in zip(before, after)), 1)
                self.assertLess(sum(after), sum(before))
            self.assertLessEqual(result["calls"], 2048)

    def test_candidate_operators_are_exact_and_strictly_decreasing(self):
        found = list(candidates((4, 0, 0)))
        self.assertEqual(found, [(0, 0, 0), (1, 0, 0), (2, 0, 0), (3, 0, 0)])
        self.assertEqual(list(candidates((0, 0, 0))), [])

    def test_reducer_rejects_benign_control(self):
        with self.assertRaisesRegex(ValueError, "starting input"):
            reduce_failure((16, 8, 8), wrapping_failure)

    def test_budget_exhaustion_does_not_claim_minimal(self):
        result = reduce_failure((16, MAX, 2), wrapping_failure, budget=1)
        self.assertFalse(result["candidate_1_minimal"])
        self.assertEqual(result["termination"], "budget")
        self.assertEqual(result["calls"], 1)
        self.assertTrue(wrapping_failure(tuple(result["input"])))

    def test_reducer_rejects_invalid_domain_and_budget(self):
        for triple in ((0, -1, 2), (0, MAX + 1, 1), (True, 0, 0), (0, 0)):
            with self.assertRaises(ValueError):
                reduce_failure(triple, wrapping_failure)
        for budget in (0, -1, True, 2049, 1.5):
            with self.assertRaises(ValueError):
                reduce_failure((16, MAX, 2), wrapping_failure, budget)


class ReplayTests(unittest.TestCase):
    def test_valid_range_replay_roundtrip(self):
        self.assertEqual(parse_replay(encoded(replay())), replay())

    def test_all_four_function_schemas(self):
        for function in FUNCTIONS:
            item = replay()
            item["function"] = function
            if function.endswith("boolean"):
                item.update(input={"value": 255}, expected=-1)
                item["recorded"] = {"O0": -1, "O2": -1} if function == "canonical_boolean" else {"O0": 1, "O2": 1}
            self.assertEqual(parse_replay(encoded(item)), item)

    def test_rejects_wrong_schema_extra_missing_and_signature_fields(self):
        invalid = []
        for key in replay():
            item = replay()
            del item[key]
            invalid.append(item)
        for update in ({"extra": 1}, {"schema": 1}, {"function": "system"},
                       {"function": {}}, {"input": [0, 1, 2]}, {"input": {"value": 7}},
                       {"recorded": {"O0": 1}}, {"recorded": {"O0": 1, "O2": 1, "O3": 1}}):
            item = replay()
            item.update(update)
            invalid.append(item)
        for item in invalid:
            with self.assertRaises(ValueError):
                parse_replay(encoded(item))

    def test_rejects_narrowing_boolean_float_string_and_out_of_range_values(self):
        for value in (-1, MAX + 1, True, False, 1.0, "1", None, []):
            item = replay()
            item["input"]["offset"] = value
            with self.assertRaises(ValueError):
                parse_replay(encoded(item))
        for value in (-1, 256, True, "1"):
            item = replay()
            item.update(function="canonical_boolean", input={"value": value}, expected=-1)
            with self.assertRaises(ValueError):
                parse_replay(encoded(item))

    def test_rejects_false_expected_and_recorded_return_domains(self):
        for expected in (1, True, 0.0, None):
            item = replay()
            item["expected"] = expected
            with self.assertRaises(ValueError):
                parse_replay(encoded(item))
        for recorded in (-1, 2, True, 1.0, "1"):
            item = replay()
            item["recorded"]["O0"] = recorded
            with self.assertRaises(ValueError):
                parse_replay(encoded(item))

    def test_rejects_bad_hashes(self):
        for sha in ("A" * 64, "a" * 63, "g" * 64, 0, []):
            item = replay()
            item["fixture_sha256"] = sha
            with self.assertRaises(ValueError):
                parse_replay(encoded(item))

    def test_rejects_duplicate_keys_including_nested_input(self):
        raw = encoded(replay()).replace(b'"total": 0', b'"total": 0, "total": 1')
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            parse_replay(raw)

    def test_rejects_nonfinite_large_invalid_utf8_and_deep_payloads(self):
        for raw in (b'{"expected": NaN}', b'{"expected": Infinity}', b"{" * 2000,
                    b"[" * 2000 + b"]" * 2000, b"\xff", b" " * 16385, b"null", b"[]"):
            with self.assertRaises(ValueError):
                parse_replay(raw)

    def test_native_adapter_rejects_narrowing_before_accessing_dll(self):
        # No native library is installed in this object: rejection must precede the call.
        native = object.__new__(Native)
        for function, args in (("legacy_range", (MAX + 1, 0, 0)), ("legacy_range", (0, True, 0)),
                               ("canonical_boolean", (256,)), ("legacy_range", (0, 1)),
                               ("unknown", (0,))):
            with self.assertRaises(ValueError):
                native.call(function, args)


if __name__ == "__main__":
    unittest.main()
