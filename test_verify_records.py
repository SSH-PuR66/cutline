"""Corrupt one saved evidence dimension at a time; never execute its contents."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import verify_records as verifier


class RecordIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.lab = Path(self.temp.name)
        for name in verifier.SOURCES | {"provenance.json", "native-tests.json", "analysis-O0.json", "analysis-O2.json"}:
            shutil.copyfile(verifier.LAB / name, self.lab / name)

    def mutate(self, filename, change):
        path = self.lab / filename
        value = json.loads(path.read_text(encoding="utf-8"))
        change(value)
        path.write_text(json.dumps(value), encoding="utf-8")

    def rejected(self):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            verifier.verify(self.lab)

    def test_original_records(self):
        self.assertEqual(verifier.verify(self.lab), {
            "source_hashes": 5, "binary_identities": 2, "functions": 8, "instructions": 76})

    def test_duplicate_json_members(self):
        path = self.lab / "native-tests.json"
        path.write_text(path.read_text().replace('"schema_version": 1', '"schema_version": 7, "schema_version": 1'))
        self.rejected()

    def test_boolean_schema(self):
        self.mutate("native-tests.json", lambda x: x.update(schema_version=True))
        self.rejected()

    def test_nonfinite_json(self):
        self.mutate("native-tests.json", lambda x: x.update(seed=float("nan")))
        self.rejected()

    def test_oversized_record(self):
        (self.lab / "native-tests.json").write_bytes(b" " * (verifier.MAX_RECORD_BYTES + 1))
        self.rejected()

    def test_deep_json(self):
        (self.lab / "native-tests.json").write_text("[" * 3000 + "0" + "]" * 3000)
        self.rejected()

    def test_invalid_utf8(self):
        (self.lab / "native-tests.json").write_bytes(b"\xff")
        self.rejected()

    def test_empty_source_set(self):
        self.mutate("provenance.json", lambda x: x.update(source_sha256={}))
        self.rejected()

    def test_record_path_cannot_select_source(self):
        def change(value):
            value["source_sha256"]["../fixture.c"] = value["source_sha256"].pop("fixture.c")
        self.mutate("provenance.json", change)
        self.rejected()

    def test_changed_source(self):
        with (self.lab / "fixture.c").open("ab") as stream:
            stream.write(b"\n/* changed */\n")
        self.rejected()

    def test_duplicate_build(self):
        self.mutate("native-tests.json", lambda x: x["builds"].append(x["builds"][0]))
        self.rejected()

    def test_wrong_binary_size(self):
        self.mutate("provenance.json", lambda x: x["artifacts"][0].update(size_bytes=1))
        self.rejected()

    def test_wrong_digest(self):
        self.mutate("analysis-O0.json", lambda x: x.update(binary_sha256="0" * 64))
        self.rejected()

    def test_wrong_program_identity(self):
        self.mutate("analysis-O0.json", lambda x: x.update(program="fixture-O2.dll"))
        self.rejected()

    def test_duplicate_function(self):
        self.mutate("analysis-O0.json", lambda x: x["functions"].__setitem__(1, x["functions"][0]))
        self.rejected()

    def test_duplicate_block(self):
        self.mutate("analysis-O0.json", lambda x: x["functions"][0]["blocks"].append(x["functions"][0]["blocks"][0]))
        self.rejected()

    def test_instruction_address_gap(self):
        self.mutate("analysis-O0.json", lambda x: x["functions"][0]["blocks"][0]["instructions"][1].update(address="180001003"))
        self.rejected()

    def test_instruction_exceeds_x64_limit(self):
        self.mutate("analysis-O0.json", lambda x: x["functions"][0]["blocks"][0]["instructions"][0].update(bytes=" ".join(["90"] * 16)))
        self.rejected()

    def test_boolean_instruction_count(self):
        self.mutate("analysis-O0.json", lambda x: x["functions"][0].update(instruction_count=True))
        self.rejected()

    def test_dangling_edge(self):
        self.mutate("analysis-O0.json", lambda x: x["functions"][0]["blocks"][0]["edges"].append({"to": "1", "kind": "JUMP"}))
        self.rejected()

    def test_impossible_corpus_count(self):
        self.mutate("native-tests.json", lambda x: x["builds"][0].update(range_inputs=0))
        self.rejected()

    def test_negative_disagreement_count(self):
        self.mutate("native-tests.json", lambda x: x["builds"][0].update(legacy_range_false_accepts=-1))
        self.rejected()

    def test_false_arithmetic_witness(self):
        self.mutate("native-tests.json", lambda x: x["builds"][0]["examples"][0].update(mathematical=1))
        self.rejected()

    def test_duplicate_boundary_input(self):
        self.mutate("native-tests.json", lambda x: x["boundary_values"].__setitem__(1, 0))
        self.rejected()


if __name__ == "__main__":
    unittest.main()
