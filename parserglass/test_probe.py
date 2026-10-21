import unittest

from probe import BudgetStream, MAX_INPUT, MAX_OUTPUT, MAX_READ, corpus, elf, reference


class CorpusTests(unittest.TestCase):
    def test_complete_controls(self):
        for name in ("plain-valid", "zlib-valid", "zlib-empty-valid"):
            self.assertTrue(reference(corpus()[name])["accepted"], name)

    def test_incomplete_or_ambiguous_storage_rejected(self):
        for name, data in corpus().items():
            if name not in ("plain-valid", "zlib-valid", "zlib-empty-valid"):
                self.assertFalse(reference(data)["accepted"], name)

    def test_corpus_is_bounded_and_repeatable(self):
        self.assertEqual(corpus(), corpus())
        self.assertEqual(len(corpus()), 10)
        self.assertTrue(all(len(data) <= MAX_INPUT for data in corpus().values()))

    def test_storage_gate_precedes_read(self):
        with self.assertRaises(ValueError):
            BudgetStream(bytes(MAX_INPUT + 1))
        with self.assertRaises(ValueError):
            BudgetStream(b"abc").read(MAX_READ + 1)
        with self.assertRaises(ValueError):
            elf(b"", compressed=True, declared_size=MAX_OUTPUT + 1)

    def test_call_budget_is_enforced(self):
        stream = BudgetStream(b"x")
        for _ in range(128):
            stream.read(1)
        with self.assertRaises(ValueError):
            stream.read(1)

    def test_reference_never_accepts_header_prefix(self):
        data = corpus()["plain-valid"]
        for boundary in range(256):
            self.assertFalse(reference(data[:boundary])["accepted"], boundary)


if __name__ == "__main__":
    unittest.main()
