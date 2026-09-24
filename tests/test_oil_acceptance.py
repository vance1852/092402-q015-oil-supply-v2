from __future__ import annotations

import unittest
from pathlib import Path

from oil_supply.acceptance import run


ROOT = Path(__file__).resolve().parents[1]


class OilAcceptanceTests(unittest.TestCase):
    def test_acceptance_produces_valid_evidence_package(self) -> None:
        result = run(ROOT)
        self.assertEqual(result["status"], "ok")
        evidence = result["evidence"]
        self.assertTrue(evidence["valid"])
        self.assertGreater(evidence["item_count"], 0)
        self.assertEqual(len(evidence["package_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
