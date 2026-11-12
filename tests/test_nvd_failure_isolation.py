
import io
import json
import tempfile
import unittest

from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch

from core.nvd_scan_analysis import (
    analyze_nvd_batch,
)
from core.nvd_client import NVDSearchResult
from core.scan_report import ScanReportWriter
import test_nvd_end_to_end as e2e_tests


class TestNVDFailureIsolation(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.writer = ScanReportWriter(
            output_dir=self.temp_dir.name
        )

        self.helper = e2e_tests.TestNVDEndToEnd()
        self.helper.setUp()
        self.addCleanup(self.helper.doCleanups)

        self.summary = self.helper.make_summary()

    def make_batch(self):
        client = MagicMock()

        def search(product, version):
            return NVDSearchResult(
                query=f"{product} {version}",
                cve_ids=("CVE-2024-12345",),
                total_results=1,
                complete=True,
            )

        client.search.side_effect = search

        return analyze_nvd_batch(
            self.summary,
            client,
        )

    def write_and_read(self, batch):
        path = self.writer.write(
            self.summary,
            tcp_budget_used=3,
            tcp_budget_limit=20,
            assessment=batch,
        )

        return json.loads(
            path.read_text(encoding="utf-8")
        )

    def test_corrupt_counter_preserves_tcp(self):
        batch = replace(
            self.make_batch(),
            attempted_queries=99,
        )

        data = self.write_and_read(batch)

        self.assertEqual(
            data["cve_assessment"]["status"],
            "ERROR",
        )
        self.assertEqual(
            data["cve_assessment"]["errors"][0]["code"],
            "REPORT_VALIDATION_FAILED",
        )
        self.assertEqual(len(data["results"]), 3)
        self.assertEqual(
            data["tcp_budget"]["used"], 3
        )

    def test_control_character_is_not_exported(self):
        batch = self.make_batch()
        bad_entry = replace(
            batch.entries[0],
            product="OpenSSH\nPRIVATE_DATA",
        )

        batch = replace(
            batch,
            entries=(bad_entry,) + batch.entries[1:],
        )

        data = self.write_and_read(batch)
        serialized = json.dumps(data)

        self.assertEqual(
            data["cve_assessment"]["status"],
            "ERROR",
        )
        self.assertNotIn(
            "PRIVATE_DATA", serialized
        )

    def test_oversized_identity_is_not_exported(self):
        batch = self.make_batch()

        bad_entry = replace(
            batch.entries[0],
            version="X" * 101,
        )

        batch = replace(
            batch,
            entries=(bad_entry,) + batch.entries[1:],
        )

        data = self.write_and_read(batch)

        self.assertEqual(
            data["cve_assessment"]["status"],
            "ERROR",
        )
        self.assertNotIn(
            "X" * 101,
            json.dumps(data),
        )

    def test_corrupt_nvd_cli_report_is_consistent(self):
        from unittest.mock import patch

        helper = self.helper
        original_batch = self.make_batch()
        bad_batch = replace(
            original_batch,
            attempted_queries=99,
        )

        with patch(
            "main.analyze_nvd_batch",
            return_value=bad_batch,
        ):
            with redirect_stdout(helper.stdout):
                result = __import__("main").main([
                    "--program", "synthetic-policy.yaml",
                    "--target", "example.test",
                    "--nvd",
                ])

        self.assertEqual(result, 0)

        paths = list(
            helper.output_dir.glob("*.json")
        )
        self.assertEqual(len(paths), 1)

        data = json.loads(
            paths[0].read_text(encoding="utf-8")
        )

        self.assertEqual(
            data["cve_assessment"]["status"],
            "ERROR",
        )
        self.assertEqual(len(data["results"]), 3)
        self.assertIn(
            "Status: ERROR",
            helper.stdout.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
