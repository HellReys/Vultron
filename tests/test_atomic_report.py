import json
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

from core.scan_report import ScanReportWriter
from core.scan_orchestrator import ScanSummary
from core.tcp_scanner import TCPPortResult


class TestAtomicReport(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.output_dir = Path(self.temp_dir.name)

        self.writer = ScanReportWriter(
            output_dir=self.output_dir
        )

        self.summary = ScanSummary(
            target="example.com",
            results=(
                TCPPortResult(
                    host="example.com",
                    ip_address="1.1.1.1",
                    port=22,
                    open=True,
                    service="SSH",
                    banner="SSH-2.0-SECRET_BANNER",
                    confidence="high",
                ),
            ),
            open_ports=(22,),
            attempted_connections=1,
        )

    def write_report(self):
        return self.writer.write(
            self.summary,
            tcp_budget_used=1,
            tcp_budget_limit=10,
        )

    def test_atomic_report_is_valid_json(self):
        path = self.write_report()

        data = json.loads(
            path.read_text(encoding="utf-8")
        )

        self.assertEqual(data["target"], "example.com")
        self.assertEqual(data["total_open_ports"], 1)
        self.assertTrue(path.exists())

    def test_banner_is_redacted(self):
        path = self.write_report()
        content = path.read_text(encoding="utf-8")

        data = json.loads(content)

        self.assertEqual(
            data["results"][0]["banner"],
            "[REDACTED]",
        )

        self.assertNotIn(
            "SECRET_BANNER",
            content,
        )

    def test_no_temporary_files_after_success(self):
        self.write_report()

        self.assertEqual(
            list(self.output_dir.glob("*.tmp")),
            [],
        )

    def test_json_failure_leaves_no_report(self):
        with patch(
            "core.scan_report.json.dump",
            side_effect=ValueError("Synthetic serialization failure"),
        ):
            with self.assertRaises(ValueError):
                self.write_report()

        self.assertEqual(
            list(self.output_dir.iterdir()),
            [],
        )

        self.assertIsNone(
            self.writer.last_assessment_section
        )

    def test_existing_report_is_not_overwritten(self):
        path = self.output_dir / "existing.json"
        path.write_text(
            '{"original": true}',
            encoding="utf-8",
        )

        with self.assertRaises(FileExistsError):
            ScanReportWriter._atomic_write(
                path,
                {"new": True},
            )

        self.assertEqual(
            path.read_text(encoding="utf-8"),
            '{"original": true}',
        )

        self.assertEqual(
            sorted(p.name for p in self.output_dir.iterdir()),
            ["existing.json"],
        )


if __name__ == "__main__":
    unittest.main()
