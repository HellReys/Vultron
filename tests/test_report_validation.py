import copy
import json
import tempfile
import unittest
from pathlib import Path

from core.report_validation import validate_report
from core.scan_orchestrator import ScanSummary
from core.scan_report import ScanReportWriter
from core.tcp_scanner import TCPPortResult


class TestReportValidation(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.output_dir = Path(self.temp_dir.name)
        self.writer = ScanReportWriter(self.output_dir)

        self.summary = ScanSummary(
            target="example.com",
            results=(
                TCPPortResult(
                    host="example.com",
                    ip_address="1.1.1.1",
                    port=22,
                    open=True,
                    service="SSH",
                    banner="SECRET_BANNER",
                    confidence="high",
                ),
            ),
            open_ports=(22,),
            attempted_connections=1,
        )

        path = self.writer.write(
            self.summary,
            tcp_budget_used=1,
            tcp_budget_limit=10,
        )

        self.report = json.loads(
            path.read_text(encoding="utf-8")
        )

    def test_valid_report(self):
        self.assertTrue(validate_report(self.report))

    def test_unknown_field_rejected(self):
        report = copy.deepcopy(self.report)
        report["unexpected_field"] = "value"

        with self.assertRaises(ValueError):
            validate_report(report)

    def test_invalid_port_rejected(self):
        report = copy.deepcopy(self.report)
        report["results"][0]["port"] = 70000

        with self.assertRaises(ValueError):
            validate_report(report)

    def test_inconsistent_open_count_rejected(self):
        report = copy.deepcopy(self.report)
        report["total_open_ports"] = 0

        with self.assertRaises(ValueError):
            validate_report(report)

    def test_raw_banner_rejected(self):
        report = copy.deepcopy(self.report)
        report["results"][0]["banner"] = "SECRET_DATA"

        with self.assertRaises(ValueError):
            validate_report(report)

    def test_invalid_schema_version_rejected(self):
        report = copy.deepcopy(self.report)
        report["schema_version"] = 99

        with self.assertRaises(ValueError):
            validate_report(report)

    def test_oversized_report_rejected(self):
        report = copy.deepcopy(self.report)

        report["results"] = [
            {
                "port": 22,
                "status": "OPEN",
                "service": "A" * 200,
                "banner": "[REDACTED]",
                "confidence": "high",
            }
            for _ in range(4096)
        ]

        report["total_open_ports"] = 4096
        report["attempted_connections"] = 4096

        with self.assertRaisesRegex(
            ValueError, "Report size limit exceeded"
        ):
            validate_report(report)


if __name__ == "__main__":
    unittest.main()
