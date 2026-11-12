import json
import tempfile
import unittest
from pathlib import Path

from core.scan_report import ScanReportWriter
from core.scan_orchestrator import ScanSummary
from core.tcp_scanner import TCPPortResult


class TestScanReportWriter(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.output_dir = Path(self.temp_dir.name)

        self.writer = ScanReportWriter(
            self.output_dir
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
                    banner="SSH-2.0-OpenSSH_9.6",
                    confidence="high"
                ),
                TCPPortResult(
                    host="example.com",
                    ip_address="1.1.1.1",
                    port=443,
                    open=False
                )
            ),
            open_ports=(22,),
            attempted_connections=2
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_report(self):
        return self.writer.write(
            self.summary,
            tcp_budget_used=2,
            tcp_budget_limit=20
        )

    def test_report_created(self):
        path = self.write_report()

        self.assertTrue(path.exists())
        self.assertEqual(path.suffix, ".json")

    def test_report_content(self):
        path = self.write_report()

        data = json.loads(
            path.read_text(encoding="utf-8")
        )

        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["target"], "example.com")
        self.assertEqual(data["total_open_ports"], 1)
        self.assertEqual(data["attempted_connections"], 2)

        self.assertEqual(
            data["tcp_budget"],
            {"used": 2, "limit": 20}
        )

        self.assertEqual(
            data["results"][0]["service"],
            "SSH"
        )

        self.assertEqual(
            data["results"][0]["confidence"],
            "high"
        )

        self.assertEqual(
            data["results"][1]["status"],
            "NOT_OPEN"
        )

    def test_timestamp_is_utc(self):
        path = self.write_report()

        data = json.loads(
            path.read_text(encoding="utf-8")
        )

        self.assertTrue(
            data["scan_timestamp"].endswith("+00:00")
        )

    def test_target_filename_sanitized(self):
        self.assertEqual(
            ScanReportWriter._safe_target(
                "../example.com"
            ),
            "example.com"
        )

        self.assertEqual(
            ScanReportWriter._safe_target(
                "api/example.com"
            ),
            "api_example.com"
        )

    def test_invalid_budget_rejected(self):
        with self.assertRaises(ValueError):
            self.writer.write(
                self.summary,
                tcp_budget_used=21,
                tcp_budget_limit=20
            )

    def test_boolean_budget_rejected(self):
        with self.assertRaises(ValueError):
            self.writer.write(
                self.summary,
                tcp_budget_used=True,
                tcp_budget_limit=20
            )

    def test_report_has_no_policy_secrets(self):
        path = self.write_report()

        data = json.loads(
            path.read_text(encoding="utf-8")
        )

        self.assertNotIn("api_key", data)
        self.assertNotIn("headers", data)
        self.assertNotIn("authorization", data)

    def test_distinct_report_filenames(self):
        first = self.write_report()
        second = self.write_report()

        self.assertNotEqual(first, second)
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())

    def test_default_cve_section(self):
        path = self.write_report()

        data = json.loads(
            path.read_text(encoding="utf-8")
        )

        section = data["cve_assessment"]

        self.assertEqual(
            section["status"],
            "NOT_PERFORMED",
        )

        self.assertFalse(
            section["vulnerability_confirmed"]
        )

        self.assertEqual(section["results"], [])

    def test_report_rejects_invalid_assessment(self):
        with self.assertRaises(ValueError):
            self.writer.write(
                self.summary,
                tcp_budget_used=2,
                tcp_budget_limit=20,
                assessment="invalid",
            )

    def test_banner_is_not_exported_raw(self):
        path = self.write_report()

        data = json.loads(
            path.read_text(encoding="utf-8")
        )

        self.assertEqual(
            data["results"][0]["banner"],
            "[REDACTED]",
        )

        self.assertNotIn(
            "SSH-2.0-OpenSSH_9.6",
            path.read_text(encoding="utf-8"),
        )

    def test_invalid_tcp_data_creates_no_file(self):
        from types import SimpleNamespace

        original = self.summary

        invalid = SimpleNamespace(
            target=original.target,
            results=(
                SimpleNamespace(
                    port=70000,
                    open=True,
                    service="SSH",
                    banner=None,
                    confidence="high",
                ),
            ),
            open_ports=(70000,),
            attempted_connections=1,
        )

        with self.assertRaises(ValueError):
            self.writer.write(
                invalid,
                tcp_budget_used=1,
                tcp_budget_limit=20,
            )

        self.assertEqual(
            list(self.output_dir.iterdir()),
            [],
        )


    def test_untrusted_service_sanitized_in_report(self):
        from types import SimpleNamespace

        summary = SimpleNamespace(
            target="example.com",
            results=(
                SimpleNamespace(
                    port=22,
                    open=True,
                    service="SSH\nFAKE_SERVICE",
                    banner="SECRET_BANNER",
                    confidence="high",
                ),
            ),
            open_ports=(22,),
            attempted_connections=1,
        )

        path = self.writer.write(
            summary,
            tcp_budget_used=1,
            tcp_budget_limit=10,
        )

        data = json.loads(
            path.read_text(encoding="utf-8")
        )

        self.assertNotIn(
            "\n",
            data["results"][0]["service"],
        )

        self.assertEqual(
            data["results"][0]["banner"],
            "[REDACTED]",
        )


if __name__ == "__main__":
    unittest.main()