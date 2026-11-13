import json
import tempfile
import unittest
from pathlib import Path

from core.http_probe import HTTPProbeResult
from core.http_report import build_http_report
from core.report_validation import validate_report
from core.scan_orchestrator import ScanSummary
from core.scan_report import ScanReportWriter
from core.service_fingerprint import ServiceFingerprint
from core.tcp_scanner import TCPPortResult


class TestHTTPReporting(unittest.TestCase):

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)

        self.writer = ScanReportWriter(Path(temp.name))

        self.summary = ScanSummary(
            target="example.com",
            results=(
                TCPPortResult(
                    host="example.com",
                    ip_address="1.1.1.1",
                    port=443,
                    open=True,
                    service="Unknown",
                    confidence="none",
                ),
            ),
            open_ports=(443,),
            attempted_connections=1,
        )

    def make_http_result(self):
        return HTTPProbeResult(
            port=443,
            status="OK",
            fingerprint=ServiceFingerprint(
                service="HTTPS",
                banner="",
                confidence="medium",
                product="nginx",
                version="1.24.0",
                version_source=(
                    "http_server_header_unverified"
                ),
            ),
        )

    def write(self, http_results=None):
        path = self.writer.write(
            self.summary,
            tcp_budget_used=1,
            tcp_budget_limit=1,
            http_results=http_results,
        )
        return json.loads(path.read_text(encoding="utf-8"))

    def test_tcp_only_report_keeps_schema_one(self):
        report = self.write()

        self.assertEqual(report["schema_version"], 1)
        self.assertNotIn("http_fingerprints", report)

    def test_http_report_uses_schema_two(self):
        report = self.write((self.make_http_result(),))

        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(
            report["http_fingerprints"][0]["product"],
            "nginx",
        )
        self.assertFalse(
            report["http_fingerprints"][0]["evidence_verified"]
        )
        self.assertTrue(validate_report(report))

    def test_empty_http_results(self):
        report = self.write(())

        self.assertEqual(report["schema_version"], 2)
        self.assertEqual(report["http_fingerprints"], [])

    def test_untrusted_header_data_not_exported(self):
        result = HTTPProbeResult(
            port=443,
            status="OK",
            fingerprint=ServiceFingerprint(
                service="HTTPS",
                banner="session=SECRET_TOKEN",
                confidence="medium",
                product="UntrustedProxy",
                version="SECRET_TOKEN",
                version_source="untrusted",
            ),
        )

        report = self.write((result,))
        serialized = json.dumps(report)

        self.assertNotIn("SECRET_TOKEN", serialized)
        self.assertNotIn("UntrustedProxy", serialized)
        self.assertIsNone(
            report["http_fingerprints"][0]["product"]
        )

    def test_failed_http_probe(self):
        result = HTTPProbeResult(
            port=443,
            status="NETWORK_ERROR",
        )

        report = self.write((result,))

        self.assertEqual(
            report["http_fingerprints"][0]["status"],
            "NETWORK_ERROR",
        )
        self.assertIsNone(
            report["http_fingerprints"][0]["service"]
        )

    def test_duplicate_http_port_rejected(self):
        result = self.make_http_result()

        with self.assertRaises(ValueError):
            build_http_report((result, result))

    def test_invalid_verified_evidence_rejected(self):
        report = self.write((self.make_http_result(),))

        report["http_fingerprints"][0][
            "evidence_verified"
        ] = True

        with self.assertRaises(ValueError):
            validate_report(report)


if __name__ == "__main__":
    unittest.main()
