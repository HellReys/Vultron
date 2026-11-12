
import io
import json
import tempfile
import unittest

from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import main

from core.nvd_client import (
    NVDError,
    NVDRateLimitError,
    NVDSearchResult,
)
from core.scan_report import ScanReportWriter


class TestNVDEndToEnd(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.output_dir = Path(self.temp_dir.name)
        self.stdout = io.StringIO()

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)

        config = self.stack.enter_context(
            patch("main.ConfigurationManager")
        )
        policy_class = self.stack.enter_context(
            patch("main.PolicyEngine")
        )
        context_class = self.stack.enter_context(
            patch("main.ProgramContext")
        )
        orchestrator_class = self.stack.enter_context(
            patch("main.ScanOrchestrator")
        )
        self.nvd_class = self.stack.enter_context(
            patch("main.NVDClient")
        )

        self.stack.enter_context(
            patch(
                "main.ScanReportWriter",
                side_effect=lambda: ScanReportWriter(
                    output_dir=self.output_dir
                ),
            )
        )

        config.return_value.load.return_value = (
            SimpleNamespace(
                app=SimpleNamespace(name="Vultron")
            )
        )

        self.policy = policy_class.return_value
        self.policy.can_scan.return_value = True
        self.policy.tcp_policy.enabled = True
        self.policy.tcp_policy.allowed_ports = (22, 80, 443)

        context = context_class.return_value
        context.tcp_budget.used = 3
        context.tcp_budget.max_requests = 20

        self.orchestrator = orchestrator_class.return_value
        self.orchestrator.scan_tcp.return_value = (
            self.make_summary()
        )

        self.client = self.nvd_class.return_value
        self.client.search.side_effect = self.search_success

    @staticmethod
    def make_port(port, product, version):
        return SimpleNamespace(
            port=port,
            open=True,
            service=product,
            product=product,
            version=version,
            banner="Synthetic test banner",
            confidence="high",
        )

    def make_summary(self):
        return SimpleNamespace(
            target="example.test",
            attempted_connections=3,
            open_ports=(22, 80, 443),
            results=(
                self.make_port(22, "OpenSSH", "9.6"),
                self.make_port(80, "nginx", "1.24"),
                self.make_port(443, "Apache", "2.4"),
            ),
        )

    @staticmethod
    def search_success(product, version):
        return NVDSearchResult(
            query=f"{product} {version}",
            cve_ids=("CVE-2024-12345",),
            total_results=1,
            complete=True,
        )

    def execute_cli(self, enable_nvd=True):
        arguments = [
            "--program", "synthetic-policy.yaml",
            "--target", "example.test",
        ]

        if enable_nvd:
            arguments.append("--nvd")

        with redirect_stdout(self.stdout):
            result = main.main(arguments)

        return result

    def read_report(self):
        paths = list(
            self.output_dir.glob("*.json")
        )

        self.assertEqual(len(paths), 1)

        return json.loads(
            paths[0].read_text(encoding="utf-8")
        )

    def test_disabled_nvd_does_not_contact_api(self):
        result = self.execute_cli(enable_nvd=False)
        report = self.read_report()

        self.assertEqual(result, 0)
        self.nvd_class.assert_not_called()

        self.assertEqual(
            report["cve_assessment"]["status"],
            "NOT_PERFORMED",
        )

        self.assertIn(
            "Status: NOT_PERFORMED",
            self.stdout.getvalue(),
        )

    def test_complete_batch_saved_to_json(self):
        result = self.execute_cli()
        report = self.read_report()
        section = report["cve_assessment"]

        self.assertEqual(result, 0)
        self.assertEqual(
            self.client.search.call_count, 3
        )
        self.assertEqual(
            section["status"], "COMPLETE"
        )
        self.assertEqual(
            section["attempted_queries"], 3
        )
        self.assertEqual(
            len(section["results"]), 3
        )

        self.assertTrue(all(
            item["applicability"] == "UNKNOWN"
            for item in section["results"]
        ))

        self.assertFalse(
            section["vulnerability_confirmed"]
        )

        self.assertEqual(
            report["total_open_ports"], 3
        )

        self.assertEqual(
            len(report["results"]), 3
        )

        self.assertIn(
            "Status: COMPLETE",
            self.stdout.getvalue(),
        )

        self.assertIn(
            "Confirmed vulnerabilities: 0",
            self.stdout.getvalue(),
        )

        self.client.session.close.assert_called_once()

    def test_partial_batch_saved_to_json(self):
        self.orchestrator.scan_tcp.return_value = (
            SimpleNamespace(
                target="example.test",
                attempted_connections=4,
                open_ports=(22, 80, 443, 8080),
                results=(
                    self.make_port(22, "OpenSSH", "9.6"),
                    self.make_port(80, "nginx", "1.24"),
                    self.make_port(443, "Apache", "2.4"),
                    self.make_port(8080, "Tomcat", "10.0"),
                ),
            )
        )

        result = self.execute_cli()
        report = self.read_report()
        section = report["cve_assessment"]

        self.assertEqual(result, 0)
        self.assertEqual(
            section["status"], "PARTIAL"
        )
        self.assertEqual(
            section["omitted_services"], 1
        )
        self.assertEqual(
            self.client.search.call_count, 3
        )

        self.assertIn(
            "Status: PARTIAL",
            self.stdout.getvalue(),
        )

    def test_nvd_failure_preserves_tcp_report(self):
        self.client.search.side_effect = NVDError(
            "Synthetic NVD API failure"
        )

        result = self.execute_cli()
        report = self.read_report()
        section = report["cve_assessment"]

        self.assertEqual(result, 0)
        self.assertEqual(
            section["status"], "ERROR"
        )
        self.assertEqual(
            section["failed_queries"], 3
        )

        self.assertEqual(
            len(report["results"]), 3
        )
        self.assertEqual(
            report["tcp_budget"]["used"], 3
        )

        self.assertNotIn(
            "Synthetic NVD API failure",
            json.dumps(report),
        )

        self.assertIn(
            "Status: ERROR",
            self.stdout.getvalue(),
        )

    def test_rate_limit_stops_queries(self):
        self.client.search.side_effect = (
            NVDRateLimitError(
                "Synthetic rate limit"
            )
        )

        result = self.execute_cli()
        report = self.read_report()
        section = report["cve_assessment"]

        self.assertEqual(result, 0)
        self.assertEqual(
            section["status"], "ERROR"
        )
        self.assertEqual(
            section["attempted_queries"], 1
        )
        self.assertEqual(
            section["omitted_services"], 2
        )
        self.assertEqual(
            self.client.search.call_count, 1
        )



    def test_nvd_constructor_failure_preserves_report(self):
        self.nvd_class.side_effect = NVDError(
            "PRIVATE_CONNECTION_DETAILS"
        )

        result = self.execute_cli()
        report = self.read_report()

        self.assertEqual(result, 0)
        self.assertEqual(
            report["cve_assessment"]["status"],
            "ERROR",
        )
        self.assertEqual(len(report["results"]), 3)

        self.assertNotIn(
            "PRIVATE_CONNECTION_DETAILS",
            self.stdout.getvalue(),
        )

        self.assertNotIn(
            "PRIVATE_CONNECTION_DETAILS",
            json.dumps(report),
        )

    def test_invalid_nvd_configuration_preserves_report(self):
        self.nvd_class.side_effect = ValueError(
            "Invalid synthetic NVD configuration"
        )

        result = self.execute_cli()
        report = self.read_report()

        self.assertEqual(result, 0)
        self.assertEqual(
            report["cve_assessment"]["status"],
            "ERROR",
        )
        self.assertEqual(len(report["results"]), 3)

    def test_nvd_cleanup_error_preserves_report(self):
        self.client.session.close.side_effect = OSError(
            "Synthetic connection cleanup failure"
        )

        result = self.execute_cli()
        report = self.read_report()

        self.assertEqual(result, 0)
        self.assertEqual(
            report["cve_assessment"]["status"],
            "COMPLETE",
        )
        self.assertEqual(len(report["results"]), 3)

        self.assertIn(
            "NVD connection cleanup failed",
            self.stdout.getvalue(),
        )

    def test_untrusted_banner_is_safe_in_terminal(self):
        summary = self.make_summary()

        malicious_port = SimpleNamespace(
            port=22,
            open=True,
            service="OpenSSH\nFAKE_SERVICE",
            product="OpenSSH",
            version="9.6",
            banner="\x1b[31mFAKE_ALERT\nNEXT_LINE",
            confidence="high",
        )

        self.orchestrator.scan_tcp.return_value = (
            SimpleNamespace(
                target=summary.target,
                attempted_connections=3,
                open_ports=summary.open_ports,
                results=(
                    malicious_port,
                    *summary.results[1:],
                ),
            )
        )

        result = self.execute_cli(enable_nvd=False)
        output = self.stdout.getvalue()
        report = self.read_report()

        self.assertEqual(result, 0)

        self.assertNotIn("\x1b", output)
        self.assertNotIn("\nFAKE_SERVICE", output)
        self.assertNotIn("\nNEXT_LINE", output)

        self.assertEqual(
            report["cve_assessment"]["status"],
            "NOT_PERFORMED",
        )

if __name__ == "__main__":
    unittest.main()
