import io
import unittest
from contextlib import redirect_stdout, redirect_stderr
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from core.policy_engine import PolicyEngine

import main


class TestMainCLI(unittest.TestCase):

    def setUp(self):
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()

    def test_missing_arguments(self):
        with redirect_stderr(self.stderr):
            with self.assertRaises(SystemExit) as result:
                main.main([])

        self.assertEqual(result.exception.code, 2)

    def test_help_command(self):
        with redirect_stdout(self.stdout):
            with self.assertRaises(SystemExit) as result:
                main.main(["--help"])

        self.assertEqual(result.exception.code, 0)
        self.assertIn(
            "--program",
            self.stdout.getvalue()
        )

    @patch("main.run_scan")
    def test_cli_passes_arguments(self, mock_run):
        with redirect_stdout(self.stdout):
            result = main.main([
                "--program", "config/programs/example.yaml",
                "--target", "example.com"
            ])

        self.assertEqual(result, 0)

        mock_run.assert_called_once_with(
            program_path="config/programs/example.yaml",
            target="example.com",
            settings_path="config/settings.yaml"
        )

    @patch("main.run_scan")
    def test_custom_settings_path(self, mock_run):
        with redirect_stdout(self.stdout):
            result = main.main([
                "--program", "program.yaml",
                "--target", "example.com",
                "--settings", "custom.yaml"
            ])

        self.assertEqual(result, 0)

        self.assertEqual(
            mock_run.call_args.kwargs["settings_path"],
            "custom.yaml"
        )

    @patch("main.run_scan")
    def test_permission_error(self, mock_run):
        mock_run.side_effect = PermissionError(
            "Scanning disabled."
        )

        with redirect_stderr(self.stderr):
            result = main.main([
                "--program", "program.yaml",
                "--target", "example.com"
            ])

        self.assertEqual(result, 1)
        self.assertIn(
            "Scanning disabled",
            self.stderr.getvalue()
        )

    @patch("main.run_scan")
    def test_invalid_config_error(self, mock_run):
        mock_run.side_effect = ValueError(
            "Invalid configuration."
        )

        with redirect_stderr(self.stderr):
            result = main.main([
                "--program", "program.yaml",
                "--target", "example.com"
            ])

        self.assertEqual(result, 1)

    @patch("main.ScanOrchestrator")
    @patch("main.ProgramContext")
    @patch("main.PolicyEngine")
    @patch("main.ConfigurationManager")
    def test_disabled_policy_prevents_scan(
        self,
        mock_config,
        mock_policy,
        mock_context,
        mock_orchestrator
    ):
        mock_config.return_value.load.return_value = (
            SimpleNamespace(
                app=SimpleNamespace(name="Vultron")
            )
        )

        mock_policy.return_value.can_scan.return_value = False

        with redirect_stderr(self.stderr):
            result = main.main([
                "--program", "program.yaml",
                "--target", "example.com"
            ])

        self.assertEqual(result, 1)
        mock_context.assert_not_called()
        mock_orchestrator.assert_not_called()

    @patch("main.ScanOrchestrator")
    @patch("main.ProgramContext")
    @patch("main.PolicyEngine")
    @patch("main.ConfigurationManager")
    def test_tcp_disabled_prevents_scan(
        self,
        mock_config,
        mock_policy,
        mock_context,
        mock_orchestrator
    ):
        mock_config.return_value.load.return_value = (
            SimpleNamespace(
                app=SimpleNamespace(name="Vultron")
            )
        )

        policy = mock_policy.return_value
        policy.can_scan.return_value = True

        policy.tcp_policy.enabled = False

        with redirect_stderr(self.stderr):
            result = main.main([
                "--program", "program.yaml",
                "--target", "example.com"
            ])

        self.assertEqual(result, 1)
        mock_context.assert_not_called()
        mock_orchestrator.assert_not_called()

    @patch("main.ScanOrchestrator")
    @patch("main.ProgramContext")
    @patch("main.PolicyEngine")
    @patch("main.ConfigurationManager")
    def test_successful_scan_flow(
        self,
        mock_config,
        mock_policy,
        mock_context,
        mock_orchestrator
    ):
        mock_config.return_value.load.return_value = (
            SimpleNamespace(
                app=SimpleNamespace(name="Vultron")
            )
        )

        policy = mock_policy.return_value
        policy.can_scan.return_value = True
        policy.tcp_policy.enabled = True
        policy.tcp_policy.allowed_ports = (80, 443)

        context = mock_context.return_value
        context.tcp_budget.used = 2
        context.tcp_budget.max_requests = 20

        summary = SimpleNamespace(
            target="example.com",
            attempted_connections=2,
            open_ports=(80,),
            results=(
                SimpleNamespace(
                    port=80,
                    open=True,
                    service="HTTP",
                    banner="HTTP/1.1 200 OK",
                    confidence="high"
                ),
                SimpleNamespace(
                    port=443,
                    open=False,
                    service="Unknown",
                    banner="",
                    confidence="none"
                )
            )
        )

        mock_orchestrator.return_value.scan_tcp.return_value = (
            summary
        )

        with patch("main.ScanReportWriter") as mock_reporter:
            mock_reporter.return_value.write.return_value = (
                "reports/test_report.json"
            )

            with redirect_stdout(self.stdout):
                result = main.main([
                    "--program", "program.yaml",
                    "--target", "example.com"
                ])

            mock_reporter.return_value.write.assert_called_once()

        self.assertEqual(result, 0)

        mock_orchestrator.assert_called_once_with(context)
        mock_orchestrator.return_value.scan_tcp.assert_called_once_with(
            "example.com"
        )

        self.assertIn(
            "80       OPEN",
            self.stdout.getvalue()
        )

        self.assertIn(
            "HTTP",
            self.stdout.getvalue()
        )

        self.assertIn(
            "[REPORT] Saved to:",
            self.stdout.getvalue()
        )

    def test_example_program_is_disabled(self):
        policy = PolicyEngine(
            "config/programs/example.yaml"
        )

        self.assertFalse(policy.can_scan())
        self.assertFalse(policy.tcp_policy.enabled)

    @patch("main.run_scan")
    def test_nvd_flag_passed_to_runner(self, mock_run):
        with redirect_stdout(self.stdout):
            result = main.main([
                "--program", "program.yaml",
                "--target", "example.com",
                "--nvd",
            ])

        self.assertEqual(result, 0)

        self.assertTrue(
            mock_run.call_args.kwargs["nvd_enabled"]
        )

    @patch("main.run_scan")
    def test_nvd_disabled_by_default(self, mock_run):
        with redirect_stdout(self.stdout):
            result = main.main([
                "--program", "program.yaml",
                "--target", "example.com",
            ])

        self.assertEqual(result, 0)

        self.assertNotIn(
            "nvd_enabled",
            mock_run.call_args.kwargs,
        )

    @patch("main.run_scan")
    def test_nvd_requires_normal_cli_arguments(
        self, mock_run
    ):
        with redirect_stderr(self.stderr):
            with self.assertRaises(SystemExit):
                main.main(["--nvd"])

        mock_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()