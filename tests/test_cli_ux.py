import io
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

import main
from core.request_budget import RequestBudgetExceeded


class TestCLIUserExperience(unittest.TestCase):

    @patch("main.run_scan")
    def test_error_control_characters_are_sanitized(self, mock_run):
        mock_run.side_effect = ValueError(
            "Invalid configuration\nFAKE_SUCCESS"
        )

        output = io.StringIO()

        with redirect_stderr(output):
            result = main.main([
                "--program", "program.yaml",
                "--target", "example.com",
            ])

        message = output.getvalue()

        self.assertEqual(result, 1)
        self.assertIn(
            "[ERROR] Invalid configuration",
            message,
        )
        self.assertNotIn("\nFAKE_SUCCESS", message)
        self.assertEqual(message.count("\n"), 1)

    @patch("main.run_scan")
    def test_error_length_is_limited(self, mock_run):
        mock_run.side_effect = OSError("X" * 1000)

        output = io.StringIO()

        with redirect_stderr(output):
            result = main.main([
                "--program", "program.yaml",
                "--target", "example.com",
            ])

        self.assertEqual(result, 1)
        self.assertLessEqual(
            len(output.getvalue().strip()),
            len("[ERROR] ") + 200,
        )

    @patch("main.run_scan")
    def test_http_budget_error_is_handled(self, mock_run):
        mock_run.side_effect = RequestBudgetExceeded(
            "Scan request budget exhausted: 1/1"
        )

        output = io.StringIO()

        with redirect_stderr(output):
            result = main.main([
                "--program", "program.yaml",
                "--target", "example.com",
                "--http-fingerprint",
            ])

        self.assertEqual(result, 1)
        self.assertIn(
            "[ERROR] Scan request budget exhausted: 1/1",
            output.getvalue(),
        )



if __name__ == "__main__":
    unittest.main()
