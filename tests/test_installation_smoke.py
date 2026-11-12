import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "main.py"
PROGRAM = ROOT / "config/programs/example.yaml"
SETTINGS = ROOT / "config/settings.yaml"


class TestInstallationSmoke(unittest.TestCase):

    def run_cli(self, *args):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [sys.executable, str(MAIN), *args],
                cwd=directory,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=30,
                check=False,
            )

            reports = Path(directory) / "reports"
            report_files = (
                list(reports.iterdir())
                if reports.exists()
                else []
            )

            return result, report_files

    def test_cli_help(self):
        result, files = self.run_cli("--help")

        self.assertEqual(result.returncode, 0)
        self.assertIn("--program", result.stdout)
        self.assertIn("--target", result.stdout)
        self.assertIn("--settings", result.stdout)
        self.assertIn("--nvd", result.stdout)
        self.assertEqual(files, [])

    def test_missing_arguments(self):
        result, files = self.run_cli()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required", result.stderr.lower())
        self.assertEqual(files, [])

    def test_disabled_program_prevents_scan(self):
        result, files = self.run_cli(
            "--program", str(PROGRAM),
            "--target", "example.com",
            "--settings", str(SETTINGS),
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "Scanning is disabled",
            result.stderr,
        )
        self.assertEqual(files, [])

    def test_disabled_program_prevents_nvd_scan(self):
        result, files = self.run_cli(
            "--program", str(PROGRAM),
            "--target", "example.com",
            "--settings", str(SETTINGS),
            "--nvd",
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "Scanning is disabled",
            result.stderr,
        )
        self.assertNotIn(
            "[NVD ANALYSIS] Enabled",
            result.stdout,
        )
        self.assertEqual(files, [])


if __name__ == "__main__":
    unittest.main()
