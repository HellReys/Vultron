import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import main
from core.version import __version__


class TestVultronVersion(unittest.TestCase):

    def test_release_candidate_version(self):
        self.assertEqual(__version__, "2.0.0rc1")

    def test_version_argument(self):
        output = io.StringIO()

        with redirect_stdout(output):
            with self.assertRaises(SystemExit) as result:
                main.main(["--version"])

        self.assertEqual(result.exception.code, 0)
        self.assertEqual(
            output.getvalue().strip(),
            "Vultron 2.0.0rc1",
        )

    def test_version_does_not_start_scan(self):
        with patch("main.run_scan") as mock_scan:
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit):
                    main.main(["--version"])

            mock_scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
