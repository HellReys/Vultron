import unittest

from types import SimpleNamespace
from unittest.mock import MagicMock

from core.nvd_scan_analysis import NVDScanAnalyzer
from core.nvd_client import NVDSearchResult
from core.cpe_applicability import CPEStatus


class TestNVDScanAnalyzer(unittest.TestCase):

    def make_result(
        self,
        product,
        version,
        open=True,
    ):
        return SimpleNamespace(
            open=open,
            product=product,
            version=version,
        )

    def make_client(self):
        client = MagicMock()

        client.search.return_value = NVDSearchResult(
            query="OpenSSH 9.6",
            cve_ids=("CVE-2024-12345",),
            total_results=1,
            complete=True,
        )

        return client

    def test_missing_version_skips_lookup(self):
        summary = SimpleNamespace(
            results=(
                self.make_result("OpenSSH", None),
            )
        )

        client = self.make_client()

        result = NVDScanAnalyzer.analyze(
            summary, client
        )

        self.assertIsNone(result)
        client.search.assert_not_called()

    def test_closed_port_skips_lookup(self):
        summary = SimpleNamespace(
            results=(
                self.make_result(
                    "OpenSSH", "9.6", open=False
                ),
            )
        )

        client = self.make_client()

        result = NVDScanAnalyzer.analyze(
            summary, client
        )

        self.assertIsNone(result)
        client.search.assert_not_called()

    def test_keyword_match_is_not_verified(self):
        summary = SimpleNamespace(
            results=(
                self.make_result("OpenSSH", "9.6"),
            )
        )

        client = self.make_client()

        result = NVDScanAnalyzer.analyze(
            summary, client
        )

        client.search.assert_called_once_with(
            "OpenSSH", "9.6"
        )

        self.assertFalse(result.accepted)
        self.assertEqual(
            result.summary.results[0].status,
            CPEStatus.UNKNOWN,
        )

    def test_one_lookup_for_multiple_services(self):
        summary = SimpleNamespace(
            results=(
                self.make_result("OpenSSH", "9.6"),
                self.make_result("OpenSSH", "9.6"),
                self.make_result("nginx", "1.24"),
            )
        )

        client = self.make_client()

        NVDScanAnalyzer.analyze(
            summary, client
        )

        self.assertEqual(
            client.search.call_count, 1
        )

    def test_incomplete_search_preserved(self):
        summary = SimpleNamespace(
            results=(
                self.make_result("OpenSSH", "9.6"),
            )
        )

        client = self.make_client()

        client.search.return_value = NVDSearchResult(
            query="OpenSSH 9.6",
            cve_ids=("CVE-2024-12345",),
            total_results=25,
            complete=False,
        )

        result = NVDScanAnalyzer.analyze(
            summary, client
        )

        self.assertFalse(
            result.summary.search_complete
        )


if __name__ == "__main__":
    unittest.main()