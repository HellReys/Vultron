
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from core.assessment_report import AssessmentReport
from core.nvd_client import (
    NVDError,
    NVDRateLimitError,
    NVDSearchResult,
)
from core.nvd_scan_analysis import (
    analyze_nvd_batch,
)


class TestNVDScanBatch(unittest.TestCase):

    def make_summary(self, identities):
        return SimpleNamespace(
            results=tuple(
                SimpleNamespace(
                    open=True,
                    product=product,
                    version=version,
                )
                for product, version in identities
            )
        )

    def make_client(self):
        client = MagicMock()

        def search(product, version):
            return NVDSearchResult(
                query=f"{product} {version}",
                cve_ids=("CVE-2024-12345",),
                total_results=1,
                complete=True,
            )

        client.search.side_effect = search
        return client

    def test_three_unique_services(self):
        summary = self.make_summary([
            ("OpenSSH", "9.6"),
            ("nginx", "1.24"),
            ("Apache", "2.4"),
        ])

        client = self.make_client()
        result = analyze_nvd_batch(summary, client)

        self.assertEqual(result.status, "COMPLETE")
        self.assertEqual(result.attempted_queries, 3)
        self.assertEqual(client.search.call_count, 3)

    def test_duplicate_services_not_queried(self):
        summary = self.make_summary([
            ("OpenSSH", "9.6"),
            ("OpenSSH", "9.6"),
        ])

        client = self.make_client()
        result = analyze_nvd_batch(summary, client)

        self.assertEqual(result.attempted_queries, 1)
        self.assertEqual(client.search.call_count, 1)

    def test_query_limit_creates_partial_result(self):
        summary = self.make_summary([
            ("ProductA", "1.0"),
            ("ProductB", "2.0"),
            ("ProductC", "3.0"),
            ("ProductD", "4.0"),
        ])

        client = self.make_client()
        result = analyze_nvd_batch(summary, client)

        self.assertEqual(result.status, "PARTIAL")
        self.assertEqual(result.omitted_services, 1)
        self.assertEqual(client.search.call_count, 3)

    def test_api_failure_is_reported(self):
        summary = self.make_summary([
            ("OpenSSH", "9.6"),
        ])

        client = self.make_client()
        client.search.side_effect = NVDError(
            "Temporary API failure"
        )

        result = analyze_nvd_batch(summary, client)
        section = AssessmentReport.build(result)

        self.assertEqual(result.status, "ERROR")
        self.assertEqual(section["failed_queries"], 1)
        self.assertEqual(
            section["errors"][0]["code"],
            "LOOKUP_FAILED",
        )
        self.assertFalse(section["vulnerability_confirmed"])

    def test_rate_limit_stops_remaining_queries(self):
        summary = self.make_summary([
            ("OpenSSH", "9.6"),
            ("nginx", "1.24"),
            ("Apache", "2.4"),
        ])

        client = self.make_client()
        client.search.side_effect = NVDRateLimitError(
            "Rate limited"
        )

        result = analyze_nvd_batch(summary, client)

        self.assertEqual(result.status, "ERROR")
        self.assertEqual(result.attempted_queries, 1)
        self.assertEqual(result.omitted_services, 2)
        self.assertEqual(client.search.call_count, 1)

    def test_invalid_query_limit_rejected(self):
        summary = self.make_summary([
            ("OpenSSH", "9.6")
        ])

        client = self.make_client()

        for limit in (0, 4, -1, True):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    analyze_nvd_batch(
                        summary,
                        client,
                        max_queries=limit,
                    )


if __name__ == "__main__":
    unittest.main()
