
import unittest

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import MagicMock

from core.assessment_report import AssessmentReport
from core.nvd_client import NVDSearchResult, NVDError
from core.nvd_scan_analysis import (
    analyze_nvd_batch,
    NVDScanBatch,
)
from core.nvd_report_integrity import validate_nvd_batch


class TestNVDReportIntegrity(unittest.TestCase):

    @staticmethod
    def make_summary(identities):
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

    @staticmethod
    def make_client(cve_ids=("CVE-2024-12345",)):
        client = MagicMock()

        def search(product, version):
            return NVDSearchResult(
                query=f"{product} {version}",
                cve_ids=cve_ids,
                total_results=len(cve_ids),
                complete=True,
            )

        client.search.side_effect = search
        return client

    def make_complete_batch(self):
        return analyze_nvd_batch(
            self.make_summary([
                ("OpenSSH", "9.6"),
            ]),
            self.make_client(),
        )

    def test_valid_complete_batch(self):
        batch = self.make_complete_batch()

        self.assertTrue(validate_nvd_batch(batch))

        report = AssessmentReport.build(batch)

        self.assertEqual(report["status"], "COMPLETE")
        self.assertFalse(report["vulnerability_confirmed"])

    def test_no_eligible_services(self):
        batch = analyze_nvd_batch(
            self.make_summary([
                ("OpenSSH", None),
            ]),
            self.make_client(),
        )

        report = AssessmentReport.build(batch)

        self.assertEqual(
            report["status"],
            "NO_ELIGIBLE_SERVICES",
        )
        self.assertEqual(report["attempted_queries"], 0)
        self.assertEqual(report["results"], [])

    def test_empty_cve_search_is_not_a_finding(self):
        batch = analyze_nvd_batch(
            self.make_summary([
                ("OpenSSH", "9.6"),
            ]),
            self.make_client(cve_ids=()),
        )

        report = AssessmentReport.build(batch)

        self.assertEqual(report["status"], "COMPLETE")
        self.assertEqual(report["results"], [])
        self.assertEqual(
            report["confirmed_vulnerabilities"], 0
        )

    def test_false_complete_with_omitted_services(self):
        batch = replace(
            self.make_complete_batch(),
            omitted_services=1,
        )

        with self.assertRaises(ValueError):
            AssessmentReport.build(batch)

    def test_query_counter_mismatch_rejected(self):
        batch = replace(
            self.make_complete_batch(),
            attempted_queries=2,
        )

        with self.assertRaises(ValueError):
            AssessmentReport.build(batch)

    def test_boolean_query_counter_rejected(self):
        batch = replace(
            self.make_complete_batch(),
            attempted_queries=True,
        )

        with self.assertRaises(ValueError):
            AssessmentReport.build(batch)

    def test_failed_batch_cannot_be_complete(self):
        client = self.make_client()
        client.search.side_effect = NVDError(
            "PRIVATE_NVD_ERROR_DETAILS"
        )

        batch = analyze_nvd_batch(
            self.make_summary([
                ("OpenSSH", "9.6"),
            ]),
            client,
        )

        report = AssessmentReport.build(batch)

        self.assertEqual(report["status"], "ERROR")

        self.assertNotIn(
            "PRIVATE_NVD_ERROR_DETAILS",
            str(report),
        )

        corrupted = replace(
            batch,
            status="COMPLETE",
            search_complete=True,
        )

        with self.assertRaises(ValueError):
            AssessmentReport.build(corrupted)

    def test_invalid_error_code_rejected(self):
        client = self.make_client()
        client.search.side_effect = NVDError("Failed")

        batch = analyze_nvd_batch(
            self.make_summary([
                ("OpenSSH", "9.6"),
            ]),
            client,
        )

        corrupted_entry = replace(
            batch.entries[0],
            error_code="UNEXPECTED_INTERNAL_ERROR",
        )

        corrupted = replace(
            batch,
            entries=(corrupted_entry,),
        )

        with self.assertRaises(ValueError):
            AssessmentReport.build(corrupted)


if __name__ == "__main__":
    unittest.main()
