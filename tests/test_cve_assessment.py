import unittest

from core.cve_assessment import (
    CVECandidateAssessor,
    AssessmentStatus
)
from core.nvd_client import NVDSearchResult


class TestCVECandidateAssessor(unittest.TestCase):

    def make_result(
        self,
        ids=(),
        total=0,
        complete=True,
        query="OpenSSH 9.6p1"
    ):
        return NVDSearchResult(
            query=query,
            cve_ids=ids,
            total_results=total,
            complete=complete
        )

    def test_single_candidate(self):
        result = self.make_result(
            ids=("CVE-2024-12345",),
            total=1
        )

        assessment = CVECandidateAssessor.assess(
            "OpenSSH", "9.6p1", result
        )

        self.assertEqual(
            assessment.status,
            AssessmentStatus.CANDIDATE
        )
        self.assertEqual(
            assessment.candidates[0].cve_id,
            "CVE-2024-12345"
        )
        self.assertTrue(assessment.search_complete)

    def test_multiple_candidates(self):
        result = self.make_result(
            ids=(
                "CVE-2024-12345",
                "CVE-2025-67890"
            ),
            total=2
        )

        assessment = CVECandidateAssessor.assess(
            "OpenSSH", "9.6p1", result
        )

        self.assertEqual(len(assessment.candidates), 2)

    def test_no_matches_not_safe(self):
        result = self.make_result()

        assessment = CVECandidateAssessor.assess(
            "OpenSSH", "9.6p1", result
        )

        self.assertEqual(
            assessment.status,
            AssessmentStatus.UNKNOWN
        )
        self.assertEqual(assessment.candidates, ())

    def test_missing_version(self):
        assessment = CVECandidateAssessor.assess(
            "OpenSSH", None
        )

        self.assertEqual(
            assessment.status,
            AssessmentStatus.UNKNOWN
        )
        self.assertIsNone(assessment.total_results)

    def test_search_not_performed(self):
        assessment = CVECandidateAssessor.assess(
            "OpenSSH", "9.6p1"
        )

        self.assertEqual(
            assessment.status,
            AssessmentStatus.UNKNOWN
        )
        self.assertFalse(assessment.search_complete)

    def test_incomplete_results(self):
        result = self.make_result(
            ids=("CVE-2024-12345",),
            total=50,
            complete=False
        )

        assessment = CVECandidateAssessor.assess(
            "OpenSSH", "9.6p1", result
        )

        self.assertEqual(
            assessment.status,
            AssessmentStatus.CANDIDATE
        )
        self.assertFalse(assessment.search_complete)
        self.assertIn("Additional", assessment.reason)

    def test_query_mismatch_rejected(self):
        result = self.make_result(
            query="nginx 1.24.0"
        )

        with self.assertRaises(ValueError):
            CVECandidateAssessor.assess(
                "OpenSSH", "9.6p1", result
            )

    def test_invalid_cve_id_rejected(self):
        result = self.make_result(
            ids=("NOT-A-CVE",),
            total=1
        )

        with self.assertRaises(ValueError):
            CVECandidateAssessor.assess(
                "OpenSSH", "9.6p1", result
            )

    def test_duplicate_cve_rejected(self):
        result = self.make_result(
            ids=(
                "CVE-2024-12345",
                "CVE-2024-12345"
            ),
            total=2
        )

        with self.assertRaises(ValueError):
            CVECandidateAssessor.assess(
                "OpenSSH", "9.6p1", result
            )

    def test_inconsistent_result_rejected(self):
        result = self.make_result(
            ids=("CVE-2024-12345",),
            total=5,
            complete=True
        )

        with self.assertRaises(ValueError):
            CVECandidateAssessor.assess(
                "OpenSSH", "9.6p1", result
            )


if __name__ == "__main__":
    unittest.main()