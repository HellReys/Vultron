import unittest

from core.cve_applicability import (
    CVEApplicabilityAssessor,
)
from core.cpe_applicability import CPEStatus
from core.cve_assessment import CVECandidateAssessor
from core.nvd_client import (
    NVDSearchResult,
    NVDCVERecord,
)


class TestCVEApplicabilityAssessor(unittest.TestCase):

    OBSERVED = (
        "cpe:2.3:a:example:server:1.0:"
        "*:*:*:*:*:*:*"
    )

    OTHER = (
        "cpe:2.3:a:example:other:2.0:"
        "*:*:*:*:*:*:*"
    )

    CVE_ID = "CVE-2024-12345"

    def make_assessment(self, ids=None, complete=True):
        if ids is None:
            ids = (self.CVE_ID,)

        search = NVDSearchResult(
            query="ExampleServer 1.0",
            cve_ids=ids,
            total_results=(
                len(ids) if complete else len(ids) + 1
            ),
            complete=complete,
        )

        return CVECandidateAssessor.assess(
            "ExampleServer",
            "1.0",
            search,
        )

    def make_record(
        self,
        criteria=None,
        status="Analyzed",
        configurations=None,
    ):
        if configurations is None:
            configurations = ({
                "operator": "OR",
                "nodes": [{
                    "operator": "OR",
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": (
                            criteria or self.OBSERVED
                        ),
                    }],
                }],
            },)

        return NVDCVERecord(
            cve_id=self.CVE_ID,
            vuln_status=status,
            published="2024-01-01T00:00:00.000",
            last_modified="2024-02-01T00:00:00.000",
            configurations=configurations,
        )

    def test_possible_match(self):
        result = CVEApplicabilityAssessor.assess(
            self.make_assessment(),
            {self.CVE_ID: self.make_record()},
            self.OBSERVED,
        )

        self.assertEqual(
            result.results[0].status,
            CPEStatus.POSSIBLE,
        )

    def test_no_match(self):
        result = CVEApplicabilityAssessor.assess(
            self.make_assessment(),
            {
                self.CVE_ID: self.make_record(
                    criteria=self.OTHER
                )
            },
            self.OBSERVED,
        )

        self.assertEqual(
            result.results[0].status,
            CPEStatus.NO_MATCH,
        )

    def test_missing_record(self):
        result = CVEApplicabilityAssessor.assess(
            self.make_assessment(),
            {},
            self.OBSERVED,
        )

        self.assertEqual(
            result.results[0].status,
            CPEStatus.UNKNOWN,
        )

    def test_missing_observed_cpe(self):
        result = CVEApplicabilityAssessor.assess(
            self.make_assessment(),
            {self.CVE_ID: self.make_record()},
        )

        self.assertEqual(
            result.results[0].status,
            CPEStatus.UNKNOWN,
        )

    def test_missing_configurations(self):
        result = CVEApplicabilityAssessor.assess(
            self.make_assessment(),
            {
                self.CVE_ID: self.make_record(
                    configurations=()
                )
            },
            self.OBSERVED,
        )

        self.assertEqual(
            result.results[0].status,
            CPEStatus.UNKNOWN,
        )

    def test_rejected_record(self):
        result = CVEApplicabilityAssessor.assess(
            self.make_assessment(),
            {
                self.CVE_ID: self.make_record(
                    status="Rejected"
                )
            },
            self.OBSERVED,
        )

        self.assertEqual(
            result.results[0].status,
            CPEStatus.UNKNOWN,
        )

        self.assertIn(
            "rejected",
            result.results[0].reason.lower(),
        )

    def test_incomplete_search_preserved(self):
        result = CVEApplicabilityAssessor.assess(
            self.make_assessment(complete=False),
            {self.CVE_ID: self.make_record()},
            self.OBSERVED,
        )

        self.assertFalse(result.search_complete)

    def test_unrelated_record_rejected(self):
        with self.assertRaises(ValueError):
            CVEApplicabilityAssessor.assess(
                self.make_assessment(),
                {
                    "CVE-2024-99999":
                    self.make_record()
                },
                self.OBSERVED,
            )


if __name__ == "__main__":
    unittest.main()