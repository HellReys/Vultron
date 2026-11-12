import unittest

from core.cpe_applicability import CPEStatus
from core.cve_applicability import (
    CVEApplicabilityAssessor,
)
from core.cve_assessment import CVECandidateAssessor
from core.nvd_client import (
    NVDCVERecord,
    NVDSearchResult,
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

    def test_real_nvd_or_configuration_match(self):
        config = ({
            "nodes": [{
                "operator": "OR",
                "negate": False,
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": self.OBSERVED,
                    "matchCriteriaId": (
                        "00000000-0000-4000-8000-000000000001"
                    ),
                }],
            }]
        },)

        record = self.make_record(
            configurations=config
        )

        result = CVEApplicabilityAssessor.assess(
            self.make_assessment(),
            {self.CVE_ID: record},
            self.OBSERVED,
        )

        self.assertEqual(
            result.results[0].status,
            CPEStatus.POSSIBLE,
        )

    def test_real_nvd_different_product(self):
        config = ({
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": self.OTHER,
                }],
            }]
        },)

        result = CVEApplicabilityAssessor.assess(
            self.make_assessment(),
            {
                self.CVE_ID: self.make_record(
                    configurations=config
                )
            },
            self.OBSERVED,
        )

        self.assertEqual(
            result.results[0].status,
            CPEStatus.NO_MATCH,
        )

    def test_real_nvd_version_range_unknown(self):
        config = ({
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": (
                        "cpe:2.3:a:example:server:*:"
                        "*:*:*:*:*:*:*"
                    ),
                    "versionStartIncluding": "1.0",
                    "versionEndExcluding": "2.0",
                }],
            }]
        },)

        result = CVEApplicabilityAssessor.assess(
            self.make_assessment(),
            {
                self.CVE_ID: self.make_record(
                    configurations=config
                )
            },
            self.OBSERVED,
        )

        self.assertEqual(
            result.results[0].status,
            CPEStatus.UNKNOWN,
        )

    def test_real_nvd_and_platform_unknown(self):
        config = ({
            "nodes": [{
                "operator": "AND",
                "children": [
                    {
                        "operator": "OR",
                        "cpeMatch": [{
                            "vulnerable": True,
                            "criteria": self.OBSERVED,
                        }],
                    },
                    {
                        "operator": "OR",
                        "cpeMatch": [{
                            "vulnerable": False,
                            "criteria": (
                                "cpe:2.3:o:example:os:1.0:"
                                "*:*:*:*:*:*:*"
                            ),
                        }],
                    },
                ],
            }]
        },)

        result = CVEApplicabilityAssessor.assess(
            self.make_assessment(),
            {
                self.CVE_ID: self.make_record(
                    configurations=config
                )
            },
            self.OBSERVED,
        )

        self.assertEqual(
            result.results[0].status,
            CPEStatus.UNKNOWN,
        )

    def test_real_nvd_empty_config_unknown(self):
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

        self.assertIn(
            "missing",
            result.results[0].reason.lower(),
        )

    def test_real_nvd_match_plus_unsupported_unknown(self):
        config = ({
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [
                    {
                        "vulnerable": True,
                        "criteria": self.OBSERVED,
                    },
                    {
                        "vulnerable": True,
                        "criteria": (
                            "cpe:2.3:a:example:server:*:"
                            "*:*:*:*:*:*:*"
                        ),
                        "versionEndExcluding": "3.0",
                    },
                ],
            }]
        },)

        result = CVEApplicabilityAssessor.assess(
            self.make_assessment(),
            {
                self.CVE_ID: self.make_record(
                    configurations=config
                )
            },
            self.OBSERVED,
        )

        self.assertEqual(
            result.results[0].status,
            CPEStatus.UNKNOWN,
        )

    def test_multiple_cve_records_independent_results(self):
        from dataclasses import replace

        second_id = "CVE-2024-54321"

        assessment = self.make_assessment(
            ids=(self.CVE_ID, second_id)
        )

        first_record = self.make_record()

        second_record = replace(
            self.make_record(
                criteria=self.OTHER
            ),
            cve_id=second_id,
        )

        result = CVEApplicabilityAssessor.assess(
            assessment,
            {
                self.CVE_ID: first_record,
                second_id: second_record,
            },
            self.OBSERVED,
        )

        self.assertEqual(
            len(result.results),
            2,
        )

        self.assertEqual(
            result.results[0].status,
            CPEStatus.POSSIBLE,
        )

        self.assertEqual(
            result.results[1].status,
            CPEStatus.NO_MATCH,
        )

if __name__ == "__main__":
    unittest.main()