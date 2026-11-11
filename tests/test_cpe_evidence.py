import unittest

from core.cpe_evidence import (
    CPEObservation,
    CPESource,
    EvidenceAwareCVEAssessor,
)
from core.cpe_applicability import CPEStatus
from core.cve_assessment import CVECandidateAssessor
from core.nvd_client import (
    NVDSearchResult,
    NVDCVERecord,
)


class TestCPEEvidence(unittest.TestCase):

    CVE_ID = "CVE-2024-12345"

    CPE = (
        "cpe:2.3:a:example:server:1.0:"
        "*:*:*:*:*:*:*"
    )

    OTHER = (
        "cpe:2.3:a:example:other:2.0:"
        "*:*:*:*:*:*:*"
    )

    def setUp(self):
        search = NVDSearchResult(
            query="ExampleServer 1.0",
            cve_ids=(self.CVE_ID,),
            total_results=1,
            complete=True,
        )

        self.candidates = CVECandidateAssessor.assess(
            "ExampleServer",
            "1.0",
            search,
        )

        self.records = {
            self.CVE_ID: NVDCVERecord(
                cve_id=self.CVE_ID,
                vuln_status="Analyzed",
                published="2024-01-01",
                last_modified="2024-02-01",
                configurations=({
                    "nodes": [{
                        "operator": "OR",
                        "cpeMatch": [{
                            "vulnerable": True,
                            "criteria": self.CPE,
                        }],
                    }],
                },),
            )
        }

    def test_no_evidence_returns_unknown(self):
        result = EvidenceAwareCVEAssessor.assess(
            self.candidates,
            self.records,
        )

        self.assertFalse(result.accepted)
        self.assertEqual(
            result.summary.results[0].status,
            CPEStatus.UNKNOWN,
        )

    def test_nvd_derived_cpe_is_blocked(self):
        observation = CPEObservation(
            cpe=self.CPE,
            source=CPESource.NVD_DERIVED,
            evidence="Copied from an NVD CVE record.",
        )

        result = EvidenceAwareCVEAssessor.assess(
            self.candidates,
            self.records,
            observation,
        )

        self.assertFalse(result.accepted)
        self.assertEqual(
            result.summary.results[0].status,
            CPEStatus.UNKNOWN,
        )

    def test_passive_banner_is_not_verified(self):
        observation = CPEObservation(
            cpe=self.CPE,
            source=CPESource.PASSIVE_BANNER,
            evidence="SSH service identification banner.",
        )

        result = EvidenceAwareCVEAssessor.assess(
            self.candidates,
            self.records,
            observation,
        )

        self.assertFalse(result.accepted)
        self.assertEqual(
            result.summary.results[0].status,
            CPEStatus.UNKNOWN,
        )

    def test_verified_cpe_allows_comparison(self):
        observation = CPEObservation(
            cpe=self.CPE,
            source=CPESource.INDEPENDENT_VERIFICATION,
            evidence="Verified using installed package metadata.",
        )

        result = EvidenceAwareCVEAssessor.assess(
            self.candidates,
            self.records,
            observation,
        )

        self.assertTrue(result.accepted)
        self.assertEqual(
            result.summary.results[0].status,
            CPEStatus.POSSIBLE,
        )

    def test_verified_different_product_no_match(self):
        observation = CPEObservation(
            cpe=self.OTHER,
            source=CPESource.INDEPENDENT_VERIFICATION,
            evidence="Verified using installed package metadata.",
        )

        result = EvidenceAwareCVEAssessor.assess(
            self.candidates,
            self.records,
            observation,
        )

        self.assertTrue(result.accepted)
        self.assertEqual(
            result.summary.results[0].status,
            CPEStatus.NO_MATCH,
        )


if __name__ == "__main__":
    unittest.main()