import unittest

from core.assessment_report import AssessmentReport
from core.cpe_applicability import CPEStatus
from core.cpe_evidence import (
    CPEObservation,
    CPESource,
    EvidenceAwareCVEAssessor,
)
from core.cve_assessment import CVECandidateAssessor
from core.nvd_client import (
    NVDSearchResult,
    NVDCVERecord,
)


class TestAssessmentReport(unittest.TestCase):

    CVE_ID = "CVE-2024-12345"
    CPE = "cpe:2.3:a:example:server:1.0:*:*:*:*:*:*:*"

    def make_assessment(self, observation=None):
        search = NVDSearchResult(
            query="ExampleServer 1.0",
            cve_ids=(self.CVE_ID,),
            total_results=1,
            complete=True,
        )

        candidates = CVECandidateAssessor.assess(
            "ExampleServer", "1.0", search
        )

        record = NVDCVERecord(
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

        return EvidenceAwareCVEAssessor.assess(
            candidates,
            {self.CVE_ID: record},
            observation,
        )

    def test_not_performed(self):
        data = AssessmentReport.build()

        self.assertEqual(
            data["status"], "NOT_PERFORMED"
        )
        self.assertEqual(data["results"], [])
        self.assertFalse(data["vulnerability_confirmed"])

    def test_unverified_evidence_unknown(self):
        observation = CPEObservation(
            self.CPE,
            CPESource.NVD_DERIVED,
            "Copied from NVD",
        )

        data = AssessmentReport.build(
            self.make_assessment(observation)
        )

        self.assertFalse(data["evidence_accepted"])
        self.assertEqual(
            data["results"][0]["applicability"],
            CPEStatus.UNKNOWN.value,
        )

    def test_independent_evidence_possible(self):
        observation = CPEObservation(
            self.CPE,
            CPESource.INDEPENDENT_VERIFICATION,
            "Verified from installed package metadata.",
        )

        data = AssessmentReport.build(
            self.make_assessment(observation)
        )

        self.assertTrue(data["evidence_accepted"])
        self.assertEqual(
            data["results"][0]["applicability"],
            CPEStatus.POSSIBLE.value,
        )
        self.assertFalse(
            data["results"][0]["vulnerability_confirmed"]
        )

    def test_no_confirmed_vulnerability(self):
        observation = CPEObservation(
            self.CPE,
            CPESource.INDEPENDENT_VERIFICATION,
            "Verified package metadata.",
        )

        data = AssessmentReport.build(
            self.make_assessment(observation)
        )

        self.assertEqual(
            data["confirmed_vulnerabilities"], 0
        )
        self.assertEqual(
            data["results"][0]["status"], "CANDIDATE"
        )

    def test_raw_evidence_not_exported(self):
        observation = CPEObservation(
            self.CPE,
            CPESource.INDEPENDENT_VERIFICATION,
            "PRIVATE_INTERNAL_EVIDENCE",
        )

        data = AssessmentReport.build(
            self.make_assessment(observation)
        )

        self.assertNotIn(
            "PRIVATE_INTERNAL_EVIDENCE",
            str(data),
        )
        self.assertNotIn(self.CPE, str(data))

    def test_invalid_assessment_rejected(self):
        with self.assertRaises(ValueError):
            AssessmentReport.build("invalid")