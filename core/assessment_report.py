from core.cpe_applicability import CPEStatus
from core.cpe_evidence import EvidenceAssessment


class AssessmentReport:
    """
    Convert an evidence-aware CVE assessment into
    a safe, serializable report section.
    """

    @staticmethod
    def build(assessment=None):
        if assessment is None:
            return {
                "status": "NOT_PERFORMED",
                "evidence_accepted": False,
                "evidence_source": None,
                "search_complete": False,
                "confirmed_vulnerabilities": 0,
                "vulnerability_confirmed": False,
                "results": [],
                "reason": "CVE analysis was not performed.",
            }

        if not isinstance(assessment, EvidenceAssessment):
            raise ValueError("Invalid evidence assessment.")

        if type(assessment.accepted) is not bool:
            raise ValueError("Invalid evidence status.")

        summary = assessment.summary

        if not isinstance(summary.results, tuple):
            raise ValueError("Invalid CVE results.")

        if type(summary.search_complete) is not bool:
            raise ValueError("Invalid search completion status.")

        if assessment.source is None:
            source = None
        else:
            from core.cpe_evidence import CPESource

            if not isinstance(assessment.source, CPESource):
                raise ValueError("Invalid evidence source.")

            source = assessment.source.value

        results = []

        for item in summary.results:
            if not isinstance(item.status, CPEStatus):
                raise ValueError("Invalid applicability status.")

            results.append({
                "cve_id": item.cve_id,
                "status": "CANDIDATE",
                "applicability": item.status.value,
                "reason": item.reason,
                "vulnerability_confirmed": False,
            })

        return {
            "status": (
                "CANDIDATES_FOUND"
                if results else "NO_CANDIDATES"
            ),
            "evidence_accepted": assessment.accepted,
            "evidence_source": source,
            "search_complete": summary.search_complete,
            "confirmed_vulnerabilities": 0,
            "vulnerability_confirmed": False,
            "results": results,
            "reason": assessment.reason,
        }