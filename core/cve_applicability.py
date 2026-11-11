from copy import deepcopy
from dataclasses import dataclass

from core.cpe_applicability import (
    CPEApplicabilityEvaluator,
    CPEStatus,
)
from core.cve_assessment import (
    CVEAssessment,
    AssessmentStatus,
)
from core.nvd_client import NVDCVERecord


@dataclass(frozen=True)
class CVEApplicabilityResult:
    cve_id: str
    status: CPEStatus
    reason: str


@dataclass(frozen=True)
class CVEApplicabilitySummary:
    product: str | None
    version: str | None
    observed_cpe: str | None
    results: tuple[CVEApplicabilityResult, ...]
    search_complete: bool


class CVEApplicabilityAssessor:
    """
    Combines CVE candidates, full NVD records
    and conservative CPE evaluation.

    It never confirms a vulnerability.
    """

    @classmethod
    def assess(
        cls,
        candidate_assessment,
        records,
        observed_cpe=None,
    ):
        if not isinstance(
            candidate_assessment, CVEAssessment
        ):
            raise ValueError(
                "Invalid CVE candidate assessment."
            )

        if not isinstance(records, dict):
            raise ValueError(
                "CVE records must be a dictionary."
            )

        if (
            observed_cpe is not None
            and not isinstance(observed_cpe, str)
        ):
            raise ValueError(
                "Invalid observed CPE."
            )

        candidates = candidate_assessment.candidates

        if (
            not isinstance(candidates, tuple)
            or any(
                candidate.status
                != AssessmentStatus.CANDIDATE
                for candidate in candidates
            )
        ):
            raise ValueError(
                "Invalid CVE candidate collection."
            )

        candidate_ids = {
            candidate.cve_id
            for candidate in candidates
        }

        if len(candidate_ids) != len(candidates):
            raise ValueError(
                "Duplicate CVE candidates."
            )

        for cve_id, record in records.items():
            if (
                cve_id not in candidate_ids
                or not isinstance(record, NVDCVERecord)
                or record.cve_id != cve_id
            ):
                raise ValueError(
                    "Invalid or unrelated CVE record."
                )

        results = []

        for candidate in candidates:
            cve_id = candidate.cve_id
            record = records.get(cve_id)

            if record is None:
                results.append(
                    CVEApplicabilityResult(
                        cve_id,
                        CPEStatus.UNKNOWN,
                        "Full NVD record is unavailable."
                    )
                )
                continue

            if record.vuln_status in (
                "Rejected",
                "REJECT",
                "Rejected by CVE Numbering Authority",
            ):
                results.append(
                    CVEApplicabilityResult(
                        cve_id,
                        CPEStatus.UNKNOWN,
                        "CVE record is rejected. "
                        "Do not report it as an "
                        "active vulnerability."
                    )
                )
                continue

            if not observed_cpe:
                results.append(
                    CVEApplicabilityResult(
                        cve_id,
                        CPEStatus.UNKNOWN,
                        "Observed CPE is unavailable."
                    )
                )
                continue

            if not record.configurations:
                results.append(
                    CVEApplicabilityResult(
                        cve_id,
                        CPEStatus.UNKNOWN,
                        "NVD applicability data "
                        "is missing."
                    )
                )
                continue

            evaluation = (
                CPEApplicabilityEvaluator.evaluate(
                    deepcopy(list(
                        record.configurations
                    )),
                    observed_cpe
                )
            )

            results.append(
                CVEApplicabilityResult(
                    cve_id=cve_id,
                    status=evaluation.status,
                    reason=evaluation.reason
                )
            )

        return CVEApplicabilitySummary(
            product=candidate_assessment.product,
            version=candidate_assessment.version,
            observed_cpe=observed_cpe,
            results=tuple(results),
            search_complete=(
                candidate_assessment.search_complete
            )
        )