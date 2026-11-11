import re
from dataclasses import dataclass
from enum import Enum

from core.nvd_client import NVDSearchResult


class AssessmentStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class CVECandidate:
    cve_id: str
    status: AssessmentStatus
    reason: str


@dataclass(frozen=True)
class CVEAssessment:
    product: str | None
    version: str | None
    status: AssessmentStatus
    candidates: tuple[CVECandidate, ...]
    total_results: int | None
    search_complete: bool
    reason: str


class CVECandidateAssessor:
    """
    Classify NVD keyword-search results.

    This class does not confirm vulnerabilities or
    evaluate CPE applicability.
    """

    CVE_PATTERN = re.compile(
        r"^CVE-\d{4}-\d{4,}$"
    )

    @classmethod
    def assess(cls, product, version, search_result=None):
        if product is not None and not isinstance(product, str):
            raise ValueError("Invalid product.")

        if version is not None and not isinstance(version, str):
            raise ValueError("Invalid version.")

        product = product.strip() if product else None
        version = version.strip() if version else None

        if not product or not version:
            return CVEAssessment(
                product=product,
                version=version,
                status=AssessmentStatus.UNKNOWN,
                candidates=(),
                total_results=None,
                search_complete=False,
                reason="Product or version information is missing."
            )

        if search_result is None:
            return CVEAssessment(
                product=product,
                version=version,
                status=AssessmentStatus.UNKNOWN,
                candidates=(),
                total_results=None,
                search_complete=False,
                reason="NVD search has not been performed."
            )

        if not isinstance(search_result, NVDSearchResult):
            raise ValueError("Invalid NVD search result.")

        expected_query = f"{product} {version}"

        if search_result.query != expected_query:
            raise ValueError(
                "NVD search result does not match the product/version."
            )

        if (
            type(search_result.total_results) is not int
            or search_result.total_results < 0
            or type(search_result.complete) is not bool
            or not isinstance(search_result.cve_ids, tuple)
            or len(search_result.cve_ids) > search_result.total_results
            or search_result.complete != (
                len(search_result.cve_ids)
                == search_result.total_results
            )
        ):
            raise ValueError("Inconsistent NVD search result.")

        candidates = []
        seen = set()

        for cve_id in search_result.cve_ids:
            if (
                not isinstance(cve_id, str)
                or not cls.CVE_PATTERN.fullmatch(cve_id)
            ):
                raise ValueError("Invalid CVE identifier.")

            if cve_id in seen:
                raise ValueError("Duplicate CVE identifier.")

            seen.add(cve_id)

            candidates.append(
                CVECandidate(
                    cve_id=cve_id,
                    status=AssessmentStatus.CANDIDATE,
                    reason=(
                        "NVD keyword-search match. "
                        "Product and version applicability "
                        "have not been verified."
                    )
                )
            )

        if candidates:
            status = AssessmentStatus.CANDIDATE
            reason = (
                "Potential CVE matches require manual verification."
            )

        elif search_result.complete:
            status = AssessmentStatus.UNKNOWN
            reason = (
                "No keyword-search matches were returned. "
                "This does not establish that the product is safe."
            )

        else:
            status = AssessmentStatus.UNKNOWN
            reason = "NVD search results are incomplete."

        if not search_result.complete:
            reason += " Additional NVD results may exist."

        return CVEAssessment(
            product=product,
            version=version,
            status=status,
            candidates=tuple(candidates),
            total_results=search_result.total_results,
            search_complete=search_result.complete,
            reason=reason
        )