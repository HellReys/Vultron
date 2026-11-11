from dataclasses import dataclass
from enum import Enum

from core.cve_applicability import CVEApplicabilityAssessor


class CPESource(str, Enum):
    INDEPENDENT_VERIFICATION = "independent_verification"
    PASSIVE_BANNER = "passive_banner"
    NVD_DERIVED = "nvd_derived"


@dataclass(frozen=True)
class CPEObservation:
    cpe: str
    source: CPESource
    evidence: str = ""


@dataclass(frozen=True)
class EvidenceAssessment:
    summary: object
    source: CPESource | None
    evidence: str
    accepted: bool
    reason: str


class EvidenceAwareCVEAssessor:
    """
    Prevents NVD-derived or unverified CPE identities
    from being treated as independently observed.

    An accepted observation permits CPE comparison,
    not vulnerability confirmation.
    """

    @classmethod
    def assess(cls, candidate_assessment, records,
               observation=None):

        if observation is None:
            summary = CVEApplicabilityAssessor.assess(
                candidate_assessment,
                records,
                observed_cpe=None,
            )

            return EvidenceAssessment(
                summary=summary,
                source=None,
                evidence="",
                accepted=False,
                reason="No independent CPE evidence supplied.",
            )

        if not isinstance(observation, CPEObservation):
            raise ValueError("Invalid CPE observation.")

        if not isinstance(observation.source, CPESource):
            raise ValueError("Invalid CPE evidence source.")

        if not isinstance(observation.cpe, str):
            raise ValueError("Invalid observed CPE.")

        if not isinstance(observation.evidence, str):
            raise ValueError("Invalid evidence description.")

        accepted = (
            observation.source
            == CPESource.INDEPENDENT_VERIFICATION
            and bool(observation.evidence.strip())
        )

        if accepted:
            summary = CVEApplicabilityAssessor.assess(
                candidate_assessment,
                records,
                observed_cpe=observation.cpe,
            )

            reason = (
                "Independent verification was declared. "
                "CPE comparison is permitted, but "
                "vulnerability is not confirmed."
            )
        else:
            summary = CVEApplicabilityAssessor.assess(
                candidate_assessment,
                records,
                observed_cpe=None,
            )

            reason = (
                "CPE evidence is insufficient or "
                "not independently verified."
            )

        return EvidenceAssessment(
            summary=summary,
            source=observation.source,
            evidence=observation.evidence,
            accepted=accepted,
            reason=reason,
        )