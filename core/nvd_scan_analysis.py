from core.cve_assessment import CVECandidateAssessor
from core.cpe_evidence import EvidenceAwareCVEAssessor
from dataclasses import dataclass
from core.nvd_client import NVDError, NVDRateLimitError


class NVDScanAnalyzer:
    """
    Opt-in NVD keyword analysis for TCP scan results.

    Version 1:
    - One unique product/version lookup per scan.
    - No automatic CPE inference.
    - No vulnerability confirmation.
    """

    @staticmethod
    def analyze(summary, client):
        seen = set()

        for result in summary.results:
            if not result.open:
                continue

            product = getattr(result, "product", None)
            version = getattr(result, "version", None)

            if (
                not isinstance(product, str)
                or not isinstance(version, str)
                or not product.strip()
                or not version.strip()
            ):
                continue

            product = product.strip()
            version = version.strip()

            identity = (product, version)

            if identity in seen:
                continue

            seen.add(identity)

            # One NVD keyword search per scan.
            search_result = client.search(
                product,
                version,
            )

            candidates = CVECandidateAssessor.assess(
                product,
                version,
                search_result,
            )

            # No independently verified observed CPE
            # has been supplied by this scan.
            #
            # Therefore applicability must remain UNKNOWN.
            return EvidenceAwareCVEAssessor.assess(
                candidates,
                records={},
                observation=None,
            )

        return None

@dataclass(frozen=True)
class NVDScanEntry:
    product: str
    version: str
    assessment: object | None
    error_code: str | None = None


@dataclass(frozen=True)
class NVDScanBatch:
    status: str
    entries: tuple[NVDScanEntry, ...]
    attempted_queries: int
    omitted_services: int
    search_complete: bool


def analyze_nvd_batch(summary, client, max_queries=3):
    """
    Bounded, opt-in multi-service NVD analysis.

    No automatic CPE verification.
    No automatic full-CVE downloads.
    No vulnerability confirmation.
    """

    if type(max_queries) is not int or not 1 <= max_queries <= 3:
        raise ValueError("NVD query limit must be between 1 and 3.")

    identities = []
    seen = set()

    for result in summary.results:
        if not result.open:
            continue

        product = getattr(result, "product", None)
        version = getattr(result, "version", None)

        if not isinstance(product, str) or not isinstance(version, str):
            continue

        product = product.strip()
        version = version.strip()

        if not product or not version:
            continue

        # Respect NVDClient input constraints.
        if len(product) > 100 or len(version) > 100:
            continue

        if any(ord(c) < 32 for c in product + version):
            continue

        key = (product.casefold(), version.casefold())

        if key in seen:
            continue

        seen.add(key)
        identities.append((product, version))

    if not identities:
        return NVDScanBatch(
            status="NO_ELIGIBLE_SERVICES",
            entries=(),
            attempted_queries=0,
            omitted_services=0,
            search_complete=False,
        )

    entries = []
    rate_limited = False

    for product, version in identities[:max_queries]:
        try:
            search = client.search(product, version)

            candidates = CVECandidateAssessor.assess(
                product, version, search
            )

            assessment = EvidenceAwareCVEAssessor.assess(
                candidates,
                records={},
                observation=None,
            )

            entries.append(
                NVDScanEntry(
                    product=product,
                    version=version,
                    assessment=assessment,
                )
            )

        except NVDRateLimitError:
            entries.append(
                NVDScanEntry(
                    product=product,
                    version=version,
                    assessment=None,
                    error_code="RATE_LIMIT",
                )
            )

            rate_limited = True
            break

        except (NVDError, ValueError):
            entries.append(
                NVDScanEntry(
                    product=product,
                    version=version,
                    assessment=None,
                    error_code="LOOKUP_FAILED",
                )
            )

    successful = [
        entry for entry in entries
        if entry.assessment is not None
    ]

    omitted = len(identities) - len(entries)

    complete = (
        not rate_limited
        and omitted == 0
        and len(successful) == len(entries)
        and all(
            entry.assessment.summary.search_complete
            for entry in successful
        )
    )

    if not successful:
        status = "ERROR"
    elif complete:
        status = "COMPLETE"
    else:
        status = "PARTIAL"

    return NVDScanBatch(
        status=status,
        entries=tuple(entries),
        attempted_queries=len(entries),
        omitted_services=omitted,
        search_complete=complete,
    )
