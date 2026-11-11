from core.cve_assessment import CVECandidateAssessor
from core.cpe_evidence import EvidenceAwareCVEAssessor


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