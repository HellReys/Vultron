from dataclasses import dataclass
from enum import Enum


class CPEStatus(str, Enum):
    POSSIBLE = "POSSIBLE"
    NO_MATCH = "NO_MATCH"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class CPEEvaluation:
    status: CPEStatus
    reason: str


class CPEApplicabilityEvaluator:
    """
    Conservative evaluator for a limited subset of
    NVD CVE 2.0 applicability configurations.

    Supported:
      - Flat OR nodes
      - Exact CPE 2.3 component matching
      - '*' wildcards in match criteria
      - vulnerable=True entries without version ranges

    Unsupported structures return UNKNOWN.
    """

    VERSION_BOUNDS = (
        "versionStartIncluding",
        "versionStartExcluding",
        "versionEndIncluding",
        "versionEndExcluding",
    )

    @staticmethod
    def _parse_cpe(value, observed=False):
        if not isinstance(value, str):
            return None

        parts = value.split(":")

        if (
            len(parts) != 13
            or parts[:2] != ["cpe", "2.3"]
            or any(not part for part in parts)
        ):
            return None

        # Escaped CPE syntax needs a dedicated parser.
        if "\\" in value or "?" in value:
            return None

        if observed and any(
                part == "*" for part in parts[2:6]
        ):
            return None

        if parts[2] not in ("a", "o", "h"):
            return None

        return tuple(parts)

    @classmethod
    def _compare(cls, observed, criteria):
        candidate = cls._parse_cpe(criteria)

        if candidate is None:
            return None

        for actual, expected in zip(observed, candidate):
            if expected != "*" and actual != expected:
                return False

        return True

    @classmethod
    def evaluate(cls, configurations, observed_cpe):
        observed = cls._parse_cpe(
            observed_cpe,
            observed=True
        )

        if observed is None:
            return CPEEvaluation(
                CPEStatus.UNKNOWN,
                "Observed CPE is invalid or unsupported."
            )

        if (
            not isinstance(configurations, list)
            or not configurations
        ):
            return CPEEvaluation(
                CPEStatus.UNKNOWN,
                "No usable applicability configurations."
            )

        matched = False
        uncertain = False

        for configuration in configurations:
            if not isinstance(configuration, dict):
                uncertain = True
                continue

            # Only top-level OR configurations are supported.
            if (
                configuration.get("operator") != "OR"
                or configuration.get("negate", False) is not False
            ):
                uncertain = True
                continue

            nodes = configuration.get("nodes")

            if not isinstance(nodes, list) or not nodes:
                uncertain = True
                continue

            for node in nodes:
                if not isinstance(node, dict):
                    uncertain = True
                    continue

                # AND, negation and nested nodes are deferred.
                if (
                    node.get("operator") != "OR"
                    or node.get("negate", False) is not False
                    or "children" in node
                    or "nodes" in node
                ):
                    uncertain = True
                    continue

                matches = node.get("cpeMatch")

                if not isinstance(matches, list) or not matches:
                    uncertain = True
                    continue

                for entry in matches:
                    if not isinstance(entry, dict):
                        uncertain = True
                        continue

                    if type(entry.get("vulnerable")) is not bool:
                        uncertain = True
                        continue

                    # A non-vulnerable CPE may describe a
                    # required platform condition.
                    if entry["vulnerable"] is False:
                        uncertain = True
                        continue

                    # Version ordering is not implemented.
                    if any(
                        key in entry
                        for key in cls.VERSION_BOUNDS
                    ):
                        uncertain = True
                        continue

                    result = cls._compare(
                        observed,
                        entry.get("criteria")
                    )

                    if result is True:
                        matched = True
                    elif result is None:
                        uncertain = True

        if matched:
            return CPEEvaluation(
                CPEStatus.POSSIBLE,
                "A supported CPE criterion matched. "
                "Vulnerability is not confirmed."
            )

        if uncertain:
            return CPEEvaluation(
                CPEStatus.UNKNOWN,
                "Applicability contains unsupported "
                "or incomplete conditions."
            )

        return CPEEvaluation(
            CPEStatus.NO_MATCH,
            "No supported CPE criterion matched."
        )