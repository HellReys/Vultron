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

        # Only whole-component '*' wildcards are supported.
        # Partial wildcard expressions require a full CPE parser.
        if any("*" in part and part != "*" for part in parts):
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

        uncertain = False

        for actual, expected in zip(observed, candidate):
            if expected == "*":
                continue

            if actual == "*" and expected != "*":
                uncertain = True
                continue

            if actual != expected:
                return False

        return None if uncertain else True

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

            # NVD 2.0 configuration objects may omit
            # the top-level operator.
            #
            # If absent, we support a simple collection
            # of OR nodes only. Explicit AND and
            # negation remain unsupported.

            allowed_config_fields = {
                "operator",
                "negate",
                "nodes",
            }

            if (
                    set(configuration) - allowed_config_fields
                    or configuration.get("operator", "OR") != "OR"
                    or configuration.get("negate", False) is not False
            ):
                uncertain = True
                continue

            nodes = configuration.get("nodes")

            if not isinstance(nodes, list) or not nodes:
                uncertain = True
                continue

            if (
                    "operator" not in configuration
                    and len(nodes) != 1
            ):
                uncertain = True
                continue

            for node in nodes:
                if not isinstance(node, dict):
                    uncertain = True
                    continue

                allowed_node_fields = {
                    "operator",
                    "negate",
                    "cpeMatch",
                }

                if (
                        set(node) - allowed_node_fields
                        or node.get("operator") != "OR"
                        or node.get("negate", False) is not False
                ):
                    uncertain = True
                    continue

                entries = node.get("cpeMatch")

                if not isinstance(entries, list) or not entries:
                    uncertain = True
                    continue

                for entry in entries:
                    if not isinstance(entry, dict):
                        uncertain = True
                        continue

                    if type(entry.get("vulnerable")) is not bool:
                        uncertain = True
                        continue

                    if entry["vulnerable"] is False:
                        uncertain = True
                        continue

                    if any(
                            field in entry
                            for field in cls.VERSION_BOUNDS
                    ):
                        uncertain = True
                        continue

                    # Unsupported fields must not silently
                    # affect applicability.
                    allowed_fields = {
                        "vulnerable",
                        "criteria",
                        "matchCriteriaId"
                    }

                    if set(entry) - allowed_fields:
                        uncertain = True
                        continue

                    comparison = cls._compare(
                        observed,
                        entry.get("criteria")
                    )

                    if comparison is True:
                        matched = True

                    elif comparison is None:
                        uncertain = True

        # Uncertainty takes precedence over every match.
        if uncertain:
            return CPEEvaluation(
                CPEStatus.UNKNOWN,
                "At least one applicability condition "
                "could not be evaluated safely."
            )

        if matched:
            return CPEEvaluation(
                CPEStatus.POSSIBLE,
                "Supported CPE criteria matched. "
                "Vulnerability is not confirmed."
            )

        return CPEEvaluation(
            CPEStatus.NO_MATCH,
            "No supported CPE criterion matched."
        )