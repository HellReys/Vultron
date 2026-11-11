import unittest

from core.cpe_applicability import (
    CPEApplicabilityEvaluator,
    CPEStatus
)


class TestCPEApplicability(unittest.TestCase):

    OBSERVED = (
        "cpe:2.3:a:openbsd:openssh:9.6p1:"
        "*:*:*:*:*:*:*"
    )

    def make_config(self, entries, operator="OR"):
        return [{
            "operator": "OR",
            "nodes": [{
                "operator": operator,
                "cpeMatch": entries
            }]
        }]

    def make_entry(self, criteria, vulnerable=True):
        return {
            "vulnerable": vulnerable,
            "criteria": criteria
        }

    def test_exact_match(self):
        config = self.make_config([
            self.make_entry(self.OBSERVED)
        ])

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(result.status, CPEStatus.POSSIBLE)

    def test_wildcard_version(self):
        criteria = (
            "cpe:2.3:a:openbsd:openssh:*:"
            "*:*:*:*:*:*:*"
        )

        config = self.make_config([
            self.make_entry(criteria)
        ])

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(result.status, CPEStatus.POSSIBLE)

    def test_different_product(self):
        criteria = (
            "cpe:2.3:a:example:nginx:1.24:"
            "*:*:*:*:*:*:*"
        )

        config = self.make_config([
            self.make_entry(criteria)
        ])

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(result.status, CPEStatus.NO_MATCH)

    def test_different_version(self):
        criteria = (
            "cpe:2.3:a:openbsd:openssh:8.0:"
            "*:*:*:*:*:*:*"
        )

        config = self.make_config([
            self.make_entry(criteria)
        ])

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(result.status, CPEStatus.NO_MATCH)

    def test_version_range_is_unknown(self):
        entry = self.make_entry(
            "cpe:2.3:a:openbsd:openssh:*:"
            "*:*:*:*:*:*:*"
        )

        entry["versionEndExcluding"] = "9.7"

        config = self.make_config([entry])

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(result.status, CPEStatus.UNKNOWN)

    def test_and_operator_is_unknown(self):
        config = self.make_config(
            [self.make_entry(self.OBSERVED)],
            operator="AND"
        )

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(result.status, CPEStatus.UNKNOWN)

    def test_negated_node_is_unknown(self):
        config = self.make_config([
            self.make_entry(self.OBSERVED)
        ])

        config[0]["nodes"][0]["negate"] = True

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(result.status, CPEStatus.UNKNOWN)

    def test_non_vulnerable_entry_is_unknown(self):
        config = self.make_config([
            self.make_entry(
                self.OBSERVED,
                vulnerable=False
            )
        ])

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(result.status, CPEStatus.UNKNOWN)

    def test_missing_configuration(self):
        result = CPEApplicabilityEvaluator.evaluate(
            [], self.OBSERVED
        )

        self.assertEqual(result.status, CPEStatus.UNKNOWN)

    def test_invalid_observed_cpe(self):
        config = self.make_config([
            self.make_entry(self.OBSERVED)
        ])

        result = CPEApplicabilityEvaluator.evaluate(
            config, "OpenSSH 9.6p1"
        )

        self.assertEqual(result.status, CPEStatus.UNKNOWN)

    def test_nested_nodes_are_unknown(self):
        config = self.make_config([
            self.make_entry(self.OBSERVED)
        ])

        config[0]["nodes"][0]["children"] = []

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(result.status, CPEStatus.UNKNOWN)

    def test_or_with_matching_entry(self):
        other = (
            "cpe:2.3:a:example:other:1.0:"
            "*:*:*:*:*:*:*"
        )

        config = self.make_config([
            self.make_entry(other),
            self.make_entry(self.OBSERVED)
        ])

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(result.status, CPEStatus.POSSIBLE)

    def test_unknown_product_is_rejected(self):
        observed = (
            "cpe:2.3:a:openbsd:*:9.6p1:"
            "*:*:*:*:*:*:*"
        )

        config = self.make_config([
            self.make_entry(self.OBSERVED)
        ])

        result = CPEApplicabilityEvaluator.evaluate(
            config, observed
        )

        self.assertEqual(
            result.status,
            CPEStatus.UNKNOWN
        )

    def test_match_with_unsupported_and_is_unknown(self):
        config = self.make_config([
            self.make_entry(self.OBSERVED)
        ])

        config[0]["nodes"].append({
            "operator": "AND",
            "cpeMatch": [
                self.make_entry(self.OBSERVED)
            ]
        })

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(result.status, CPEStatus.UNKNOWN)

    def test_match_with_negated_node_is_unknown(self):
        config = self.make_config([
            self.make_entry(self.OBSERVED)
        ])

        config[0]["nodes"].append({
            "operator": "OR",
            "negate": True,
            "cpeMatch": [
                self.make_entry(self.OBSERVED)
            ]
        })

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(result.status, CPEStatus.UNKNOWN)

    def test_match_with_version_range_is_unknown(self):
        ranged_entry = self.make_entry(
            self.OBSERVED
        )

        ranged_entry["versionEndExcluding"] = "10.0"

        config = self.make_config([
            self.make_entry(self.OBSERVED),
            ranged_entry
        ])

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(result.status, CPEStatus.UNKNOWN)

    def test_match_with_platform_condition_is_unknown(self):
        config = self.make_config([
            self.make_entry(self.OBSERVED),
            self.make_entry(
                "cpe:2.3:o:example:system:1.0:"
                "*:*:*:*:*:*:*",
                vulnerable=False
            )
        ])

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(result.status, CPEStatus.UNKNOWN)

    def test_unspecified_observed_field_is_unknown(self):
        criteria = (
            "cpe:2.3:a:openbsd:openssh:9.6p1:"
            "*:windows:*:*:*:*:*"
        )

        config = self.make_config([
            self.make_entry(criteria)
        ])

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(result.status, CPEStatus.UNKNOWN)

    def test_partial_wildcard_is_unknown(self):
        criteria = (
            "cpe:2.3:a:openbsd:open*:*:"
            "*:*:*:*:*:*:*"
        )

        config = self.make_config([
            self.make_entry(criteria)
        ])

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(result.status, CPEStatus.UNKNOWN)

    def test_nvd_schema_without_top_operator(self):
        config = [{
            "nodes": [{
                "operator": "OR",
                "negate": False,
                "cpeMatch": [
                    self.make_entry(self.OBSERVED)
                ],
            }]
        }]

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(
            result.status,
            CPEStatus.POSSIBLE
        )

    def test_nvd_schema_no_match(self):
        config = [{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [
                    self.make_entry(
                        "cpe:2.3:a:example:other:2.0:"
                        "*:*:*:*:*:*:*"
                    )
                ],
            }]
        }]

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(
            result.status,
            CPEStatus.NO_MATCH
        )

    def test_nvd_schema_with_match_criteria_id(self):
        entry = self.make_entry(self.OBSERVED)

        entry["matchCriteriaId"] = (
            "00000000-0000-4000-8000-000000000001"
        )

        config = [{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [entry],
            }]
        }]

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(
            result.status,
            CPEStatus.POSSIBLE
        )

    def test_nvd_schema_explicit_and_is_unknown(self):
        config = [{
            "operator": "AND",
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [
                    self.make_entry(self.OBSERVED)
                ],
            }]
        }]

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(
            result.status,
            CPEStatus.UNKNOWN
        )

    def test_nvd_schema_mixed_conditions_unknown(self):
        config = [{
            "nodes": [
                {
                    "operator": "OR",
                    "cpeMatch": [
                        self.make_entry(self.OBSERVED)
                    ],
                },
                {
                    "operator": "AND",
                    "cpeMatch": [
                        self.make_entry(self.OBSERVED)
                    ],
                },
            ]
        }]

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(
            result.status,
            CPEStatus.UNKNOWN
        )

    def test_nvd_schema_unknown_top_field(self):
        config = [{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [
                    self.make_entry(self.OBSERVED)
                ],
            }],
            "unexpectedField": True,
        }]

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(
            result.status,
            CPEStatus.UNKNOWN
        )

    def test_nvd_schema_missing_nodes(self):
        config = [{}]

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(
            result.status,
            CPEStatus.UNKNOWN
        )

    def test_nvd_multiple_nodes_without_operator_unknown(self):
        config = [{
            "nodes": [
                {
                    "operator": "OR",
                    "cpeMatch": [
                        self.make_entry(self.OBSERVED)
                    ],
                },
                {
                    "operator": "OR",
                    "cpeMatch": [
                        self.make_entry(self.OBSERVED)
                    ],
                },
            ]
        }]

        result = CPEApplicabilityEvaluator.evaluate(
            config, self.OBSERVED
        )

        self.assertEqual(
            result.status,
            CPEStatus.UNKNOWN
        )

if __name__ == "__main__":
    unittest.main()