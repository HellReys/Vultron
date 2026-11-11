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

if __name__ == "__main__":
    unittest.main()