import os
import unittest

from core.cpe_applicability import (
    CPEApplicabilityEvaluator,
    CPEStatus,
)
from core.nvd_client import NVDClient


@unittest.skipUnless(
    os.getenv("VULTRON_LIVE_NVD_TEST") == "1",
    "Live NVD tests are disabled by default."
)
class TestNVDLiveApplicability(unittest.TestCase):

    CVE_ID = "CVE-2024-3094"

    @classmethod
    def setUpClass(cls):
        cls.client = NVDClient(
            requests_per_second=0.1,
            timeout=15.0
        )

        try:
            cls.record = cls.client.get_cve(cls.CVE_ID)
        except Exception:
            cls.client.session.close()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.client.session.close()

    def test_real_configuration_structure(self):
        configurations = self.record.configurations

        self.assertIsInstance(configurations, tuple)

        node_count = 0
        match_count = 0
        range_count = 0
        operators = set()

        for config in configurations:
            self.assertIsInstance(config, dict)

            nodes = config.get("nodes", [])
            self.assertIsInstance(nodes, list)

            for node in nodes:
                self.assertIsInstance(node, dict)
                node_count += 1

                operator = node.get("operator")
                if operator is not None:
                    self.assertIsInstance(operator, str)
                    operators.add(operator)

                entries = node.get("cpeMatch", [])
                self.assertIsInstance(entries, list)

                for entry in entries:
                    self.assertIsInstance(entry, dict)
                    self.assertIsInstance(
                        entry.get("criteria"), str
                    )
                    self.assertIsInstance(
                        entry.get("vulnerable"), bool
                    )

                    match_count += 1

                    if any(
                        key in entry
                        for key in (
                            "versionStartIncluding",
                            "versionStartExcluding",
                            "versionEndIncluding",
                            "versionEndExcluding",
                        )
                    ):
                        range_count += 1

        print("\nREAL NVD APPLICABILITY STRUCTURE")
        print("CVE:", self.record.cve_id)
        print("Configurations:", len(configurations))
        print("Top-level nodes:", node_count)
        print("Direct CPE match entries:", match_count)
        print("Direct version-range entries:", range_count)
        print("Operators:", sorted(operators))
        print("Schema inspection: PASS")

    def test_observed_cpe_applicability(self):
        observed_cpe = os.getenv(
            "VULTRON_OBSERVED_CPE"
        )

        if not observed_cpe:
            self.skipTest(
                "No independently supplied observed CPE."
            )

        result = CPEApplicabilityEvaluator.evaluate(
            list(self.record.configurations),
            observed_cpe
        )

        self.assertIsInstance(result.status, CPEStatus)
        self.assertIsInstance(result.reason, str)
        self.assertTrue(result.reason)

        print("\nREAL NVD CPE EVALUATION")
        print("CVE:", self.record.cve_id)
        print("Observed CPE:", observed_cpe)
        print("Assessment:", result.status.value)
        print("Reason:", result.reason)
        print("Vulnerability confirmed: NO")


if __name__ == "__main__":
    unittest.main()