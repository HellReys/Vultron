import os
import unittest

from core.nvd_client import NVDClient, NVDCVERecord


@unittest.skipUnless(
    os.getenv("VULTRON_LIVE_NVD_TEST") == "1",
    "Live NVD test is disabled by default."
)
class TestNVDLiveAPI(unittest.TestCase):

    CVE_ID = "CVE-2024-3094"

    def test_live_cve_retrieval(self):
        client = NVDClient(
            requests_per_second=0.1,
            timeout=15.0
        )

        try:
            record = client.get_cve(self.CVE_ID)

            self.assertIsInstance(
                record, NVDCVERecord
            )

            self.assertEqual(
                record.cve_id,
                self.CVE_ID
            )

            self.assertIsInstance(
                record.published,
                str
            )

            self.assertIsInstance(
                record.last_modified,
                str
            )

            self.assertIsInstance(
                record.configurations,
                tuple
            )

            # Cached lookup must not trigger
            # an additional request.
            cached = client.get_cve(self.CVE_ID)

            self.assertEqual(record, cached)
            self.assertIsNot(record, cached)

            print("\nLIVE NVD VALIDATION")
            print("CVE:", record.cve_id)
            print("Status:", record.vuln_status)
            print("Published:", record.published)
            print("Modified:", record.last_modified)
            print(
                "Configurations:",
                len(record.configurations)
            )
            print("Result: PASS")

        finally:
            client.session.close()


if __name__ == "__main__":
    unittest.main()