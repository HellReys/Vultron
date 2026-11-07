import tempfile
import unittest
from pathlib import Path

import yaml

from core.policy_engine import PolicyEngine


class TestPolicyEngine(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config_path = (
            Path(self.temp_dir.name) / "test_policy.yaml"
        )

        self.config = {
            "program": {
                "name": "Test Program"
            },
            "scope": {
                "allowed": [
                    "example.com",
                    "*.example.com"
                ],
                "excluded": [
                    "admin.example.com"
                ]
            },
            "scanning": {
                "enabled": False,
                "authorization_confirmed": False,
                "requests_per_second": 2,
                "max_concurrent_requests": 2
            }
        }

        self.save_config()

    def tearDown(self):
        self.temp_dir.cleanup()

    def save_config(self):
        with self.config_path.open(
            "w", encoding="utf-8"
        ) as file:
            yaml.safe_dump(self.config, file)

    def test_program_name(self):
        policy = PolicyEngine(self.config_path)
        self.assertEqual(
            policy.program_name, "Test Program"
        )

    def test_allowed_domain(self):
        policy = PolicyEngine(self.config_path)
        allowed, _ = policy.check_host("api.example.com")
        self.assertTrue(allowed)

    def test_excluded_domain(self):
        policy = PolicyEngine(self.config_path)
        allowed, _ = policy.check_host("admin.example.com")
        self.assertFalse(allowed)

    def test_outside_scope(self):
        policy = PolicyEngine(self.config_path)
        allowed, _ = policy.check_url(
            "https://external.com/"
        )
        self.assertFalse(allowed)

    def test_scanning_disabled_by_default(self):
        policy = PolicyEngine(self.config_path)
        self.assertFalse(policy.can_scan())

    def test_scanning_without_authorization(self):
        self.config["scanning"]["enabled"] = True
        self.save_config()

        with self.assertRaises(ValueError):
            PolicyEngine(self.config_path)

    def test_scanning_with_authorization(self):
        self.config["scanning"]["enabled"] = True
        self.config["scanning"][
            "authorization_confirmed"
        ] = True

        self.save_config()
        policy = PolicyEngine(self.config_path)
        self.assertTrue(policy.can_scan())

    def test_invalid_rate_limit(self):
        self.config["scanning"][
            "requests_per_second"
        ] = 0

        self.save_config()

        with self.assertRaises(ValueError):
            PolicyEngine(self.config_path)

    def test_missing_allowed_scope(self):
        self.config["scope"]["allowed"] = []
        self.save_config()

        with self.assertRaises(ValueError):
            PolicyEngine(self.config_path)

    def test_unknown_scanning_field(self):
        self.config["scanning"]["unsafe_mode"] = True
        self.save_config()

        with self.assertRaises(ValueError):
            PolicyEngine(self.config_path)


if __name__ == "__main__":
    unittest.main()
