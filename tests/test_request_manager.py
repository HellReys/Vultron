import tempfile
import unittest
from pathlib import Path

import yaml

from core.policy_engine import PolicyEngine
from core.request_manager import RequestManager


class TestRequestManager(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.config_path = (
            Path(self.temp_dir.name) / "policy.yaml"
        )

        self.config = {
            "program": {
                "name": "Local Test Program"
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
                "enabled": True,
                "authorization_confirmed": True,
                "requests_per_second": 100,
                "max_concurrent_requests": 2
            }
        }

        self.save_config()
        self.manager = self.create_manager()

    def tearDown(self):
        self.temp_dir.cleanup()

    def save_config(self):
        with self.config_path.open(
            "w", encoding="utf-8"
        ) as file:
            yaml.safe_dump(self.config, file)

    def create_manager(self):
        return RequestManager(
            PolicyEngine(self.config_path)
        )

    def test_allowed_url(self):
        plan = self.manager.prepare(
            "https://api.example.com/users"
        )

        self.assertEqual(plan.method, "GET")
        self.assertEqual(
            plan.hostname, "api.example.com"
        )

    def test_outside_scope(self):
        with self.assertRaises(PermissionError):
            self.manager.prepare(
                "https://external.com/"
            )

    def test_excluded_domain(self):
        with self.assertRaises(PermissionError):
            self.manager.prepare(
                "https://admin.example.com/"
            )

    def test_scanning_disabled(self):
        self.config["scanning"]["enabled"] = False
        self.save_config()

        manager = self.create_manager()

        with self.assertRaises(PermissionError):
            manager.prepare(
                "https://example.com/"
            )

    def test_unsupported_method(self):
        with self.assertRaises(PermissionError):
            self.manager.prepare(
                "https://example.com/",
                method="POST"
            )

    def test_non_standard_port(self):
        with self.assertRaises(PermissionError):
            self.manager.prepare(
                "https://example.com:8080/"
            )

    def test_permit(self):
        with self.manager.permit(
            "https://example.com/"
        ) as plan:
            self.assertEqual(
                plan.hostname, "example.com"
            )

    def test_url_credentials_rejected(self):
        with self.assertRaises(PermissionError):
            self.manager.prepare(
                "https://user:pass@example.com/"
            )

    def test_invalid_characters(self):
        with self.assertRaises(ValueError):
            self.manager.prepare(
                "https://example.com/\nunsafe"
            )


if __name__ == "__main__":
    unittest.main()
