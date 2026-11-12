import tempfile
import unittest
from pathlib import Path

from yaml.constructor import ConstructorError

from core.config_manager import ConfigurationManager
from core.policy_engine import PolicyEngine
from core.yaml_loader import load_yaml


class TestUniqueYAMLLoader(unittest.TestCase):

    def test_valid_yaml(self):
        data = load_yaml(
            "scanning:\n"
            "  enabled: false\n"
            "  authorization_confirmed: false\n"
        )

        self.assertFalse(data["scanning"]["enabled"])

    def test_duplicate_root_key_rejected(self):
        with self.assertRaisesRegex(
            ConstructorError,
            "Duplicate YAML key",
        ):
            load_yaml(
                "scanning: 1\n"
                "scanning: 2\n"
            )

    def test_duplicate_nested_key_rejected(self):
        with self.assertRaisesRegex(
            ConstructorError,
            "Duplicate YAML key",
        ):
            load_yaml(
                "scanning:\n"
                "  enabled: false\n"
                "  enabled: true\n"
            )

    def test_duplicate_scope_key_rejected_by_policy(self):
        text = (
            "program:\n"
            "  name: Test\n"
            "scope:\n"
            "  allowed:\n"
            "    - example.com\n"
            "  excluded: []\n"
            "  excluded:\n"
            "    - admin.example.com\n"
            "scanning:\n"
            "  enabled: false\n"
            "  authorization_confirmed: false\n"
            "  requests_per_second: 1\n"
            "  max_concurrent_requests: 1\n"
        )

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "policy.yaml"
            path.write_text(text, encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError,
                "Cannot load policy configuration",
            ):
                PolicyEngine(path)

    def test_duplicate_setting_rejected(self):
        text = (
            "app:\n"
            "  name: Vultron\n"
            "http:\n"
            "  timeout: 5\n"
            "  timeout: 60\n"
            "  max_response_bytes: 1024\n"
        )

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "settings.yaml"
            path.write_text(text, encoding="utf-8")

            manager = ConfigurationManager(path)

            with self.assertRaisesRegex(
                ValueError,
                "Cannot load global configuration",
            ):
                manager.load()


if __name__ == "__main__":
    unittest.main()
