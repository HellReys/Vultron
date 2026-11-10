import tempfile
import unittest
from pathlib import Path

import yaml

from core.config_manager import ConfigurationManager
from core.program_context import ProgramContext
from core.scope_guard import ScopeGuard


class FakePolicy:
    def __init__(self):
        self.requests_per_second = 100
        self.max_concurrent_requests = 2
        self.max_requests = 20

        self.scope_guard = ScopeGuard(
            allowed=["example.com"],
            excluded=[]
        )

    def can_scan(self):
        return True

    def check_url(self, url):
        return self.scope_guard.check_url(url)

    def check_host(self, host):
        return self.scope_guard.check_host(host)


class TestConfigurationManager(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.config_path = (
            Path(self.temp_dir.name) / "settings.yaml"
        )

        self.config = {
            "app": {
                "name": "Vultron"
            },
            "http": {
                "timeout": 5.0,
                "max_response_bytes": 262144
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

    def load_settings(self):
        return ConfigurationManager(
            self.config_path
        ).load()

    def test_valid_configuration(self):
        settings = self.load_settings()

        self.assertEqual(settings.app.name, "Vultron")
        self.assertEqual(settings.http.timeout, 5.0)
        self.assertEqual(
            settings.http.max_response_bytes,
            262144
        )

    def test_missing_configuration_file(self):
        missing = (
            Path(self.temp_dir.name) / "missing.yaml"
        )

        with self.assertRaises(ValueError):
            ConfigurationManager(missing).load()

    def test_invalid_yaml(self):
        self.config_path.write_text(
            "app: [invalid",
            encoding="utf-8"
        )

        with self.assertRaises(ValueError):
            self.load_settings()

    def test_unknown_configuration_field(self):
        self.config["debug_mode"] = True
        self.save_config()

        with self.assertRaises(ValueError):
            self.load_settings()

    def test_empty_app_name(self):
        self.config["app"]["name"] = ""
        self.save_config()

        with self.assertRaises(ValueError):
            self.load_settings()

    def test_invalid_timeout(self):
        self.config["http"]["timeout"] = -1
        self.save_config()

        with self.assertRaises(ValueError):
            self.load_settings()

    def test_boolean_timeout_rejected(self):
        self.config["http"]["timeout"] = True
        self.save_config()

        with self.assertRaises(ValueError):
            self.load_settings()

    def test_invalid_response_size(self):
        self.config["http"]["max_response_bytes"] = 0
        self.save_config()

        with self.assertRaises(ValueError):
            self.load_settings()

    def test_program_context_uses_settings(self):
        self.config["http"]["timeout"] = 8.0
        self.config["http"]["max_response_bytes"] = 4096
        self.save_config()

        settings = self.load_settings()

        context = ProgramContext(
            FakePolicy(),
            settings=settings
        )

        transport = context.create_http_transport()

        self.assertEqual(transport.timeout, 8.0)
        self.assertEqual(
            transport.max_response_bytes,
            4096
        )

    def test_explicit_transport_override(self):
        settings = self.load_settings()

        context = ProgramContext(
            FakePolicy(),
            settings=settings
        )

        transport = context.create_http_transport(
            timeout=3.0
        )

        self.assertEqual(transport.timeout, 3.0)


if __name__ == "__main__":
    unittest.main()