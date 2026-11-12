import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import yaml

from core.policy_engine import PolicyEngine
from core.program_context import ProgramContext
from core.scan_orchestrator import ScanOrchestrator
from core.scan_report import ScanReportWriter


def fake_resolver(hostname, port, **kwargs):
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("1.1.1.1", 0),
        )
    ]


class TestPolicyPipelineIntegration(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)

        self.root = Path(self.temporary.name)
        self.policy_path = self.root / "policy.yaml"

        self.config = {
            "program": {"name": "Integration Test"},
            "scope": {
                "allowed": ["example.com", "*.example.com"],
                "excluded": ["admin.example.com"],
            },
            "scanning": {
                "enabled": True,
                "authorization_confirmed": True,
                "requests_per_second": 100,
                "max_concurrent_requests": 1,
                "max_requests": 10,
            },
            "tcp_scanning": {
                "enabled": True,
                "allowed_ports": [80, 443],
                "connections_per_second": 100,
                "max_connections": 2,
                "banner_grabbing_enabled": True,
            },
        }

    def create_orchestrator(self, config=None):
        self.policy_path.write_text(
            yaml.safe_dump(config or self.config),
            encoding="utf-8",
        )

        policy = PolicyEngine(self.policy_path)
        context = ProgramContext(policy)

        return ScanOrchestrator(context), context

    @staticmethod
    def fake_socket(connect_result):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.connect_ex.return_value = connect_result
        sock.recv.return_value = b"SSH-2.0-OpenSSH_9.6\r\n"
        return sock

    def test_complete_pipeline_creates_valid_report(self):
        orchestrator, context = self.create_orchestrator()

        first = self.fake_socket(0)
        second = self.fake_socket(111)

        factory = MagicMock(
            side_effect=[first, second]
        )

        summary = orchestrator.scan_tcp(
            "example.com",
            ports=[80, 443],
            resolver=fake_resolver,
            socket_factory=factory,
        )

        self.assertEqual(summary.open_ports, (80,))
        self.assertEqual(summary.attempted_connections, 2)
        self.assertEqual(context.tcp_budget.used, 2)
        self.assertEqual(factory.call_count, 2)

        writer = ScanReportWriter(
            self.root / "reports"
        )

        path = writer.write(
            summary,
            tcp_budget_used=context.tcp_budget.used,
            tcp_budget_limit=2,
        )

        report = json.loads(
            path.read_text(encoding="utf-8")
        )

        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["target"], "example.com")
        self.assertEqual(report["total_open_ports"], 1)
        self.assertEqual(report["attempted_connections"], 2)
        self.assertEqual(report["tcp_budget"]["used"], 2)
        self.assertEqual(len(report["results"]), 2)

        self.assertEqual(
            report["results"][0]["status"],
            "OPEN",
        )
        self.assertEqual(
            report["results"][1]["status"],
            "NOT_OPEN",
        )

        self.assertEqual(
            report["results"][0]["banner"],
            "[REDACTED]",
        )

        self.assertNotIn(
            "OpenSSH_9.6",
            path.read_text(encoding="utf-8"),
        )

        first.send.assert_not_called()
        first.sendall.assert_not_called()

    def test_excluded_target_creates_no_connection(self):
        orchestrator, context = self.create_orchestrator()
        factory = MagicMock()

        with self.assertRaises(PermissionError):
            orchestrator.scan_tcp(
                "admin.example.com",
                ports=[80],
                resolver=fake_resolver,
                socket_factory=factory,
            )

        factory.assert_not_called()
        self.assertEqual(context.tcp_budget.used, 0)

    def test_private_dns_address_is_blocked(self):
        orchestrator, context = self.create_orchestrator()
        factory = MagicMock()

        def private_resolver(*args, **kwargs):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    6,
                    "",
                    ("127.0.0.1", 0),
                )
            ]

        with self.assertRaises(PermissionError):
            orchestrator.scan_tcp(
                "example.com",
                ports=[80],
                resolver=private_resolver,
                socket_factory=factory,
            )

        factory.assert_not_called()
        self.assertEqual(context.tcp_budget.used, 0)

    def test_disabled_authorization_blocks_pipeline(self):
        config = {
            **self.config,
            "scanning": {
                **self.config["scanning"],
                "enabled": False,
                "authorization_confirmed": False,
            },
        }

        orchestrator, context = self.create_orchestrator(
            config
        )

        factory = MagicMock()
        resolver = MagicMock()

        with self.assertRaises(PermissionError):
            orchestrator.scan_tcp(
                "example.com",
                ports=[80],
                resolver=resolver,
                socket_factory=factory,
            )

        factory.assert_not_called()
        resolver.assert_not_called()
        self.assertEqual(context.tcp_budget.used, 0)


if __name__ == "__main__":
    unittest.main()
