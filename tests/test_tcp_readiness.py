import socket
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import yaml

from core.policy_engine import PolicyEngine
from core.program_context import ProgramContext
from core.scan_orchestrator import ScanOrchestrator


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


class TestTCPReadiness(unittest.TestCase):

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def create_pipeline(self, ports, budget):
        config = {
            "program": {"name": "Performance Test"},
            "scope": {
                "allowed": ["example.com"],
                "excluded": [],
            },
            "scanning": {
                "enabled": True,
                "authorization_confirmed": True,
                "requests_per_second": 1000,
                "max_concurrent_requests": 1,
                "max_requests": 100,
            },
            "tcp_scanning": {
                "enabled": True,
                "allowed_ports": ports,
                "connections_per_second": 1000,
                "max_connections": budget,
                "banner_grabbing_enabled": False,
            },
        }

        path = self.root / "policy.yaml"
        path.write_text(
            yaml.safe_dump(config),
            encoding="utf-8",
        )

        context = ProgramContext(PolicyEngine(path))
        return ScanOrchestrator(context), context

    @staticmethod
    def make_factory():
        def create_socket(family, socktype):
            sock = MagicMock()
            sock.__enter__.return_value = sock
            sock.connect_ex.return_value = 111
            return sock

        return MagicMock(side_effect=create_socket)

    def test_64_port_batch(self):
        ports = list(range(10000, 10064))
        orchestrator, context = self.create_pipeline(
            ports, budget=64
        )
        factory = self.make_factory()

        start = time.perf_counter()

        summary = orchestrator.scan_tcp(
            "example.com",
            ports=ports,
            resolver=fake_resolver,
            socket_factory=factory,
        )

        elapsed = time.perf_counter() - start

        self.assertEqual(len(summary.results), 64)
        self.assertEqual(summary.attempted_connections, 64)
        self.assertEqual(summary.open_ports, ())
        self.assertEqual(context.tcp_budget.used, 64)
        self.assertEqual(factory.call_count, 64)
        self.assertEqual(context.tcp_budget.remaining, 0)

        print(
            f"\n64 mocked TCP connections: "
            f"{elapsed:.4f} seconds"
        )

    def test_budget_shared_across_scans(self):
        orchestrator, context = self.create_pipeline(
            [80, 443],
            budget=2,
        )
        factory = self.make_factory()

        first = orchestrator.scan_tcp(
            "example.com",
            ports=[80],
            resolver=fake_resolver,
            socket_factory=factory,
        )

        second = orchestrator.scan_tcp(
            "example.com",
            ports=[443],
            resolver=fake_resolver,
            socket_factory=factory,
        )

        self.assertEqual(first.attempted_connections, 1)
        self.assertEqual(second.attempted_connections, 1)
        self.assertEqual(context.tcp_budget.used, 2)
        self.assertEqual(factory.call_count, 2)

    def test_insufficient_budget_blocks_entire_batch(self):
        orchestrator, context = self.create_pipeline(
            [80, 443],
            budget=1,
        )

        factory = MagicMock()
        resolver = MagicMock()

        with self.assertRaises(PermissionError):
            orchestrator.scan_tcp(
                "example.com",
                ports=[80, 443],
                resolver=resolver,
                socket_factory=factory,
            )

        self.assertEqual(context.tcp_budget.used, 0)
        factory.assert_not_called()
        resolver.assert_not_called()

    def test_unauthorized_port_blocks_before_network(self):
        orchestrator, context = self.create_pipeline(
            [80],
            budget=2,
        )

        factory = MagicMock()
        resolver = MagicMock()

        with self.assertRaises(PermissionError):
            orchestrator.scan_tcp(
                "example.com",
                ports=[443],
                resolver=resolver,
                socket_factory=factory,
            )

        self.assertEqual(context.tcp_budget.used, 0)
        factory.assert_not_called()
        resolver.assert_not_called()


if __name__ == "__main__":
    unittest.main()
