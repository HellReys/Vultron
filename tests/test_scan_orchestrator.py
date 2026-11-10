import unittest
from unittest.mock import MagicMock

from core.scan_orchestrator import ScanOrchestrator
from core.tcp_policy import TCPScanPolicy
from core.tcp_scanner import TCPPortResult


class FakePolicy:
    def __init__(self, active=True, tcp_enabled=True):
        self.active = active

        self.tcp_policy = TCPScanPolicy(
            enabled=tcp_enabled,
            allowed_ports=(80, 443),
            connections_per_second=2.0,
            max_connections=10
        )

    def can_scan(self):
        return self.active


class TestScanOrchestrator(unittest.TestCase):

    def setUp(self):
        self.policy = FakePolicy()

        self.context = MagicMock()
        self.context.policy = self.policy

        self.scanner = MagicMock()

        self.scanner.scan.return_value = [
            TCPPortResult(
                host="example.com",
                ip_address="1.1.1.1",
                port=80,
                open=True
            ),
            TCPPortResult(
                host="example.com",
                ip_address="1.1.1.1",
                port=443,
                open=False
            )
        ]

        self.context.create_tcp_scanner.return_value = (
            self.scanner
        )

        self.orchestrator = ScanOrchestrator(
            self.context
        )

    def test_default_authorized_ports(self):
        summary = self.orchestrator.scan_tcp(
            "example.com"
        )

        self.scanner.scan.assert_called_once_with(
            "example.com",
            [80, 443]
        )

        self.assertEqual(
            summary.open_ports,
            (80,)
        )

    def test_custom_authorized_ports(self):
        self.orchestrator.scan_tcp(
            "example.com",
            [80]
        )

        self.scanner.scan.assert_called_once_with(
            "example.com",
            [80]
        )

    def test_unauthorized_port_blocked(self):
        with self.assertRaises(PermissionError):
            self.orchestrator.scan_tcp(
                "example.com",
                [22]
            )

        self.context.create_tcp_scanner.assert_not_called()

    def test_scanning_disabled(self):
        self.policy.active = False

        with self.assertRaises(PermissionError):
            self.orchestrator.scan_tcp(
                "example.com"
            )

        self.context.create_tcp_scanner.assert_not_called()

    def test_tcp_disabled(self):
        self.policy.tcp_policy = TCPScanPolicy(
            enabled=False,
            allowed_ports=(80, 443),
            connections_per_second=2.0,
            max_connections=10
        )

        with self.assertRaises(PermissionError):
            self.orchestrator.scan_tcp(
                "example.com"
            )

    def test_duplicate_ports_blocked(self):
        with self.assertRaises(ValueError):
            self.orchestrator.scan_tcp(
                "example.com",
                [80, 80]
            )

    def test_invalid_port_type(self):
        with self.assertRaises(ValueError):
            self.orchestrator.scan_tcp(
                "example.com",
                ["80"]
            )

    def test_scan_summary(self):
        summary = self.orchestrator.scan_tcp(
            "example.com"
        )

        self.assertEqual(
            summary.target,
            "example.com"
        )

        self.assertEqual(
            len(summary.results),
            2
        )

        self.assertEqual(
            summary.attempted_connections,
            2
        )

        self.assertEqual(
            summary.open_ports,
            (80,)
        )


if __name__ == "__main__":
    unittest.main()