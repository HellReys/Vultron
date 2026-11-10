import socket
import unittest
from unittest.mock import MagicMock

from core.scope_guard import ScopeGuard
from core.tcp_policy import TCPScanPolicy
from core.tcp_scanner import PolicyAwareTCPScanner


class FakePolicy:
    def __init__(self, active=True, tcp_enabled=True):
        self.active = active

        self.scope_guard = ScopeGuard(
            allowed=["example.com", "*.example.com"],
            excluded=["admin.example.com"]
        )

        self.tcp_policy = TCPScanPolicy(
            enabled=tcp_enabled,
            allowed_ports=(80, 443),
            connections_per_second=100.0,
            max_connections=2
        )

    def can_scan(self):
        return self.active

    def check_host(self, hostname):
        return self.scope_guard.check_host(hostname)


def fake_resolver(hostname, port, **kwargs):
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("1.1.1.1", 0)
        )
    ]


class TestTCPScanner(unittest.TestCase):

    def setUp(self):
        self.sock = MagicMock()
        self.sock.__enter__.return_value = self.sock
        self.sock.connect_ex.return_value = 0

        self.socket_factory = MagicMock(
            return_value=self.sock
        )

        self.policy = FakePolicy()

        self.scanner = PolicyAwareTCPScanner(
            policy=self.policy,
            resolver=fake_resolver,
            socket_factory=self.socket_factory
        )

    def test_allowed_port(self):
        results = self.scanner.scan(
            "api.example.com",
            [80]
        )

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].open)

        self.sock.connect_ex.assert_called_once_with(
            ("1.1.1.1", 80)
        )

    def test_closed_port(self):
        self.sock.connect_ex.return_value = 111

        results = self.scanner.scan(
            "api.example.com",
            [443]
        )

        self.assertFalse(results[0].open)

    def test_unauthorized_port(self):
        with self.assertRaises(PermissionError):
            self.scanner.scan(
                "api.example.com",
                [22]
            )

        self.socket_factory.assert_not_called()

    def test_outside_scope(self):
        with self.assertRaises(PermissionError):
            self.scanner.scan(
                "external.com",
                [80]
            )

        self.socket_factory.assert_not_called()

    def test_excluded_host(self):
        with self.assertRaises(PermissionError):
            self.scanner.scan(
                "admin.example.com",
                [80]
            )

        self.socket_factory.assert_not_called()

    def test_active_scanning_disabled(self):
        scanner = PolicyAwareTCPScanner(
            policy=FakePolicy(active=False),
            resolver=fake_resolver,
            socket_factory=self.socket_factory
        )

        with self.assertRaises(PermissionError):
            scanner.scan("example.com", [80])

    def test_tcp_scanning_disabled(self):
        scanner = PolicyAwareTCPScanner(
            policy=FakePolicy(tcp_enabled=False),
            resolver=fake_resolver,
            socket_factory=self.socket_factory
        )

        with self.assertRaises(PermissionError):
            scanner.scan("example.com", [80])

    def test_connection_budget(self):
        self.scanner.scan("example.com", [80, 443])

        self.assertEqual(self.scanner.budget.used, 2)

        with self.assertRaises(PermissionError):
            self.scanner.scan("example.com", [80])

    def test_duplicate_ports_rejected(self):
        with self.assertRaises(ValueError):
            self.scanner.scan("example.com", [80, 80])

    def test_private_dns_address_blocked(self):
        def private_resolver(*args, **kwargs):
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    6,
                    "",
                    ("127.0.0.1", 0)
                )
            ]

        scanner = PolicyAwareTCPScanner(
            policy=self.policy,
            resolver=private_resolver,
            socket_factory=self.socket_factory
        )

        with self.assertRaises(PermissionError):
            scanner.scan("example.com", [80])

        self.socket_factory.assert_not_called()


class TestTCPPolicy(unittest.TestCase):

    def test_missing_policy_is_disabled(self):
        policy = TCPScanPolicy.from_config(None)

        self.assertFalse(policy.enabled)

    def test_invalid_port_rejected(self):
        with self.assertRaises(ValueError):
            TCPScanPolicy.from_config({
                "enabled": True,
                "allowed_ports": [70000],
                "connections_per_second": 2,
                "max_connections": 10
            })


if __name__ == "__main__":
    unittest.main()