import socket
import unittest
from unittest.mock import MagicMock

from core.scope_guard import ScopeGuard
from core.tcp_policy import TCPScanPolicy
from core.tcp_scanner import PolicyAwareTCPScanner


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


class TestPolicy:
    def __init__(self):
        self.scope_guard = ScopeGuard(
            allowed=["example.com"],
            excluded=[],
        )
        self.tcp_policy = TCPScanPolicy(
            enabled=True,
            allowed_ports=(80, 443),
            connections_per_second=100.0,
            max_connections=2,
            banner_grabbing_enabled=True,
        )

    def can_scan(self):
        return True

    def check_host(self, hostname):
        return self.scope_guard.check_host(hostname)


class TestTCPReliability(unittest.TestCase):

    def setUp(self):
        self.policy = TestPolicy()

        self.sock = MagicMock()
        self.sock.__enter__.return_value = self.sock
        self.sock.connect_ex.return_value = 0
        self.sock.recv.return_value = (
            b"SSH-2.0-OpenSSH_9.6\r\n"
        )

        self.factory = MagicMock(return_value=self.sock)

        self.scanner = PolicyAwareTCPScanner(
            policy=self.policy,
            resolver=fake_resolver,
            socket_factory=self.factory,
            timeout=1.0,
        )

    def test_connection_timeout_closes_socket(self):
        self.sock.connect_ex.side_effect = socket.timeout()

        results = self.scanner.scan("example.com", [80])

        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].open)
        self.assertEqual(self.scanner.budget.used, 1)
        self.sock.__exit__.assert_called_once()
        self.sock.recv.assert_not_called()

    def test_connection_refused_closes_socket(self):
        self.sock.connect_ex.return_value = 111

        results = self.scanner.scan("example.com", [80])

        self.assertFalse(results[0].open)
        self.assertEqual(self.scanner.budget.used, 1)
        self.sock.__exit__.assert_called_once()
        self.sock.recv.assert_not_called()

    def test_banner_timeout_keeps_port_open(self):
        self.sock.recv.side_effect = socket.timeout()

        results = self.scanner.scan("example.com", [80])

        self.assertTrue(results[0].open)
        self.assertEqual(results[0].service, "Unknown")
        self.assertEqual(results[0].banner, "")
        self.assertEqual(self.scanner.budget.used, 1)

        self.sock.settimeout.assert_any_call(0.2)
        self.sock.__exit__.assert_called_once()

    def test_unexpected_banner_error_closes_socket(self):
        self.sock.recv.side_effect = RuntimeError(
            "Simulated internal error"
        )

        with self.assertRaises(RuntimeError):
            self.scanner.scan("example.com", [80])

        self.assertEqual(self.scanner.budget.used, 1)
        self.sock.__exit__.assert_called_once()

    def test_exhausted_budget_prevents_new_connection(self):
        self.scanner.scan("example.com", [80, 443])

        self.assertEqual(self.scanner.budget.used, 2)
        self.assertEqual(self.factory.call_count, 2)

        with self.assertRaises(PermissionError):
            self.scanner.scan("example.com", [80])

        self.assertEqual(self.scanner.budget.used, 2)
        self.assertEqual(self.factory.call_count, 2)


if __name__ == "__main__":
    unittest.main()
