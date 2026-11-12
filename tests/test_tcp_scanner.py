import socket
import unittest
from unittest.mock import MagicMock

from core.program_context import ProgramContext
from core.scope_guard import ScopeGuard
from core.tcp_policy import TCPScanPolicy
from core.tcp_scanner import PolicyAwareTCPScanner


class FakePolicy:
    def __init__(self, active=True, tcp_enabled=True):
        self.active = active

        # Required by ProgramContext's HTTP RequestManager.
        self.requests_per_second = 100
        self.max_concurrent_requests = 2
        self.max_requests = 20
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

class TestSharedTCPContext(unittest.TestCase):

    def setUp(self):
        self.policy = FakePolicy()

        self.context = ProgramContext(
            self.policy
        )

        def create_socket():
            sock = MagicMock()
            sock.__enter__.return_value = sock
            sock.connect_ex.return_value = 0
            return sock

        self.socket_factory = MagicMock(
            side_effect=lambda *args, **kwargs: create_socket()
        )

    def create_scanner(self):
        return self.context.create_tcp_scanner(
            resolver=fake_resolver,
            socket_factory=self.socket_factory
        )

    def test_scanners_share_budget(self):
        scanner_a = self.create_scanner()
        scanner_b = self.create_scanner()

        self.assertIs(
            scanner_a.budget,
            scanner_b.budget
        )

        self.assertIs(
            scanner_a.budget,
            self.context.tcp_budget
        )

    def test_scanners_share_rate_limiter(self):
        scanner_a = self.create_scanner()
        scanner_b = self.create_scanner()

        self.assertIs(
            scanner_a.rate_limiter,
            scanner_b.rate_limiter
        )

        self.assertIs(
            scanner_a.rate_limiter,
            self.context.tcp_rate_limiter
        )

    def test_shared_budget_exhaustion(self):
        scanner_a = self.create_scanner()
        scanner_b = self.create_scanner()

        scanner_a.scan(
            "example.com",
            [80]
        )

        scanner_b.scan(
            "example.com",
            [443]
        )

        self.assertEqual(
            self.context.tcp_budget.used,
            2
        )

        with self.assertRaises(PermissionError):
            scanner_a.scan(
                "example.com",
                [80]
            )

        self.assertEqual(
            self.socket_factory.call_count,
            2
        )

    def test_budget_separate_from_http(self):
        scanner = self.create_scanner()

        scanner.scan(
            "example.com",
            [80]
        )

        self.assertEqual(
            self.context.tcp_budget.used,
            1
        )

        self.assertEqual(
            self.context.request_manager.request_budget.used,
            0
        )

    def test_independent_context_budgets(self):
        context_b = ProgramContext(
            FakePolicy()
        )

        self.assertIsNot(
            self.context.tcp_budget,
            context_b.tcp_budget
        )

        self.assertIsNot(
            self.context.tcp_rate_limiter,
            context_b.tcp_rate_limiter
        )

    def test_context_rejects_budget_override(self):
        with self.assertRaises(ValueError):
            self.context.create_tcp_scanner(
                budget=object()
            )

    def test_context_rejects_limiter_override(self):
        with self.assertRaises(ValueError):
            self.context.create_tcp_scanner(
                rate_limiter=object()
            )

    def test_context_rejects_policy_override(self):
        with self.assertRaises(ValueError):
            self.context.create_tcp_scanner(
                policy=FakePolicy()
            )

    def test_missing_tcp_policy_rejected(self):
        policy = FakePolicy()
        del policy.tcp_policy

        context = ProgramContext(policy)

        with self.assertRaises(ValueError):
            context.create_tcp_scanner()

    def test_tcp_scanning_disabled(self):
        context = ProgramContext(
            FakePolicy(tcp_enabled=False)
        )

        scanner = context.create_tcp_scanner(
            resolver=fake_resolver,
            socket_factory=self.socket_factory
        )

        with self.assertRaises(PermissionError):
            scanner.scan(
                "example.com",
                [80]
            )

        self.socket_factory.assert_not_called()
class TestPassiveFingerprintIntegration(unittest.TestCase):

    def setUp(self):
        self.policy = FakePolicy()

        # Explicitly authorize passive banner reading
        # in this isolated test policy.
        self.policy.tcp_policy = TCPScanPolicy(
            enabled=True,
            allowed_ports=(80, 443),
            connections_per_second=100.0,
            max_connections=2,
            banner_grabbing_enabled=True
        )

        self.sock = MagicMock()
        self.sock.__enter__.return_value = self.sock
        self.sock.connect_ex.return_value = 0

        self.socket_factory = MagicMock(
            return_value=self.sock
        )

        self.scanner = PolicyAwareTCPScanner(
            policy=self.policy,
            resolver=fake_resolver,
            socket_factory=self.socket_factory
        )

    def test_ssh_identification(self):
        self.sock.recv.return_value = (
            b"SSH-2.0-OpenSSH_9.6\r\n"
        )

        results = self.scanner.scan(
            "example.com",
            [80]
        )

        self.assertEqual(results[0].service, "SSH")
        self.assertTrue(results[0].open)
        self.assertEqual(self.scanner.budget.used, 1)

        self.sock.recv.assert_called_once_with(256)
        self.sock.send.assert_not_called()
        self.sock.sendall.assert_not_called()

    def test_banner_timeout_keeps_port_open(self):
        self.sock.recv.side_effect = socket.timeout()

        results = self.scanner.scan(
            "example.com",
            [443]
        )

        self.assertTrue(results[0].open)
        self.assertEqual(results[0].service, "Unknown")
        self.assertEqual(results[0].banner, "")

    def test_disabled_fingerprinting_does_not_read(self):
        self.policy.tcp_policy = TCPScanPolicy(
            enabled=True,
            allowed_ports=(80, 443),
            connections_per_second=100.0,
            max_connections=2,
            banner_grabbing_enabled=False
        )

        scanner = PolicyAwareTCPScanner(
            policy=self.policy,
            resolver=fake_resolver,
            socket_factory=self.socket_factory
        )

        results = scanner.scan(
            "example.com",
            [80]
        )

        self.assertTrue(results[0].open)
        self.assertEqual(results[0].service, "Unknown")

        self.sock.recv.assert_not_called()

    def test_closed_port_does_not_read_banner(self):
        self.sock.connect_ex.return_value = 111

        results = self.scanner.scan(
            "example.com",
            [80]
        )

        self.assertFalse(results[0].open)
        self.sock.recv.assert_not_called()

    def test_version_information_in_tcp_result(self):
        self.sock.recv.return_value = (
            b"SSH-2.0-OpenSSH_9.6p1\r\n"
        )

        results = self.scanner.scan(
            "example.com",
            [80]
        )

        self.assertEqual(len(results), 1)

        result = results[0]

        self.assertTrue(result.open)
        self.assertEqual(result.service, "SSH")
        self.assertEqual(result.product, "OpenSSH")
        self.assertEqual(result.version, "9.6p1")

        self.assertEqual(
            result.version_source,
            "ssh_banner"
        )

        self.assertEqual(
            self.scanner.budget.used,
            1
        )

        self.sock.send.assert_not_called()
        self.sock.sendall.assert_not_called()

if __name__ == "__main__":
    unittest.main()