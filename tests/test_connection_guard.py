import socket
import unittest

from core.connection_guard import ConnectionGuard
from core.scope_guard import ScopeGuard


class FakePolicy:
    """Minimal policy for isolated connection tests."""

    def __init__(self, enabled=True):
        self.enabled = enabled

        self.scope_guard = ScopeGuard(
            allowed=[
                "example.com",
                "*.example.com",
                "8.8.4.4"
            ],
            excluded=[
                "admin.example.com",
                "8.8.8.8"
            ]
        )

    def can_scan(self):
        return self.enabled

    def check_host(self, hostname):
        return self.scope_guard.check_host(hostname)


class TestConnectionGuard(unittest.TestCase):

    @staticmethod
    def make_resolver(*addresses):
        def resolver(hostname, port, **kwargs):
            results = []

            for address in addresses:
                family = (
                    socket.AF_INET6
                    if ":" in address
                    else socket.AF_INET
                )

                results.append((
                    family,
                    socket.SOCK_STREAM,
                    6,
                    "",
                    (address, 0)
                ))

            return results

        return resolver

    def test_allowed_dns(self):
        guard = ConnectionGuard(
            FakePolicy(),
            self.make_resolver("1.1.1.1")
        )

        plan = guard.resolve("api.example.com")
        self.assertEqual(plan.addresses, ("1.1.1.1",))

    def test_mixed_private_ip(self):
        guard = ConnectionGuard(
            FakePolicy(),
            self.make_resolver(
                "1.1.1.1",
                "192.168.1.10"
            )
        )

        with self.assertRaises(PermissionError):
            guard.resolve("api.example.com")

    def test_localhost_ip(self):
        guard = ConnectionGuard(
            FakePolicy(),
            self.make_resolver("127.0.0.1")
        )

        with self.assertRaises(PermissionError):
            guard.resolve("api.example.com")

    def test_excluded_public_ip(self):
        guard = ConnectionGuard(
            FakePolicy(),
            self.make_resolver("8.8.8.8")
        )

        with self.assertRaises(PermissionError):
            guard.resolve("api.example.com")

    def test_dns_failure(self):
        def failed_resolver(*args, **kwargs):
            raise socket.gaierror("DNS lookup failed")

        guard = ConnectionGuard(
            FakePolicy(),
            failed_resolver
        )

        with self.assertRaises(ConnectionError):
            guard.resolve("api.example.com")

    def test_empty_dns(self):
        guard = ConnectionGuard(
            FakePolicy(),
            self.make_resolver()
        )

        with self.assertRaises(ConnectionError):
            guard.resolve("api.example.com")

    def test_duplicate_addresses(self):
        guard = ConnectionGuard(
            FakePolicy(),
            self.make_resolver(
                "1.1.1.1",
                "1.1.1.1"
            )
        )

        plan = guard.resolve("api.example.com")
        self.assertEqual(plan.addresses, ("1.1.1.1",))

    def test_ipv6(self):
        ipv6 = "2606:4700:4700::1111"

        guard = ConnectionGuard(
            FakePolicy(),
            self.make_resolver(ipv6)
        )

        plan = guard.resolve("api.example.com")
        self.assertEqual(plan.addresses, (ipv6,))

    def test_out_of_scope(self):
        guard = ConnectionGuard(
            FakePolicy(),
            self.make_resolver("1.1.1.1")
        )

        with self.assertRaises(PermissionError):
            guard.resolve("external.com")

    def test_scanning_disabled(self):
        guard = ConnectionGuard(
            FakePolicy(enabled=False),
            self.make_resolver("1.1.1.1")
        )

        with self.assertRaises(PermissionError):
            guard.resolve("api.example.com")

    def test_allowed_ip_literal(self):
        def should_not_resolve(*args, **kwargs):
            raise AssertionError(
                "IP literals must not require DNS."
            )

        guard = ConnectionGuard(
            FakePolicy(),
            should_not_resolve
        )

        plan = guard.resolve("8.8.4.4")
        self.assertEqual(plan.addresses, ("8.8.4.4",))


if __name__ == "__main__":
    unittest.main()
