import socket
import unittest
from unittest.mock import MagicMock, patch

from core.http_transport import (
    HTTPTransport,
    PinnedHTTPConnection,
    PinnedHTTPSConnection
)
from core.scope_guard import ScopeGuard


class FakePolicy:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.requests_per_second = 100
        self.max_concurrent_requests = 2

        self.scope_guard = ScopeGuard(
            allowed=["example.com", "*.example.com"],
            excluded=["admin.example.com"]
        )

    def can_scan(self):
        return self.enabled

    def check_url(self, url):
        return self.scope_guard.check_url(url)

    def check_host(self, host):
        return self.scope_guard.check_host(host)


def fake_resolver(host, port, **kwargs):
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("1.1.1.1", 0)
        )
    ]


class TestHTTPTransport(unittest.TestCase):

    def setUp(self):
        self.connection = MagicMock()
        self.response = MagicMock()

        self.response.status = 200
        self.response.getheaders.return_value = [
            ("Content-Type", "text/plain")
        ]
        self.response.read.return_value = b"Hello Vultron"

        self.connection.getresponse.return_value = self.response

        self.factory = MagicMock(
            return_value=self.connection
        )

        self.transport = HTTPTransport(
            FakePolicy(),
            resolver=fake_resolver,
            http_factory=self.factory,
            https_factory=self.factory
        )

    def test_allowed_https_request(self):
        result = self.transport.request(
            "https://api.example.com/test"
        )

        self.assertEqual(result.status, 200)
        self.assertEqual(result.body, b"Hello Vultron")

        self.factory.assert_called_once_with(
            "api.example.com",
            443,
            "1.1.1.1",
            5.0
        )

    def test_out_of_scope_blocked(self):
        with self.assertRaises(PermissionError):
            self.transport.request(
                "https://external.com/"
            )

        self.factory.assert_not_called()

    def test_excluded_domain_blocked(self):
        with self.assertRaises(PermissionError):
            self.transport.request(
                "https://admin.example.com/"
            )

        self.factory.assert_not_called()

    def test_scanning_disabled(self):
        transport = HTTPTransport(
            FakePolicy(enabled=False),
            resolver=fake_resolver,
            https_factory=self.factory
        )

        with self.assertRaises(PermissionError):
            transport.request("https://example.com/")

        self.factory.assert_not_called()

    def test_post_method_blocked(self):
        with self.assertRaises(PermissionError):
            self.transport.request(
                "https://example.com/",
                method="POST"
            )

        self.factory.assert_not_called()

    def test_redirect_not_followed(self):
        self.response.status = 302
        self.response.getheaders.return_value = [
            ("Location", "https://external.com/")
        ]

        result = self.transport.request(
            "https://example.com/"
        )

        self.assertEqual(result.status, 302)
        self.assertEqual(self.factory.call_count, 1)

    def test_response_size_limit(self):
        self.response.read.return_value = b"A" * 100

        transport = HTTPTransport(
            FakePolicy(),
            resolver=fake_resolver,
            max_response_bytes=32,
            https_factory=self.factory
        )

        result = transport.request(
            "https://example.com/"
        )

        self.assertEqual(len(result.body), 32)
        self.assertTrue(result.truncated)
        self.response.read.assert_called_with(33)

    def test_connection_closed_on_error(self):
        self.connection.getresponse.side_effect = OSError(
            "Simulated connection error"
        )

        with self.assertRaises(OSError):
            self.transport.request(
                "https://example.com/"
            )

        self.connection.close.assert_called_once()

    def test_dns_private_ip_blocked(self):
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

        transport = HTTPTransport(
            FakePolicy(),
            resolver=private_resolver,
            https_factory=self.factory
        )

        with self.assertRaises(PermissionError):
            transport.request(
                "https://example.com/"
            )

        self.factory.assert_not_called()


class TestPinnedConnections(unittest.TestCase):

    @patch("core.http_transport.socket.create_connection")
    def test_http_uses_pinned_ip(self, create_connection):
        connection = PinnedHTTPConnection(
            "example.com",
            80,
            "1.1.1.1",
            5.0
        )

        connection.connect()

        args, kwargs = create_connection.call_args

        self.assertEqual(args[0], ("1.1.1.1", 80))
        self.assertEqual(kwargs["timeout"], 5.0)

    @patch("core.http_transport.ssl.create_default_context")
    @patch("core.http_transport.socket.create_connection")
    def test_https_preserves_hostname(
        self,
        create_connection,
        create_context
    ):
        connection = PinnedHTTPSConnection(
            "example.com",
            443,
            "1.1.1.1",
            5.0
        )

        connection.connect()

        create_connection.assert_called_once()

        context = create_context.return_value

        context.wrap_socket.assert_called_once_with(
            create_connection.return_value,
            server_hostname="example.com"
        )


if __name__ == "__main__":
    unittest.main()
