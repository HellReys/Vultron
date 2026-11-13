import socket
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from core.http_probe import probe_http_services
from core.http_transport import TransportResponse


def make_summary(*ports):
    return SimpleNamespace(
        target="example.com",
        results=tuple(
            SimpleNamespace(port=port, open=True)
            for port in ports
        ),
    )


def make_response(url, server=None):
    headers = (
        (("Server", server),)
        if server
        else (("Content-Type", "text/html"),)
    )

    return TransportResponse(
        url=url,
        status=200,
        headers=headers,
        body=b"",
        truncated=False,
    )


class TestHTTPProbe(unittest.TestCase):

    def setUp(self):
        self.transport = MagicMock()
        self.context = MagicMock()
        self.context.create_http_transport.return_value = (
            self.transport
        )

    def test_http_port_80(self):
        self.transport.request.return_value = make_response(
            "http://example.com/",
            "nginx/1.24.0",
        )

        results = probe_http_services(
            self.context,
            make_summary(80),
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "OK")
        self.assertEqual(
            results[0].fingerprint.service, "HTTP"
        )
        self.assertEqual(
            results[0].fingerprint.product, "nginx"
        )

        self.transport.request.assert_called_once_with(
            "http://example.com/",
            method="GET",
        )

    def test_https_port_443(self):
        self.transport.request.return_value = make_response(
            "https://example.com/",
        )

        results = probe_http_services(
            self.context,
            make_summary(443),
        )

        self.assertEqual(
            results[0].fingerprint.service, "HTTPS"
        )
        self.transport.request.assert_called_once_with(
            "https://example.com/",
            method="GET",
        )

    def test_only_supported_ports_are_probed(self):
        self.transport.request.side_effect = [
            make_response("http://example.com/"),
            make_response("https://example.com/"),
        ]

        results = probe_http_services(
            self.context,
            make_summary(22, 80, 443, 8080),
        )

        self.assertEqual(
            [item.port for item in results],
            [80, 443],
        )
        self.assertEqual(
            self.transport.request.call_count,
            2,
        )

    def test_no_http_port_means_no_transport(self):
        results = probe_http_services(
            self.context,
            make_summary(22),
        )

        self.assertEqual(results, ())
        self.context.create_http_transport.assert_not_called()

    def test_network_error_is_reported(self):
        self.transport.request.side_effect = socket.timeout()

        results = probe_http_services(
            self.context,
            make_summary(443),
        )

        self.assertEqual(
            results[0].status,
            "NETWORK_ERROR",
        )

    def test_permission_error_is_not_suppressed(self):
        self.transport.request.side_effect = PermissionError(
            "HTTP budget exhausted"
        )

        with self.assertRaises(PermissionError):
            probe_http_services(
                self.context,
                make_summary(443),
            )

    def test_closed_ports_are_not_probed(self):
        summary = SimpleNamespace(
            target="example.com",
            results=(
                SimpleNamespace(port=80, open=False),
                SimpleNamespace(port=443, open=False),
            ),
        )

        results = probe_http_services(
            self.context,
            summary,
        )

        self.assertEqual(results, ())
        self.context.create_http_transport.assert_not_called()


if __name__ == "__main__":
    unittest.main()
