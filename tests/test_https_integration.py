import socket
import ssl
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import trustme

from core.http_transport import HTTPTransport
from core.scope_guard import ScopeGuard


class FakePolicy:
    """Policy used only for local integration tests."""

    def __init__(self):
        self.requests_per_second = 100
        self.max_concurrent_requests = 2

        self.scope_guard = ScopeGuard(
            allowed=["*.example.com"],
            excluded=[]
        )

    def can_scan(self):
        return True

    def check_url(self, url):
        return self.scope_guard.check_url(url)

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


class HTTPSHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header(
                "Location",
                "https://external.com/"
            )
            body = b""
        else:
            self.send_response(200)
            body = b"Secure Vultron"

        self.send_header(
            "Content-Length",
            str(len(body))
        )
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class QuietHTTPSServer(ThreadingHTTPServer):
    """Suppress expected TLS handshake errors in negative tests."""

    def handle_error(self, request, client_address):
        pass


class TestHTTPSIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Create a temporary CA and a certificate valid
        # only for api.example.com.
        cls.ca = trustme.CA()
        cls.certificate = cls.ca.issue_cert(
            "api.example.com"
        )

        server_context = ssl.SSLContext(
            ssl.PROTOCOL_TLS_SERVER
        )
        cls.certificate.configure_cert(server_context)

        cls.server = QuietHTTPSServer(
            ("127.0.0.1", 0),
            HTTPSHandler
        )
        cls.server.daemon_threads = True

        cls.server.socket = server_context.wrap_socket(
            cls.server.socket,
            server_side=True
        )

        cls.server_thread = threading.Thread(
            target=cls.server.serve_forever,
            daemon=True
        )
        cls.server_thread.start()

        # Keep the original function outside mock replacement.
        cls.real_create_connection = staticmethod(
            socket.create_connection
        )

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=5)

    def setUp(self):
        self.transport = HTTPTransport(
            FakePolicy(),
            resolver=fake_resolver,
            timeout=3.0
        )

    def local_connection(
            self,
            address,
            timeout=None,
            source_address=None
    ):
        if address != ("1.1.1.1", 443):
            raise AssertionError(
                f"Unexpected connection target: {address}"
            )

        return self.real_create_connection(
            ("127.0.0.1", self.server.server_port),
            timeout=timeout,
            source_address=source_address
        )

    def send_request(self, url, client_context):
        with (
            patch(
                "core.http_transport.socket.create_connection",
                side_effect=self.local_connection
            ) as mocked_socket,
            patch(
                "core.http_transport.ssl.create_default_context",
                return_value=client_context
            )
        ):
            try:
                return self.transport.request(url)
            finally:
                # Failed TLS handshakes still count as
                # attempted pinned connections.
                self.assertEqual(
                    mocked_socket.call_count, 1
                )

    def test_valid_certificate(self):
        context = ssl.create_default_context()

        # Trust only our temporary testing CA in addition
        # to the default system trust store.
        self.ca.configure_trust(context)

        self.assertTrue(context.verify_mode == ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

        result = self.send_request(
            "https://api.example.com/",
            context
        )

        self.assertEqual(result.status, 200)
        self.assertEqual(
            result.body,
            b"Secure Vultron"
        )

    def test_wrong_hostname_rejected(self):
        context = ssl.create_default_context()
        self.ca.configure_trust(context)

        # Server certificate is for api.example.com,
        # but the requested hostname is different.
        with self.assertRaises(
                ssl.SSLCertVerificationError
        ):
            self.send_request(
                "https://other.example.com/",
                context
            )

    def test_untrusted_certificate_rejected(self):
        # This context does not trust our temporary CA.
        context = ssl.create_default_context()

        with self.assertRaises(
                ssl.SSLCertVerificationError
        ):
            self.send_request(
                "https://api.example.com/",
                context
            )

    def test_https_redirect_not_followed(self):
        context = ssl.create_default_context()
        self.ca.configure_trust(context)

        result = self.send_request(
            "https://api.example.com/redirect",
            context
        )

        self.assertEqual(result.status, 302)
        self.assertEqual(
            dict(result.headers)["Location"],
            "https://external.com/"
        )


if __name__ == "__main__":
    unittest.main()
