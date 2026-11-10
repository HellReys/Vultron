import socket
import threading
import unittest
import time

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from core.http_transport import HTTPTransport
from core.scope_guard import ScopeGuard


class FakePolicy:
    """Test-only policy. Never use for real scanning."""

    def __init__(self):
        self.requests_per_second = 100
        self.max_concurrent_requests = 2

        self.scope_guard = ScopeGuard(
            allowed=["example.com", "*.example.com"],
            excluded=["admin.example.com"]
        )
        self.headers = {
            "User-Agent": "Vultron-Test/1.0",
            "X-Bug-Bounty-Researcher": "integration-test"
        }

    def can_scan(self):
        return True

    def check_url(self, url):
        return self.scope_guard.check_url(url)

    def check_host(self, hostname):
        return self.scope_guard.check_host(hostname)


def fake_resolver(hostname, port, **kwargs):
    """Return a public test address without DNS traffic."""
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("1.1.1.1", 0)
        )
    ]


class LocalHandler(BaseHTTPRequestHandler):
    """Minimal local HTTP server for integration tests."""

    def respond(self, status, body=b"", headers=None):
        self.send_response(status)

        for name, value in (headers or {}).items():
            self.send_header(name, value)

        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        if self.path == "/researcher":
            researcher = self.headers.get(
                "X-Bug-Bounty-Researcher", ""
            )

            user_agent = self.headers.get(
                "User-Agent", ""
            )

            body = f"{researcher}|{user_agent}".encode("utf-8")

            self.respond(200, body)

        elif self.path == "/hello":
            self.respond(200, b"Hello from Vultron")

        elif self.path == "/host":
            host = self.headers.get("Host", "")
            self.respond(200, host.encode("utf-8"))

        elif self.path == "/redirect":
            self.respond(
                302,
                headers={
                    "Location": "https://external.com/"
                }
            )

        elif self.path == "/large":
            self.respond(200, b"A" * 1024)



        elif self.path == "/slow":

            time.sleep(0.3)

            try:

                self.respond(200, b"Delayed response")

            except (

                    BrokenPipeError,

                    ConnectionResetError,

                    ConnectionAbortedError

            ):

                # Expected when the client closes a timed-out connection.

                pass

        else:
            self.respond(404, b"Not Found")

    def do_HEAD(self):
        self.respond(200, b"HEAD response")

    def log_message(self, format, *args):
        # Keep unittest output clean.
        pass


class TestHTTPIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            LocalHandler
        )
        cls.server.daemon_threads = True

        cls.server_thread = threading.Thread(
            target=cls.server.serve_forever,
            daemon=True
        )
        cls.server_thread.start()

        # Save the real socket function before patching.
        cls.real_create_connection = staticmethod(socket.create_connection)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=5)

    def setUp(self):
        self.transport = HTTPTransport(
            FakePolicy(),
            resolver=fake_resolver,
            timeout=3.0,
            max_response_bytes=64
        )

    def test_custom_headers_reach_server(self):
        result = self.send_local_request(
            "http://api.example.com/researcher"
        )

        self.assertEqual(result.status, 200)

        self.assertEqual(
            result.body,
            b"integration-test|Vultron-Test/1.0"
        )

    def local_connection(self, address, timeout=None,
                         source_address=None):
        # Only the pre-approved, pinned test destination
        # may be redirected to our local server.
        if address != ("1.1.1.1", 80):
            raise AssertionError(
                f"Unexpected connection target: {address}"
            )

        return self.real_create_connection(
            ("127.0.0.1", self.server.server_port),
            timeout=timeout,
            source_address=source_address
        )

    def send_local_request(self, url, method="GET"):
        with patch(
            "core.http_transport.socket.create_connection",
            side_effect=self.local_connection
        ) as mocked_connection:

            result = self.transport.request(url, method)

            self.assertEqual(mocked_connection.call_count, 1)

            args, _ = mocked_connection.call_args
            self.assertEqual(args[0], ("1.1.1.1", 80))

            return result

    def test_real_http_get(self):
        result = self.send_local_request(
            "http://api.example.com/hello"
        )

        self.assertEqual(result.status, 200)
        self.assertEqual(
            result.body,
            b"Hello from Vultron"
        )

    def test_host_header(self):
        result = self.send_local_request(
            "http://api.example.com/host"
        )

        self.assertEqual(result.status, 200)
        self.assertEqual(
            result.body,
            b"api.example.com"
        )

    def test_redirect_not_followed(self):
        result = self.send_local_request(
            "http://api.example.com/redirect"
        )

        self.assertEqual(result.status, 302)

        headers = dict(result.headers)

        self.assertEqual(
            headers["Location"],
            "https://external.com/"
        )

    def test_response_truncation(self):
        result = self.send_local_request(
            "http://api.example.com/large"
        )

        self.assertEqual(result.status, 200)
        self.assertEqual(len(result.body), 64)
        self.assertTrue(result.truncated)

    def test_real_http_head(self):
        result = self.send_local_request(
            "http://api.example.com/hello",
            method="HEAD"
        )

        self.assertEqual(result.status, 200)
        self.assertEqual(result.body, b"")

    def test_response_header_timeout(self):
        transport = HTTPTransport(
            FakePolicy(),
            resolver=fake_resolver,
            timeout=0.1
        )

        with patch(
            "core.http_transport.socket.create_connection",
            side_effect=self.local_connection
        ):
            with self.assertRaises(TimeoutError):
                transport.request(
                    "http://api.example.com/slow"
                )


if __name__ == "__main__":
    unittest.main()
