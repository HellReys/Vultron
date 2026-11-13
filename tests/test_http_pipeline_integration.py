import json
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import yaml

from core.http_probe import probe_http_services
from core.http_transport import HTTPTransport
from core.policy_engine import PolicyEngine
from core.program_context import ProgramContext
from core.request_budget import RequestBudgetExceeded
from core.scan_orchestrator import ScanSummary
from core.scan_report import ScanReportWriter
from core.tcp_scanner import TCPPortResult

TEST_IP = "1.1.1.1"
LOCAL_IP = "127.0.0.1"


def fake_resolver(hostname, port, **kwargs):
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            (TEST_IP, 0),
        )
    ]


class TestHTTPHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version = ""

    request_count = 0
    redirect_enabled = False

    def do_GET(self):
        type(self).request_count += 1

        if type(self).redirect_enabled:
            self.send_response(302)
            self.send_header(
                "Location",
                "https://external.example/",
            )
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        body = b"PRIVATE_RESPONSE_TOKEN"

        self.send_response(200)
        self.send_header(
            "Set-Cookie",
            "session=SECRET_COOKIE",
        )
        self.send_header(
            "Content-Length",
            str(len(body)),
        )
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class TestHTTPPipelineIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.real_create_connection = (
            socket.create_connection
        )

        cls.server = ThreadingHTTPServer(
            (LOCAL_IP, 0),
            TestHTTPHandler,
        )
        cls.server.daemon_threads = True

        cls.thread = threading.Thread(
            target=cls.server.serve_forever,
            daemon=True,
        )
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)

        self.root = Path(temporary.name)
        TestHTTPHandler.request_count = 0
        TestHTTPHandler.redirect_enabled = False

    def create_context(self, max_requests=2):
        config = {
            "program": {
                "name": "HTTP Integration Test",
            },
            "scope": {
                "allowed": ["example.com"],
                "excluded": ["admin.example.com"],
            },
            "scanning": {
                "enabled": True,
                "authorization_confirmed": True,
                "requests_per_second": 100,
                "max_concurrent_requests": 1,
                "max_requests": max_requests,
            },
            "tcp_scanning": {
                "enabled": True,
                "allowed_ports": [80],
                "connections_per_second": 100,
                "max_connections": 1,
                "banner_grabbing_enabled": False,
            },
        }

        path = self.root / "policy.yaml"

        path.write_text(
            yaml.safe_dump(config),
            encoding="utf-8",
        )

        return ProgramContext(PolicyEngine(path))

    @staticmethod
    def create_summary(target="example.com"):
        result = TCPPortResult(
            host=target,
            ip_address=TEST_IP,
            port=80,
            open=True,
            service="Unknown",
            banner="",
            confidence="none",
        )

        return ScanSummary(
            target=target,
            results=(result,),
            open_ports=(80,),
            attempted_connections=1,
        )

    def local_connection(
        self,
        address,
        timeout=None,
        source_address=None,
    ):
        if address != (TEST_IP, 80):
            raise AssertionError(
                f"Unexpected network destination: {address}"
            )

        return type(self).real_create_connection(
            (LOCAL_IP, self.server.server_port),
            timeout=timeout,
            source_address=source_address,
        )

    def run_probe(self, context, summary):
        transport = HTTPTransport(
            context.policy,
            resolver=fake_resolver,
            timeout=3.0,
            max_response_bytes=128,
            request_manager=context.request_manager,
        )

        with (
            patch.object(
                context,
                "create_http_transport",
                return_value=transport,
            ),
            patch(
                "core.http_transport.socket.create_connection",
                side_effect=self.local_connection,
            ),
        ):
            return probe_http_services(context, summary)

    def test_real_http_to_json_report(self):
        context = self.create_context()
        summary = self.create_summary()

        http_results = self.run_probe(
            context,
            summary,
        )

        writer = ScanReportWriter(
            self.root / "reports"
        )

        path = writer.write(
            summary,
            tcp_budget_used=1,
            tcp_budget_limit=1,
            http_results=http_results,
        )

        report_text = path.read_text(
            encoding="utf-8"
        )
        report = json.loads(report_text)

        self.assertEqual(
            TestHTTPHandler.request_count, 1
        )
        self.assertEqual(
            context.request_manager.request_budget.used,
            1,
        )

        self.assertEqual(report["schema_version"], 2)

        http = report["http_fingerprints"][0]

        self.assertEqual(http["port"], 80)
        self.assertEqual(http["status"], "OK")
        self.assertEqual(http["service"], "HTTP")
        self.assertEqual(http["product"], "nginx")
        self.assertEqual(http["version"], "1.24.0")
        self.assertFalse(http["evidence_verified"])

        self.assertNotIn(
            "SECRET_COOKIE",
            report_text,
        )
        self.assertNotIn(
            "PRIVATE_RESPONSE_TOKEN",
            report_text,
        )

    def test_excluded_target_blocked(self):
        context = self.create_context()
        summary = self.create_summary(
            "admin.example.com"
        )

        with self.assertRaises(PermissionError):
            self.run_probe(context, summary)

        self.assertEqual(
            TestHTTPHandler.request_count, 0
        )
        self.assertEqual(
            context.request_manager.request_budget.used,
            0,
        )

    def test_shared_http_budget_is_enforced(self):
        context = self.create_context(
            max_requests=1
        )
        summary = self.create_summary()

        self.run_probe(context, summary)

        with self.assertRaises(
            RequestBudgetExceeded
        ):
            self.run_probe(context, summary)

        self.assertEqual(
            TestHTTPHandler.request_count, 1
        )
        self.assertEqual(
            context.request_manager.request_budget.used,
            1,
        )

    def test_redirect_is_not_followed(self):
        TestHTTPHandler.redirect_enabled = True

        context = self.create_context()
        summary = self.create_summary()

        results = self.run_probe(
            context,
            summary,
        )

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "OK")
        self.assertEqual(
            TestHTTPHandler.request_count, 1
        )
        self.assertEqual(
            context.request_manager.request_budget.used,
            1,
        )


if __name__ == "__main__":
    unittest.main()
