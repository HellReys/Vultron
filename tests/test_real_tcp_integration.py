import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import yaml

from core.policy_engine import PolicyEngine
from core.program_context import ProgramContext
from core.scan_orchestrator import ScanOrchestrator
from core.scan_report import ScanReportWriter

TEST_HOST = "example.com"
TEST_IP = "1.1.1.1"
LOCAL_IP = "127.0.0.1"


def test_resolver(hostname, port, **kwargs):
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            (TEST_IP, 0),
        )
    ]


def local_resolver(hostname, port, **kwargs):
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            (LOCAL_IP, 0),
        )
    ]


class LocalSocketAdapter:
    """Test-only socket adapter using real loopback TCP."""

    def __init__(self, family, socktype, expected_port):
        self.sock = socket.socket(family, socktype)
        self.expected_port = expected_port

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.sock.close()

    def settimeout(self, timeout):
        self.sock.settimeout(timeout)

    def connect_ex(self, address):
        if address != (TEST_IP, self.expected_port):
            raise AssertionError("Unexpected TCP destination.")

        return self.sock.connect_ex(
            (LOCAL_IP, self.expected_port)
        )

    def recv(self, size):
        return self.sock.recv(size)


class TestRealTCPIntegration(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def create_pipeline(self, port):
        config = {
            "program": {"name": "Local TCP Integration"},
            "scope": {
                "allowed": [TEST_HOST],
                "excluded": [],
            },
            "scanning": {
                "enabled": True,
                "authorization_confirmed": True,
                "requests_per_second": 100,
                "max_concurrent_requests": 1,
                "max_requests": 2,
            },
            "tcp_scanning": {
                "enabled": True,
                "allowed_ports": [port],
                "connections_per_second": 100,
                "max_connections": 1,
                "banner_grabbing_enabled": True,
            },
        }

        config_path = self.root / "policy.yaml"
        config_path.write_text(
            yaml.safe_dump(config),
            encoding="utf-8",
        )

        policy = PolicyEngine(config_path)
        context = ProgramContext(policy)

        return ScanOrchestrator(context), context

    @staticmethod
    def socket_factory(port):
        return lambda family, socktype: LocalSocketAdapter(
            family, socktype, port
        )

    def test_real_open_port_and_json_report(self):
        with socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        ) as listener:
            listener.bind((LOCAL_IP, 0))
            listener.listen(1)
            listener.settimeout(3)

            port = listener.getsockname()[1]
            errors = []

            def serve():
                try:
                    connection, _ = listener.accept()
                    with connection:
                        connection.sendall(
                            b"SSH-2.0-OpenSSH_9.6p1\r\n"
                        )
                except OSError as error:
                    errors.append(error)

            worker = threading.Thread(
                target=serve,
                daemon=True,
            )
            worker.start()

            try:
                orchestrator, context = (
                    self.create_pipeline(port)
                )

                summary = orchestrator.scan_tcp(
                    TEST_HOST,
                    ports=[port],
                    resolver=test_resolver,
                    socket_factory=self.socket_factory(port),
                )
            finally:
                worker.join(timeout=3)

            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])

        self.assertEqual(summary.open_ports, (port,))
        self.assertEqual(summary.attempted_connections, 1)
        self.assertEqual(context.tcp_budget.used, 1)
        self.assertEqual(summary.results[0].service, "SSH")

        writer = ScanReportWriter(self.root / "reports")
        path = writer.write(
            summary,
            tcp_budget_used=1,
            tcp_budget_limit=1,
        )

        report = json.loads(
            path.read_text(encoding="utf-8")
        )

        self.assertEqual(report["total_open_ports"], 1)
        self.assertEqual(
            report["results"][0]["status"], "OPEN"
        )
        self.assertEqual(
            report["results"][0]["banner"], "[REDACTED]"
        )
        self.assertNotIn(
            "OpenSSH_9.6p1",
            path.read_text(encoding="utf-8"),
        )

    def test_real_closed_port(self):
        with socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        ) as reserved:
            reserved.bind((LOCAL_IP, 0))
            port = reserved.getsockname()[1]

            orchestrator, context = (
                self.create_pipeline(port)
            )

            summary = orchestrator.scan_tcp(
                TEST_HOST,
                ports=[port],
                resolver=test_resolver,
                socket_factory=self.socket_factory(port),
            )

        self.assertEqual(summary.open_ports, ())
        self.assertEqual(summary.attempted_connections, 1)
        self.assertFalse(summary.results[0].open)
        self.assertEqual(context.tcp_budget.used, 1)

    def test_loopback_address_still_blocked(self):
        orchestrator, context = self.create_pipeline(443)
        factory = MagicMock()

        with self.assertRaises(PermissionError):
            orchestrator.scan_tcp(
                TEST_HOST,
                ports=[443],
                resolver=local_resolver,
                socket_factory=factory,
            )

        factory.assert_not_called()
        self.assertEqual(context.tcp_budget.used, 0)


if __name__ == "__main__":
    unittest.main()
