import time
import unittest
from unittest.mock import MagicMock

from core.http_transport import HTTPTransport
from core.program_context import ProgramContext
from core.request_budget import RequestBudgetExceeded
from core.request_manager import RequestManager
from core.scope_guard import ScopeGuard


class FakePolicy:
    def __init__(self, rate=2):
        self.requests_per_second = rate
        self.max_concurrent_requests = 2

        self.scope_guard = ScopeGuard(
            allowed=["example.com", "*.example.com"],
            excluded=["admin.example.com"]
        )

    def can_scan(self):
        return True

    def check_url(self, url):
        return self.scope_guard.check_url(url)

    def check_host(self, hostname):
        return self.scope_guard.check_host(hostname)


class TestProgramContext(unittest.TestCase):

    def setUp(self):
        self.policy = FakePolicy()
        self.context = ProgramContext(self.policy)

    def test_shared_request_manager(self):
        recon = self.context.create_http_transport()
        endpoint = self.context.create_http_transport()

        self.assertIs(
            recon.request_manager,
            endpoint.request_manager
        )

        self.assertIs(
            recon.request_manager.rate_limiter,
            endpoint.request_manager.rate_limiter
        )

    def test_shared_rate_limit(self):
        recon = self.context.create_http_transport()
        endpoint = self.context.create_http_transport()

        timestamps = []

        with recon.request_manager.permit(
            "https://example.com/"
        ):
            timestamps.append(time.monotonic())

        with endpoint.request_manager.permit(
            "https://example.com/"
        ):
            timestamps.append(time.monotonic())

        # Third request must wait even though it comes
        # through another HTTP Transport instance.
        with recon.request_manager.permit(
            "https://example.com/"
        ):
            timestamps.append(time.monotonic())

        elapsed = timestamps[2] - timestamps[0]

        self.assertGreaterEqual(elapsed, 0.85)

    def test_independent_program_contexts(self):
        other_context = ProgramContext(FakePolicy())

        self.assertIsNot(
            self.context.request_manager.rate_limiter,
            other_context.request_manager.rate_limiter
        )

    def test_wrong_policy_manager_rejected(self):
        other_policy = FakePolicy()
        other_manager = RequestManager(other_policy)

        with self.assertRaises(ValueError):
            HTTPTransport(
                policy=self.policy,
                request_manager=other_manager
            )

    def test_context_rejects_manager_override(self):
        other_manager = RequestManager(self.policy)

        with self.assertRaises(ValueError):
            self.context.create_http_transport(
                request_manager=other_manager
            )

    def test_context_rejects_policy_override(self):
        with self.assertRaises(ValueError):
            self.context.create_http_transport(
                policy=FakePolicy()
            )

    def test_transport_requests_share_budget(self):
        response = MagicMock()
        response.status = 200
        response.getheaders.return_value = []
        response.read.return_value = b"OK"

        connection = MagicMock()
        connection.getresponse.return_value = response

        factory = MagicMock(return_value=connection)

        def resolver(hostname, port, **kwargs):
            import socket

            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    6,
                    "",
                    ("1.1.1.1", 0)
                )
            ]

        transport_a = self.context.create_http_transport(
            resolver=resolver,
            https_factory=factory
        )

        transport_b = self.context.create_http_transport(
            resolver=resolver,
            https_factory=factory
        )

        start = time.monotonic()

        transport_a.request("https://example.com/")
        transport_b.request("https://example.com/")
        transport_a.request("https://example.com/")

        elapsed = time.monotonic() - start

        self.assertGreaterEqual(elapsed, 0.85)
        self.assertEqual(factory.call_count, 3)

    def test_shared_request_budget(self):
        self.policy.max_requests = 2

        context = ProgramContext(self.policy)

        recon = context.create_http_transport()
        endpoint = context.create_http_transport()

        with recon.request_manager.permit(
            "https://example.com/"
        ):
            pass

        with endpoint.request_manager.permit(
            "https://example.com/"
        ):
            pass

        with self.assertRaises(RequestBudgetExceeded):
            with recon.request_manager.permit(
                "https://example.com/"
            ):
                pass

        self.assertIs(
            recon.request_manager.request_budget,
            endpoint.request_manager.request_budget
        )

        self.assertEqual(
            context.request_manager.request_budget.used,
            2
        )


if __name__ == "__main__":
    unittest.main()
