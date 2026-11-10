import http.client
import socket
import ssl

from dataclasses import dataclass
from urllib.parse import urlsplit

from core.connection_guard import ConnectionGuard
from core.request_manager import RequestManager
from core.header_manager import HeaderManager


class PinnedHTTPConnection(http.client.HTTPConnection):
    """Connect to a verified IP while preserving the HTTP hostname."""

    def __init__(self, hostname, port, pinned_ip, timeout):
        super().__init__(hostname, port=port, timeout=timeout)
        self.pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self.pinned_ip, self.port),
            timeout=self.timeout,
            source_address=self.source_address
        )


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a verified IP with hostname-based TLS validation."""

    def __init__(self, hostname, port, pinned_ip, timeout):
        super().__init__(
            hostname,
            port=port,
            timeout=timeout,
            context=ssl.create_default_context()
        )
        self.pinned_ip = pinned_ip

    def connect(self):
        raw_socket = socket.create_connection(
            (self.pinned_ip, self.port),
            timeout=self.timeout,
            source_address=self.source_address
        )

        try:
            self.sock = self._context.wrap_socket(
                raw_socket,
                server_hostname=self.host
            )
        except Exception:
            raw_socket.close()
            raise


@dataclass(frozen=True)
class TransportResponse:
    url: str
    status: int
    headers: tuple
    body: bytes
    truncated: bool


class HTTPTransport:
    """
    Policy-controlled HTTP transport.

    Redirects are never automatically followed.
    Only approved, globally routable IPs are used.
    """

    def __init__(
        self,
        policy,
        resolver=None,
        timeout=5.0,
        max_response_bytes=262144,
        http_factory=PinnedHTTPConnection,
        https_factory=PinnedHTTPSConnection,
        request_manager=None
    ):

        if (
            type(timeout) not in (int, float)
            or not 0 < timeout <= 60
        ):
            raise ValueError("Invalid connection timeout.")

        if (
            type(max_response_bytes) is not int
            or max_response_bytes < 1
        ):
            raise ValueError("Invalid response size limit.")


        if request_manager is not None:
            if not isinstance(request_manager, RequestManager):
                raise TypeError(
                    "request_manager must be a RequestManager instance."
                )

            if request_manager.policy is not policy:
                raise ValueError(
                    "RequestManager and HTTPTransport must "
                    "use the same policy instance."
                )

        self.request_manager = (
            request_manager
            if request_manager is not None
            else RequestManager(policy)
        )

        self.connection_guard = ConnectionGuard(
            policy,
            resolver=resolver
        )

        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.headers = HeaderManager(
            getattr(policy, "headers", {})
        ).build()
        self.http_factory = http_factory
        self.https_factory = https_factory

    def request(self, url, method="GET"):
        """Send one checked HTTP request with no redirect following."""

        with self.request_manager.permit(url, method) as plan:
            connection_plan = self.connection_guard.resolve(
                plan.hostname
            )

            # Revalidate before creating the connection.
            plan = self.request_manager.prepare(
                plan.url,
                plan.method
            )

            parsed = urlsplit(plan.url)
            hostname = parsed.hostname
            is_https = parsed.scheme == "https"
            port = 443 if is_https else 80

            # All DNS addresses were validated by ConnectionGuard.
            # Use one validated IP, not a new hostname lookup.
            pinned_ip = connection_plan.addresses[0]

            factory = (
                self.https_factory
                if is_https
                else self.http_factory
            )

            connection = factory(
                hostname,
                port,
                pinned_ip,
                self.timeout
            )

            path = parsed.path or "/"

            if parsed.query:
                path += "?" + parsed.query

            try:
                connection.request(
                    method=plan.method,
                    url=path,
                    headers=self.headers
                )

                response = connection.getresponse()

                headers = tuple(response.getheaders())

                # Read only a bounded amount of response data.
                body = response.read(
                    self.max_response_bytes + 1
                )

                truncated = (
                    len(body) > self.max_response_bytes
                )

                if truncated:
                    body = body[:self.max_response_bytes]

                return TransportResponse(
                    url=plan.url,
                    status=response.status,
                    headers=headers,
                    body=body,
                    truncated=truncated
                )

            finally:
                connection.close()
