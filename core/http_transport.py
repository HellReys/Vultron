import http.client
import socket
import ssl

from dataclasses import dataclass
from urllib.parse import urlsplit

from core.connection_guard import ConnectionGuard
from core.request_manager import RequestManager
from core.header_manager import HeaderManager
from core.request_deadline import RequestDeadline


class PinnedHTTPConnection(http.client.HTTPConnection):
    """Connect to a verified IP while preserving the HTTP hostname."""

    def __init__(self, hostname, port, pinned_ip, timeout):
        super().__init__(hostname, port=port, timeout=timeout)
        self.pinned_ip = pinned_ip

    def connect(self):
        deadline = getattr(self, "deadline", None)

        timeout = (
            deadline.socket_timeout(self.timeout)
            if deadline is not None
            else self.timeout
        )

        self.sock = socket.create_connection(
            (self.pinned_ip, self.port),
            timeout=timeout,
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
        deadline = getattr(self, "deadline", None)

        timeout = (
            deadline.socket_timeout(self.timeout)
            if deadline is not None
            else self.timeout
        )

        raw_socket = socket.create_connection(
            (self.pinned_ip, self.port),
            timeout=timeout,
            source_address=self.source_address
        )

        try:
            if deadline is not None:
                raw_socket.settimeout(
                    deadline.socket_timeout(self.timeout)
                )

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

    @staticmethod
    def _set_remaining_timeout(connection, deadline):
        remaining = deadline.remaining()

        if connection.sock is not None:
            connection.sock.settimeout(remaining)

    def _read_response_body(
        self,
        response,
        connection,
        deadline
    ):
        """
        Read a bounded response body with a shared deadline.

        Real HTTPResponse objects use incremental read1().
        Test doubles retain their existing read() interface.
        """

        if not isinstance(response, http.client.HTTPResponse):
            body = response.read(self.max_response_bytes + 1)
            deadline.remaining()

            return (
                body[:self.max_response_bytes],
                len(body) > self.max_response_bytes
            )

        chunks = []
        total = 0
        read_limit = self.max_response_bytes + 1

        while total < read_limit:
            self._set_remaining_timeout(
                connection,
                deadline
            )

            chunk = response.read1(
                min(16384, read_limit - total)
            )

            deadline.remaining()

            if not chunk:
                break

            chunks.append(chunk)
            total += len(chunk)

        body = b"".join(chunks)

        return (
            body[:self.max_response_bytes],
            len(body) > self.max_response_bytes
        )

    def request(self, url, method="GET"):
        """Send one policy checked HTTP request with a deadline."""

        with self.request_manager.permit(url, method) as plan:
            connection_plan = self.connection_guard.resolve(
                plan.hostname
            )

            plan = self.request_manager.prepare(
                plan.url,
                plan.method
            )

            parsed = urlsplit(plan.url)

            hostname = parsed.hostname
            is_https = parsed.scheme == "https"
            port = 443 if is_https else 80

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

            # The network-phase deadline starts here.
            deadline = RequestDeadline(self.timeout)
            connection.deadline = deadline

            try:
                deadline.remaining()

                connection.request(
                    method=plan.method,
                    url=path,
                    headers=self.headers
                )

                self._set_remaining_timeout(
                    connection,
                    deadline
                )

                response = connection.getresponse()

                deadline.remaining()

                headers = tuple(response.getheaders())

                body, truncated = self._read_response_body(
                    response,
                    connection,
                    deadline
                )

                deadline.remaining()

                return TransportResponse(
                    url=plan.url,
                    status=response.status,
                    headers=headers,
                    body=body,
                    truncated=truncated
                )

            finally:
                connection.close()