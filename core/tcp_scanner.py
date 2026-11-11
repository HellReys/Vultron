import ipaddress
import socket
from dataclasses import dataclass

from core.connection_guard import ConnectionGuard
from core.rate_limiter import RateLimiter
from core.request_budget import RequestBudget
from core.service_fingerprint import ServiceFingerprinter


@dataclass(frozen=True)
class TCPPortResult:
    host: str
    ip_address: str
    port: int
    open: bool
    service: str = "Unknown"
    banner: str = ""
    confidence: str = "none"


class PolicyAwareTCPScanner:
    """TCP connect scanner with explicit program-level controls."""

    def __init__(
            self,
            policy,
            resolver=None,
            socket_factory=None,
            timeout=2.0,
            rate_limiter=None,
            budget=None
    ):
        self.policy = policy
        self.tcp_policy = policy.tcp_policy

        if (
                type(timeout) not in (int, float)
                or not 0 < timeout <= 10
        ):
            raise ValueError("Invalid TCP timeout.")

        self.timeout = timeout
        self.socket_factory = socket_factory or socket.socket

        self.connection_guard = ConnectionGuard(
            policy,
            resolver=resolver
        )

        # Allow ProgramContext to inject shared controls.
        if rate_limiter is None:
            rate_limiter = RateLimiter(
                requests_per_second=(
                    self.tcp_policy.connections_per_second
                ),
                max_concurrent_requests=1
            )

        if budget is None:
            budget = RequestBudget(
                self.tcp_policy.max_connections
            )

        self.rate_limiter = rate_limiter
        self.budget = budget

    def _read_passive_banner(self, sock):
        """
        Read unsolicited server data from an existing TCP socket.

        Never sends any application-layer data.
        """

        sock.settimeout(min(self.timeout, 0.2))

        try:
            data = sock.recv(
                ServiceFingerprinter.MAX_BANNER_BYTES
            )

        except (socket.timeout, TimeoutError, OSError):
            data = b""

        return ServiceFingerprinter.identify(data)

    def scan(self, hostname, ports):
        """
        Scan explicitly approved ports on an approved host.

        The first validated IP is used.
        No DNS re-resolution occurs during connection.
        """

        if not self.policy.can_scan():
            raise PermissionError(
                "Active scanning is disabled."
            )

        if not self.tcp_policy.enabled:
            raise PermissionError(
                "TCP scanning is disabled by program policy."
            )

        if not isinstance(ports, (list, tuple)):
            raise ValueError("Ports must be a list or tuple.")

        if not ports:
            raise ValueError("No ports provided.")

        if any(type(port) is not int for port in ports):
            raise ValueError("Invalid port type.")

        if len(ports) != len(set(ports)):
            raise ValueError("Duplicate ports are not allowed.")

        for port in ports:
            if port not in self.tcp_policy.allowed_ports:
                raise PermissionError(
                    f"TCP port {port} is not authorized."
                )

        # Fail before scanning if the batch would exceed
        # the remaining connection budget.
        if len(ports) > self.budget.remaining:
            raise PermissionError(
                "Insufficient TCP connection budget."
            )

        connection_plan = self.connection_guard.resolve(
            hostname
        )

        ip_address = connection_plan.addresses[0]
        parsed_ip = ipaddress.ip_address(ip_address)

        family = (
            socket.AF_INET6
            if parsed_ip.version == 6
            else socket.AF_INET
        )

        results = []

        for port in ports:
            with self.rate_limiter.limit():
                self.budget.consume()

                service = "Unknown"
                banner = ""
                confidence = "none"

                with self.socket_factory(
                        family,
                        socket.SOCK_STREAM
                ) as sock:
                    sock.settimeout(self.timeout)

                    try:
                        result = sock.connect_ex(
                            (ip_address, port)
                        )
                        is_open = result == 0

                    except OSError:
                        is_open = False

                    if (
                            is_open
                            and self.tcp_policy.banner_grabbing_enabled
                    ):
                        fingerprint = self._read_passive_banner(
                            sock
                        )

                        service = fingerprint.service
                        banner = fingerprint.banner
                        confidence = fingerprint.confidence

                results.append(
                    TCPPortResult(
                        host=hostname,
                        ip_address=ip_address,
                        port=port,
                        open=is_open,
                        service=service,
                        banner=banner,
                        confidence=confidence
                    )
                )

        return results