import ipaddress
import socket
from dataclasses import dataclass

from core.connection_guard import ConnectionGuard
from core.rate_limiter import RateLimiter
from core.request_budget import RequestBudget


@dataclass(frozen=True)
class TCPPortResult:
    host: str
    ip_address: str
    port: int
    open: bool


class PolicyAwareTCPScanner:
    """TCP connect scanner with explicit program-level controls."""

    def __init__(
        self,
        policy,
        resolver=None,
        socket_factory=None,
        timeout=2.0
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

        self.rate_limiter = RateLimiter(
            requests_per_second=(
                self.tcp_policy.connections_per_second
            ),
            max_concurrent_requests=1
        )

        self.budget = RequestBudget(
            self.tcp_policy.max_connections
        )

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
                # One connection attempt consumes one budget unit.
                self.budget.consume()

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

                results.append(
                    TCPPortResult(
                        host=hostname,
                        ip_address=ip_address,
                        port=port,
                        open=is_open
                    )
                )

        return results