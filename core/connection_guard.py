import ipaddress
import socket
from dataclasses import dataclass


@dataclass(frozen=True)
class ConnectionPlan:
    hostname: str
    addresses: tuple[str, ...]


class ConnectionGuard:
    """
    Resolve and validate target IP addresses.

    This class does not establish network connections.
    DNS results must be pinned by the future HTTP transport.
    """

    def __init__(self, policy, resolver=None):
        self.policy = policy
        self.resolver = resolver or socket.getaddrinfo

    def resolve(self, hostname):
        """Resolve an approved hostname and validate every IP."""

        if not self.policy.can_scan():
            raise PermissionError(
                "Active scanning is disabled by program policy."
            )

        allowed, reason = self.policy.check_host(hostname)

        if not allowed:
            raise PermissionError(reason)

        hostname = hostname.strip().lower().rstrip(".")

        # A direct IP target must also be explicitly in scope.
        try:
            literal_ip = ipaddress.ip_address(
                hostname.strip("[]")
            )
        except ValueError:
            literal_ip = None

        if literal_ip is not None:
            addresses = [str(literal_ip)]
            hostname = str(literal_ip)
        else:
            try:
                results = self.resolver(
                    hostname,
                    None,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM
                )
            except OSError as error:
                raise ConnectionError(
                    f"DNS resolution failed for {hostname}: {error}"
                ) from error

            addresses = []

            for result in results:
                try:
                    address = result[4][0]
                    parsed_ip = ipaddress.ip_address(address)
                except (ValueError, IndexError, TypeError) as error:
                    raise ConnectionError(
                        "DNS resolver returned an invalid address."
                    ) from error

                addresses.append(str(parsed_ip))

        if not addresses:
            raise ConnectionError(
                f"No IP addresses found for {hostname}."
            )

        # Reject the entire result if any address is unsafe.
        for address in addresses:
            ip = ipaddress.ip_address(address)

            if not ip.is_global:
                raise PermissionError(
                    f"Non-global IP address blocked: {address}"
                )

            if self.policy.scope_guard.is_excluded(address):
                raise PermissionError(
                    f"Excluded IP address blocked: {address}"
                )

        # Remove duplicates and preserve deterministic order.
        unique_addresses = tuple(dict.fromkeys(addresses))

        return ConnectionPlan(
            hostname=hostname,
            addresses=unique_addresses
        )
