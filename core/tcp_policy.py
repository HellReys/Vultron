import math
from dataclasses import dataclass


@dataclass(frozen=True)
class TCPScanPolicy:
    enabled: bool
    allowed_ports: tuple[int, ...]
    connections_per_second: float
    max_connections: int

    @classmethod
    def from_config(cls, config):
        if config is None:
            return cls(
                enabled=False,
                allowed_ports=(),
                connections_per_second=1.0,
                max_connections=1
            )

        if not isinstance(config, dict):
            raise ValueError(
                "tcp_scanning must be a YAML mapping."
            )

        required = {
            "enabled",
            "allowed_ports",
            "connections_per_second",
            "max_connections"
        }

        if set(config) != required:
            raise ValueError(
                "Invalid or missing tcp_scanning fields."
            )

        enabled = config["enabled"]
        ports = config["allowed_ports"]
        rate = config["connections_per_second"]
        maximum = config["max_connections"]

        if type(enabled) is not bool:
            raise ValueError("TCP enabled must be boolean.")

        if not isinstance(ports, list):
            raise ValueError("allowed_ports must be a list.")

        if len(ports) > 64:
            raise ValueError("Too many allowed ports.")

        if any(
            type(port) is not int or not 1 <= port <= 65535
            for port in ports
        ):
            raise ValueError("Invalid TCP port.")

        if len(ports) != len(set(ports)):
            raise ValueError("Duplicate TCP ports.")

        if (
            type(rate) not in (int, float)
            or not math.isfinite(rate)
            or rate <= 0
        ):
            raise ValueError("Invalid TCP connection rate.")

        if type(maximum) is not int or maximum < 1:
            raise ValueError("Invalid TCP connection budget.")

        if enabled and not ports:
            raise ValueError(
                "Enabled TCP scanning requires allowed ports."
            )

        return cls(
            enabled=enabled,
            allowed_ports=tuple(sorted(ports)),
            connections_per_second=float(rate),
            max_connections=maximum
        )