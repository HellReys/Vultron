from dataclasses import dataclass


@dataclass(frozen=True)
class ScanSummary:
    target: str
    results: tuple
    open_ports: tuple
    attempted_connections: int


class ScanOrchestrator:
    """
    Coordinate policy-controlled TCP scanning.

    This layer does not open sockets directly.
    All connections go through ProgramContext.
    """

    def __init__(self, context):
        self.context = context

        if not hasattr(context, "create_tcp_scanner"):
            raise TypeError(
                "A valid ProgramContext is required."
            )

    def scan_tcp(
        self,
        hostname,
        ports=None,
        **scanner_options
    ):
        """
        Run a TCP scan using the configured program policy.

        If ports are omitted, use the explicitly allowed
        ports defined by the program.
        """

        policy = self.context.policy

        if not policy.can_scan():
            raise PermissionError(
                "Active scanning is disabled."
            )

        tcp_policy = policy.tcp_policy

        if not tcp_policy.enabled:
            raise PermissionError(
                "TCP scanning is disabled."
            )

        if ports is None:
            ports = list(tcp_policy.allowed_ports)

        elif not isinstance(ports, (list, tuple)):
            raise ValueError(
                "Ports must be a list or tuple."
            )

        else:
            ports = list(ports)

        if not ports:
            raise ValueError(
                "No authorized ports configured."
            )

        # Validate the complete batch before creating a scanner.
        if any(type(port) is not int for port in ports):
            raise ValueError("Invalid TCP port type.")

        if len(ports) != len(set(ports)):
            raise ValueError(
                "Duplicate ports are not allowed."
            )

        unauthorized = [
            port
            for port in ports
            if port not in tcp_policy.allowed_ports
        ]

        if unauthorized:
            raise PermissionError(
                f"Unauthorized TCP ports: {unauthorized}"
            )

        # The context owns the shared TCP controls.
        scanner = self.context.create_tcp_scanner(
            **scanner_options
        )

        results = scanner.scan(
            hostname,
            ports
        )

        open_ports = tuple(
            sorted(
                result.port
                for result in results
                if result.open
            )
        )

        return ScanSummary(
            target=hostname,
            results=tuple(results),
            open_ports=open_ports,
            attempted_connections=len(results)
        )