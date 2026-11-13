"""Policy-controlled HTTP service probing."""

import http.client
from dataclasses import dataclass

from core.http_fingerprint import fingerprint_http_response


@dataclass(frozen=True)
class HTTPProbeResult:
    port: int
    status: str
    fingerprint: object | None = None


def probe_http_services(context, summary):
    """
    Probe open HTTP/HTTPS ports using the shared HTTP transport.

    Only ports 80 and 443 are supported.
    No redirects or additional paths are requested.
    """

    supported_ports = {
        80: "http",
        443: "https",
    }

    ports = sorted({
        result.port
        for result in summary.results
        if result.open and result.port in supported_ports
    })

    if not ports:
        return ()

    transport = context.create_http_transport()
    results = []

    for port in ports:
        scheme = supported_ports[port]
        url = f"{scheme}://{summary.target}/"

        try:
            response = transport.request(url, method="GET")

        except PermissionError:
            # Policy and budget failures must never be hidden.
            raise

        except (OSError, http.client.HTTPException):
            results.append(
                HTTPProbeResult(
                    port=port,
                    status="NETWORK_ERROR",
                )
            )
            continue

        fingerprint = fingerprint_http_response(response)

        results.append(
            HTTPProbeResult(
                port=port,
                status="OK",
                fingerprint=fingerprint,
            )
        )

    return tuple(results)
