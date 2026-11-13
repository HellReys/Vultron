"""Conservative HTTP/HTTPS service fingerprinting."""

import re
from urllib.parse import urlsplit

from core.service_fingerprint import ServiceFingerprint

SERVER_PATTERN = re.compile(
    r"(nginx|Apache|Caddy)/"
    r"([0-9]{1,4}(?:\.[0-9]{1,4}){1,3})"
    r"(?:\s+\([^)]{1,60}\))?",
    re.IGNORECASE,
)

KNOWN_PRODUCTS = {
    "nginx": "nginx",
    "apache": "Apache HTTP Server",
    "caddy": "Caddy",
}


def fingerprint_http_response(response):
    """
    Identify HTTP services from a TransportResponse.

    Server headers are untrusted and may be modified,
    hidden, or spoofed by proxies.

    This function performs no network requests.
    """

    parsed = urlsplit(response.url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Unsupported response scheme.")

    if type(response.status) is not int:
        raise ValueError("Invalid HTTP response status.")

    if not 100 <= response.status <= 599:
        raise ValueError("Invalid HTTP response status.")

    if not isinstance(response.headers, (tuple, list)):
        raise ValueError("Invalid HTTP response headers.")

    service = (
        "HTTPS" if parsed.scheme == "https" else "HTTP"
    )

    server_headers = []

    for item in response.headers:
        if (
            not isinstance(item, (tuple, list))
            or len(item) != 2
        ):
            continue

        name, value = item

        if not isinstance(name, str):
            continue

        if name.lower() == "server":
            if isinstance(value, str):
                server_headers.append(value.strip())

    # Ambiguous or missing server evidence.
    if len(server_headers) != 1:
        return ServiceFingerprint(
            service=service,
            banner="",
            confidence="high",
        )

    server = server_headers[0]

    if len(server) > 128:
        return ServiceFingerprint(
            service=service,
            banner="",
            confidence="high",
        )

    match = SERVER_PATTERN.fullmatch(server)

    if match is None:
        return ServiceFingerprint(
            service=service,
            banner="",
            confidence="high",
        )

    product_name = match.group(1).lower()
    version = match.group(2)

    return ServiceFingerprint(
        service=service,
        banner="",
        confidence="medium",
        product=KNOWN_PRODUCTS[product_name],
        version=version,
        version_source="http_server_header_unverified",
    )
