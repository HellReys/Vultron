"""Safe, bounded HTTP fingerprint report serialization."""

import re

MAX_HTTP_RESULTS = 2

KNOWN_PRODUCTS = {
    "nginx",
    "Apache HTTP Server",
    "Caddy",
}

VERSION_PATTERN = re.compile(
    r"[0-9]{1,4}(?:\.[0-9]{1,4}){1,3}"
)


def build_http_report(http_results):
    """Export metadata only, never HTTP headers or bodies."""

    if not isinstance(http_results, (tuple, list)):
        raise ValueError("Invalid HTTP probe results.")

    if len(http_results) > MAX_HTTP_RESULTS:
        raise ValueError("Too many HTTP probe results.")

    output = []
    seen_ports = set()

    for result in http_results:
        port = result.port
        status = result.status

        if port not in (80, 443) or port in seen_ports:
            raise ValueError("Invalid or duplicate HTTP port.")

        seen_ports.add(port)

        if status not in ("OK", "NETWORK_ERROR"):
            raise ValueError("Invalid HTTP probe status.")

        expected_service = (
            "HTTP" if port == 80 else "HTTPS"
        )

        item = {
            "port": port,
            "status": status,
            "service": None,
            "product": None,
            "version": None,
            "version_source": None,
            "evidence_verified": False,
        }

        if status == "NETWORK_ERROR":
            if result.fingerprint is not None:
                raise ValueError(
                    "Failed HTTP probe has fingerprint data."
                )

            output.append(item)
            continue

        fp = result.fingerprint

        if fp is None or fp.service != expected_service:
            raise ValueError("Invalid HTTP service fingerprint.")

        item["service"] = expected_service

        # The product must come from our known parser mapping.
        # The version must be a bounded numeric version.
        if (
            fp.product in KNOWN_PRODUCTS
            and isinstance(fp.version, str)
            and VERSION_PATTERN.fullmatch(fp.version)
            and fp.version_source
            == "http_server_header_unverified"
        ):
            item["product"] = fp.product
            item["version"] = fp.version
            item["version_source"] = (
                "http_server_header_unverified"
            )

        output.append(item)

    return output
