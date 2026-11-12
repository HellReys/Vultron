import re
from urllib.parse import urlsplit

MAX_URL_LENGTH = 8192

INVALID_PERCENT_ESCAPE = re.compile(
    r"%(?![0-9a-fA-F]{2})"
)

ENCODED_CONTROL = re.compile(
    r"%(?:0[0-9a-f]|1[0-9a-f]|7f|5c)",
    re.IGNORECASE
)


def validate_http_url(url):
    """
    Validate the structure of an HTTP/HTTPS URL.

    This function does not check bug bounty scope.
    Scope and authorization remain the responsibility
    of PolicyEngine and RequestManager.
    """

    if not isinstance(url, str):
        raise ValueError("URL must be a string.")

    if not url:
        raise ValueError("URL cannot be empty.")

    if len(url) > MAX_URL_LENGTH:
        raise ValueError("URL exceeds the maximum length.")

    if any(ord(char) <= 32 or ord(char) == 127 for char in url):
        raise ValueError("URL contains control characters or spaces.")

    if "\\" in url:
        raise ValueError("Backslashes are not permitted in URLs.")

    try:
        parsed = urlsplit(url)

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS are supported.")

        if not parsed.netloc or not parsed.hostname:
            raise ValueError("URL must contain a hostname.")

        if (
            parsed.username is not None
            or parsed.password is not None
            or "@" in parsed.netloc
        ):
            raise PermissionError(
                "Credentials and userinfo are not permitted."
            )

        # Keep authority parsing predictable.
        # Unicode domains can be supported later through
        # explicit IDNA canonicalization.
        if any(ord(char) > 127 for char in parsed.netloc):
            raise ValueError(
                "Non-ASCII URL authorities are not supported."
            )

        if "%" in parsed.netloc:
            raise ValueError(
                "Percent-encoding is not allowed in the authority."
            )

        if parsed.netloc.endswith(":"):
            raise ValueError("Empty port is not permitted.")

        if parsed.hostname.endswith("."):
            raise ValueError(
                "Trailing-dot hostnames are not supported."
            )

        if parsed.fragment:
            raise ValueError(
                "URL fragments are not supported."
            )

        request_target = parsed.path + (
            "?" + parsed.query if parsed.query else ""
        )

        if INVALID_PERCENT_ESCAPE.search(request_target):
            raise ValueError("Invalid percent-encoding.")

        if ENCODED_CONTROL.search(request_target):
            raise ValueError(
                "Encoded control characters are not permitted."
            )

        port = parsed.port

        standard_port = (
            443 if parsed.scheme == "https" else 80
        )

        if port is not None and port != standard_port:
            raise PermissionError(
                "Non-standard ports are not supported yet."
            )

        return parsed

    except ValueError as error:
        raise ValueError(
            f"Invalid HTTP URL: {error}"
        ) from error
