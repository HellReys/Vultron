import re
from collections.abc import Mapping

from core.version import __version__


class HeaderManager:
    """Validate and build safe program-level HTTP headers."""

    DEFAULT_HEADERS = {
        "User-Agent": f"Vultron/{__version__}",
        "Accept": "*/*",
    }

    BLOCKED_HEADERS = {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "proxy-connection",
        "proxy-authorization",
        "authorization",
        "cookie",
        "upgrade",
        "te",
        "trailer",
        "expect",
        "accept-encoding",
        "forwarded",
        "x-real-ip"
    }

    TOKEN_PATTERN = re.compile(
        r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$"
    )

    def __init__(self, headers=None):
        if headers is None:
            headers = {}

        if not isinstance(headers, Mapping):
            raise ValueError(
                "HTTP headers must be a mapping."
            )

        self.headers = dict(headers)

    @classmethod
    def validate(cls, headers):
        validated = {}
        seen = set()

        for name, value in headers.items():
            if not isinstance(name, str):
                raise ValueError(
                    "HTTP header names must be strings."
                )

            if not cls.TOKEN_PATTERN.fullmatch(name):
                raise ValueError(
                    f"Invalid HTTP header name: {name!r}"
                )

            normalized = name.lower()

            if normalized in seen:
                raise ValueError(
                    f"Duplicate HTTP header: {name}"
                )

            seen.add(normalized)

            if (
                normalized in cls.BLOCKED_HEADERS
                or normalized.startswith("proxy-")
                or normalized.startswith("x-forwarded-")
            ):
                raise PermissionError(
                    f"Restricted HTTP header: {name}"
                )

            if not isinstance(value, str):
                raise ValueError(
                    f"Header '{name}' must have a string value."
                )

            if not value or len(value) > 2048:
                raise ValueError(
                    f"Invalid length for header '{name}'."
                )

            if any(
                ord(char) < 32 or ord(char) > 126
                for char in value
            ):
                raise ValueError(
                    f"Invalid characters in header '{name}'."
                )

            validated[name] = value

        return validated

    def build(self):
        """Merge safe defaults and program-specific headers."""

        custom = self.validate(self.headers)

        result = dict(self.DEFAULT_HEADERS)

        for name, value in custom.items():
            for existing in list(result):
                if existing.lower() == name.lower():
                    del result[existing]

            result[name] = value

        return result