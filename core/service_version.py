import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceVersion:
    product: str | None
    version: str | None
    source: str | None


class ServiceVersionExtractor:
    """
    Extract product/version information from known banners.

    No network requests are performed.
    Unknown or ambiguous versions are not guessed.
    """

    MAX_BANNER_BYTES = 256

    SSH_PATTERN = re.compile(
        rb"^SSH-\d+\.\d+-OpenSSH_"
        rb"(\d+(?:\.\d+){1,3}(?:p\d+)?)"
        rb"(?=$|[\s\r\n_-])",
        re.IGNORECASE
    )

    HTTP_STATUS_PATTERN = re.compile(
        rb"^HTTP/1\.[01]\s+\d{3}\b",
        re.IGNORECASE
    )

    SERVER_PATTERN = re.compile(
        rb"^Server:[ \t]*"
        rb"(Apache|nginx)/"
        rb"(\d+(?:\.\d+){1,3})"
        rb"(?=$|[\s()])",
        re.IGNORECASE
    )

    @classmethod
    def extract(cls, banner):
        if not isinstance(banner, bytes):
            raise TypeError("Banner must be bytes.")

        banner = banner[:cls.MAX_BANNER_BYTES]

        match = cls.SSH_PATTERN.match(banner)

        if match:
            return ServiceVersion(
                product="OpenSSH",
                version=match.group(1).decode("ascii"),
                source="ssh_banner"
            )

        # Only inspect HTTP headers when a valid
        # HTTP response status line is present.
        lines = banner.splitlines()

        if lines and cls.HTTP_STATUS_PATTERN.match(lines[0]):
            for line in lines[1:]:
                if line == b"":
                    break

                match = cls.SERVER_PATTERN.match(line.strip())

                if match:
                    product = match.group(1).lower()

                    normalized = (
                        "Apache HTTP Server"
                        if product == b"apache"
                        else "nginx"
                    )

                    return ServiceVersion(
                        product=normalized,
                        version=match.group(2).decode("ascii"),
                        source="http_server_header"
                    )

        return ServiceVersion(
            product=None,
            version=None,
            source=None
        )