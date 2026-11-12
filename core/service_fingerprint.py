from dataclasses import dataclass

from core.service_version import ServiceVersionExtractor


@dataclass(frozen=True)
class ServiceFingerprint:
    service: str
    banner: str
    confidence: str
    product: str | None = None
    version: str | None = None
    version_source: str | None = None


class ServiceFingerprinter:
    """
    Identify services using only passively received banners.

    No network connections or protocol commands are sent.
    """

    MAX_BANNER_BYTES = 256

    @classmethod
    def identify(cls, data):
        if not isinstance(data, bytes):
            raise TypeError("Banner data must be bytes.")

        data = data[:cls.MAX_BANNER_BYTES]

        # Keep printable characters and normalize whitespace.
        text = "".join(
            chr(byte) if 32 <= byte <= 126 else " "
            for byte in data
        ).strip()

        text = " ".join(text.split())

        if not text:
            return ServiceFingerprint(
                service="Unknown",
                banner="",
                confidence="none"
            )

        upper = text.upper()

        if upper.startswith("SSH-"):
            service = "SSH"
            confidence = "high"

        elif upper.startswith("220") and "SMTP" in upper:
            service = "SMTP"
            confidence = "medium"

        elif upper.startswith("220") and "FTP" in upper:
            service = "FTP"
            confidence = "medium"

        elif upper.startswith("HTTP/1."):
            service = "HTTP"
            confidence = "high"

        else:
            service = "Unknown"
            confidence = "none"

        version_info = ServiceVersionExtractor.extract(data)

        return ServiceFingerprint(
            service=service,
            banner=text,
            confidence=confidence,
            product=version_info.product,
            version=version_info.version,
            version_source=version_info.source
        )