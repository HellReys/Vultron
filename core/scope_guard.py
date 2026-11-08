import ipaddress
import re
from urllib.parse import urlsplit


class ScopeGuard:
    """Check whether a hostname or URL belongs to the approved scope."""

    def __init__(self, allowed, excluded=None):
        if not allowed:
            raise ValueError("At least one allowed scope entry is required.")

        self.allowed = [self._normalize_rule(rule) for rule in allowed]
        self.excluded = [
            self._normalize_rule(rule) for rule in (excluded or [])
        ]

    @staticmethod
    def _normalize_host(host):
        host = host.strip().lower().rstrip(".")

        if not host or any(char in host for char in "/?#@\\"):
            raise ValueError("Invalid hostname.")

        try:
            return str(ipaddress.ip_address(host.strip("[]")))
        except ValueError:
            pass

        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError("Invalid hostname.") from None

        if len(host) > 253:
            raise ValueError("Hostname is too long.")

        labels = host.split(".")
        for label in labels:
            if not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label
            ):
                raise ValueError("Invalid hostname.")

        return host

    @classmethod
    def _normalize_rule(cls, rule):
        rule = rule.strip().lower()

        if rule.startswith("*."):
            return "*." + cls._normalize_host(rule[2:])

        try:
            return str(ipaddress.ip_network(rule, strict=False))
        except ValueError:
            return cls._normalize_host(rule)

    @staticmethod
    def _matches(host, rule):
        if rule.startswith("*."):
            base = rule[2:]
            return host.endswith("." + base)

        if "/" in rule:
            try:
                return ipaddress.ip_address(host) in ipaddress.ip_network(rule)
            except ValueError:
                return False

        return host == rule


    def is_excluded(self, host):
        """Check whether a host or IP is explicitly excluded."""
        try:
            host = self._normalize_host(host)
        except (ValueError, AttributeError):
            return True

        return any(
            self._matches(host, rule)
            for rule in self.excluded
        )


    def check_host(self, host):
        try:
            host = self._normalize_host(host)
        except (ValueError, AttributeError):
            return False, "Invalid hostname"

        if any(self._matches(host, rule) for rule in self.excluded):
            return False, "Excluded by program policy"

        if any(self._matches(host, rule) for rule in self.allowed):
            return True, "Host is in scope"

        return False, "Host is outside the approved scope"

    def check_url(self, url):
        try:
            parsed = urlsplit(url)

            if parsed.scheme not in ("http", "https"):
                return False, "Unsupported URL scheme"

            if not parsed.hostname or parsed.username or parsed.password:
                return False, "Invalid URL authority"

            # Reject malformed ports even if the hostname is valid.
            port = parsed.port
            if port is not None and port < 1:
                return False, "Invalid port"

            return self.check_host(parsed.hostname)

        except ValueError:
            return False, "Invalid URL"
