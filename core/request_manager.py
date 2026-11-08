from contextlib import contextmanager
from dataclasses import dataclass
from urllib.parse import urlsplit

from core.rate_limiter import RateLimiter


@dataclass(frozen=True)
class RequestPlan:
    method: str
    url: str
    hostname: str


class RequestManager:
    """
    Validate and schedule HTTP request plans.
    """

    ALLOWED_METHODS = {"GET", "HEAD"}


    def __init__(self, policy, rate_limiter=None):
        self.policy = policy

        if rate_limiter is None:
            rate_limiter = RateLimiter(
                requests_per_second=policy.requests_per_second,
                max_concurrent_requests=policy.max_concurrent_requests
            )

        self.rate_limiter = rate_limiter


    def prepare(self, url, method="GET"):
        """Validate a request without sending it."""

        if not self.policy.can_scan():
            raise PermissionError(
                "Active scanning is disabled by program policy."
            )

        if not isinstance(url, str):
            raise ValueError("URL must be a string.")

        if not isinstance(method, str):
            raise ValueError("HTTP method must be a string.")

        method = method.upper()

        if method not in self.ALLOWED_METHODS:
            raise PermissionError(
                f"HTTP method '{method}' is not permitted."
            )

        if (
            not url
            or any(ord(char) <= 32 or ord(char) == 127 for char in url)
            or "\\" in url
        ):
            raise ValueError("URL contains invalid characters.")

        try:
            parsed = urlsplit(url)

            allowed, reason = self.policy.check_url(url)

            if not allowed:
                raise PermissionError(reason)

            # Only standard HTTP and HTTPS ports for now.
            standard_port = (
                443 if parsed.scheme == "https" else 80
            )

            if (
                parsed.port is not None
                and parsed.port != standard_port
            ):
                raise PermissionError(
                    "Non-standard ports are not supported yet."
                )

            if parsed.fragment:
                raise ValueError(
                    "URL fragments are not supported."
                )

            return RequestPlan(
                method=method,
                url=url,
                hostname=parsed.hostname
            )

        except ValueError as error:
            raise ValueError(
                f"Invalid request URL: {error}"
            ) from error

    @contextmanager
    def permit(self, url, method="GET"):
        """
        Reserve a rate/concurrency slot for a request plan.

        This is not an HTTP client and does not authorize
        an external tool to bypass policy checks.
        """

        plan = self.prepare(url, method)

        with self.rate_limiter.limit():
            # Recheck policy before granting the slot.
            plan = self.prepare(plan.url, plan.method)
            yield plan
