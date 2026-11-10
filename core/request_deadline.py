import math
import time


class RequestDeadline:
    """Track remaining time using a monotonic clock."""

    def __init__(self, timeout):
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError(
                "Timeout must be a positive finite number."
            )

        self.timeout = float(timeout)
        self._expires_at = time.monotonic() + self.timeout

    def remaining(self):
        """Return remaining seconds or raise TimeoutError."""

        remaining = self._expires_at - time.monotonic()

        if remaining <= 0:
            raise TimeoutError(
                "HTTP request deadline exceeded."
            )

        return remaining

    def socket_timeout(self, maximum=None):
        """Return the safe timeout for the next socket operation."""

        remaining = self.remaining()

        if maximum is not None:
            if (
                type(maximum) not in (int, float)
                or not math.isfinite(maximum)
                or maximum <= 0
            ):
                raise ValueError(
                    "Maximum socket timeout must be positive."
                )

            return min(remaining, maximum)

        return remaining