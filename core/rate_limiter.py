import math
import time
from collections import deque
from contextlib import contextmanager
from threading import BoundedSemaphore, Lock


class RateLimiter:
    """Thread safe rate and concurrency limiter."""

    def __init__(self, requests_per_second, max_concurrent_requests):
        # Validate the rate limit.
        if (
            type(requests_per_second) not in (int, float)
            or not math.isfinite(requests_per_second)
            or requests_per_second <= 0
        ):
            raise ValueError(
                "requests_per_second must be a positive finite number."
            )

        # Validate the concurrency limit.
        if (
            type(max_concurrent_requests) is not int
            or max_concurrent_requests < 1
        ):
            raise ValueError(
                "max_concurrent_requests must be a positive integer."
            )

        self.requests_per_second = requests_per_second
        self.max_concurrent_requests = max_concurrent_requests

        self._semaphore = BoundedSemaphore(
            max_concurrent_requests
        )
        self._lock = Lock()
        self._request_times = deque()

    def _wait_for_rate_slot(self):
        """Reserve one request slot within the rolling time window."""
        while True:
            with self._lock:
                now = time.monotonic()

                # Remove requests older than one second.
                while (
                    self._request_times
                    and now - self._request_times[0] >= max(
                    1.0, 1.0 / self.requests_per_second
                )
                ):
                    self._request_times.popleft()

                # A rolling window allows at most floor(rate)
                # requests. For sub-1 rates, use a longer interval.
                if self.requests_per_second < 1:
                    interval = 1.0 / self.requests_per_second

                    if (
                        not self._request_times
                        or now - self._request_times[-1] >= interval
                    ):
                        self._request_times.append(now)
                        return

                    wait_time = (
                        interval - (now - self._request_times[-1])
                    )
                else:
                    limit = int(self.requests_per_second)

                    if len(self._request_times) < limit:
                        self._request_times.append(now)
                        return

                    wait_time = (
                        1.0 - (now - self._request_times[0])
                    )

            # Do not hold the shared lock while waiting.
            time.sleep(max(wait_time, 0.001))

    @contextmanager
    def limit(self):
        """Reserve permission before starting a network operation."""
        self._semaphore.acquire()

        try:
            self._wait_for_rate_slot()
            yield
        finally:
            # Release the concurrency slot even after an error.
            self._semaphore.release()
