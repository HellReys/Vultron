from threading import Lock


class RequestBudgetExceeded(RuntimeError):
    """Raised when the scan's request budget is exhausted."""


class RequestBudget:
    """Thread safe request budget for one scan session."""

    def __init__(self, max_requests):
        if type(max_requests) is not int or max_requests < 1:
            raise ValueError(
                "max_requests must be a positive integer."
            )

        self.max_requests = max_requests
        self._used = 0
        self._lock = Lock()

    def consume(self):
        """Atomically reserve one request attempt."""

        with self._lock:
            if self._used >= self.max_requests:
                raise RequestBudgetExceeded(
                    "Scan request budget exhausted: "
                    f"{self._used}/{self.max_requests}"
                )

            self._used += 1
            return self._used

    @property
    def used(self):
        with self._lock:
            return self._used

    @property
    def remaining(self):
        with self._lock:
            return self.max_requests - self._used

    @property
    def exhausted(self):
        with self._lock:
            return self._used >= self.max_requests