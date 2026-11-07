import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Event

from core.rate_limiter import RateLimiter


class TestRateLimiter(unittest.TestCase):

    def test_invalid_rate(self):
        with self.assertRaises(ValueError):
            RateLimiter(0, 2)

    def test_invalid_concurrency(self):
        with self.assertRaises(ValueError):
            RateLimiter(2, 0)

    def test_boolean_rate_rejected(self):
        with self.assertRaises(ValueError):
            RateLimiter(True, 2)

    def test_rate_limit(self):
        limiter = RateLimiter(
            requests_per_second=2,
            max_concurrent_requests=3
        )

        start_times = []

        for _ in range(3):
            with limiter.limit():
                start_times.append(time.monotonic())

        # Third request must wait for the rolling window.
        elapsed = start_times[2] - start_times[0]
        self.assertGreaterEqual(elapsed, 0.85)

    def test_fractional_rate_limit(self):
        limiter = RateLimiter(
            requests_per_second=0.5,
            max_concurrent_requests=2
        )

        with limiter.limit():
            first_request = time.monotonic()

        with limiter.limit():
            second_request = time.monotonic()

        elapsed = second_request - first_request

        # A rate of 0.5 means at least 2 seconds between requests.
        self.assertGreaterEqual(elapsed, 1.85)


    def test_concurrency_limit(self):
        limiter = RateLimiter(
            requests_per_second=100,
            max_concurrent_requests=1
        )

        first_entered = Event()
        release_first = Event()
        second_entered = Event()

        def first_task():
            with limiter.limit():
                first_entered.set()
                if not release_first.wait(timeout=5):
                    raise TimeoutError("First task timed out.")

        def second_task():
            with limiter.limit():
                second_entered.set()

        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(first_task)

            self.assertTrue(first_entered.wait(timeout=2))

            second = executor.submit(second_task)

            try:
                # Second task should be blocked.
                self.assertFalse(
                    second_entered.wait(timeout=0.1)
                )
            finally:
                release_first.set()

            first.result(timeout=5)
            second.result(timeout=5)

        self.assertTrue(second_entered.is_set())

    def test_release_after_exception(self):
        limiter = RateLimiter(100, 1)

        with self.assertRaises(RuntimeError):
            with limiter.limit():
                raise RuntimeError("Simulated scan error")

        # The semaphore must have been released.
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                lambda: self._use_limiter(limiter)
            )
            self.assertTrue(future.result(timeout=2))

    @staticmethod
    def _use_limiter(limiter):
        with limiter.limit():
            return True


if __name__ == "__main__":
    unittest.main()
