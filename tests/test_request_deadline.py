import time
import unittest

from core.request_deadline import RequestDeadline


class TestRequestDeadline(unittest.TestCase):

    def test_initial_remaining_time(self):
        deadline = RequestDeadline(2.0)

        remaining = deadline.remaining()

        self.assertGreater(remaining, 0)
        self.assertLessEqual(remaining, 2.0)

    def test_deadline_decreases(self):
        deadline = RequestDeadline(1.0)

        first = deadline.remaining()

        time.sleep(0.02)

        second = deadline.remaining()

        self.assertLess(second, first)

    def test_deadline_exceeded(self):
        deadline = RequestDeadline(0.01)

        time.sleep(0.03)

        with self.assertRaises(TimeoutError):
            deadline.remaining()

    def test_socket_timeout_capped(self):
        deadline = RequestDeadline(5.0)

        timeout = deadline.socket_timeout(1.0)

        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 1.0)

    def test_invalid_zero_timeout(self):
        with self.assertRaises(ValueError):
            RequestDeadline(0)

    def test_negative_timeout(self):
        with self.assertRaises(ValueError):
            RequestDeadline(-1)

    def test_boolean_timeout_rejected(self):
        with self.assertRaises(ValueError):
            RequestDeadline(True)

    def test_infinite_timeout_rejected(self):
        with self.assertRaises(ValueError):
            RequestDeadline(float("inf"))

    def test_nan_timeout_rejected(self):
        with self.assertRaises(ValueError):
            RequestDeadline(float("nan"))


if __name__ == "__main__":
    unittest.main()