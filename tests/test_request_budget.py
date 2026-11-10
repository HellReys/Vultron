import unittest
from concurrent.futures import ThreadPoolExecutor

from core.request_budget import (
    RequestBudget,
    RequestBudgetExceeded
)


class TestRequestBudget(unittest.TestCase):

    def test_initial_state(self):
        budget = RequestBudget(5)

        self.assertEqual(budget.used, 0)
        self.assertEqual(budget.remaining, 5)
        self.assertFalse(budget.exhausted)

    def test_consume_request(self):
        budget = RequestBudget(3)

        budget.consume()

        self.assertEqual(budget.used, 1)
        self.assertEqual(budget.remaining, 2)

    def test_budget_exhaustion(self):
        budget = RequestBudget(2)

        budget.consume()
        budget.consume()

        with self.assertRaises(RequestBudgetExceeded):
            budget.consume()

        self.assertEqual(budget.used, 2)
        self.assertTrue(budget.exhausted)

    def test_invalid_zero_budget(self):
        with self.assertRaises(ValueError):
            RequestBudget(0)

    def test_negative_budget(self):
        with self.assertRaises(ValueError):
            RequestBudget(-1)

    def test_boolean_budget_rejected(self):
        with self.assertRaises(ValueError):
            RequestBudget(True)

    def test_concurrent_consumption(self):
        budget = RequestBudget(10)

        def consume():
            try:
                budget.consume()
                return True
            except RequestBudgetExceeded:
                return False

        with ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(
                lambda _: consume(),
                range(100)
            ))

        self.assertEqual(sum(results), 10)
        self.assertEqual(budget.used, 10)
        self.assertEqual(budget.remaining, 0)

    def test_no_automatic_reset(self):
        budget = RequestBudget(1)

        budget.consume()

        with self.assertRaises(RequestBudgetExceeded):
            budget.consume()

        self.assertEqual(budget.used, 1)


if __name__ == "__main__":
    unittest.main()