import unittest
from unittest.mock import MagicMock

import requests

from core.nvd_client import (
    NVDClient,
    NVDError,
    NVDRateLimitError
)


class FakeResponse:
    def __init__(self, status=200, body=b""):
        self.status_code = status
        self.body = body
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def iter_content(self, chunk_size=8192):
        for start in range(0, len(self.body), chunk_size):
            yield self.body[start:start + chunk_size]


class TestNVDClient(unittest.TestCase):

    def setUp(self):
        self.session = MagicMock()

        self.client = NVDClient(
            session=self.session,
            requests_per_second=100,
            timeout=2.0
        )

    def set_response(self, status, body):
        response = FakeResponse(status, body)

        self.session.get.return_value = response

        return response

    def test_successful_search(self):
        self.set_response(
            200,
            b'{"totalResults":1,'
            b'"vulnerabilities":['
            b'{"cve":{"id":"CVE-2024-12345"}}]}'
        )

        result = self.client.search("OpenSSH", "9.6")

        self.assertEqual(result.query, "OpenSSH 9.6")
        self.assertEqual(
            result.cve_ids,
            ("CVE-2024-12345",)
        )
        self.assertEqual(result.total_results, 1)
        self.assertTrue(result.complete)

    def test_empty_results(self):
        self.set_response(
            200,
            b'{"totalResults":0,"vulnerabilities":[]}'
        )

        result = self.client.search("Example", "1.0")

        self.assertEqual(result.cve_ids, ())
        self.assertEqual(result.total_results, 0)
        self.assertTrue(result.complete)

    def test_cache_prevents_duplicate_request(self):
        self.set_response(
            200,
            b'{"totalResults":0,"vulnerabilities":[]}'
        )

        first = self.client.search("OpenSSH", "9.6")
        second = self.client.search("OpenSSH", "9.6")

        self.assertIs(first, second)
        self.assertEqual(self.session.get.call_count, 1)

    def test_rate_limit_response(self):
        self.set_response(429, b"")

        with self.assertRaises(NVDRateLimitError):
            self.client.search("OpenSSH", "9.6")

        self.assertEqual(len(self.client.cache), 0)

    def test_http_error(self):
        self.set_response(500, b"")

        with self.assertRaises(NVDError):
            self.client.search("OpenSSH", "9.6")

        self.assertEqual(len(self.client.cache), 0)

    def test_invalid_json(self):
        self.set_response(200, b"not valid json")

        with self.assertRaises(NVDError):
            self.client.search("OpenSSH", "9.6")

    def test_response_size_limit(self):
        response = self.set_response(
            200,
            b"A" * (NVDClient.MAX_RESPONSE_BYTES + 1)
        )

        with self.assertRaises(NVDError):
            self.client.search("OpenSSH", "9.6")

        self.assertTrue(response.closed)

    def test_network_timeout(self):
        self.session.get.side_effect = (
            requests.exceptions.Timeout()
        )

        with self.assertRaises(NVDError):
            self.client.search("OpenSSH", "9.6")

        self.assertEqual(len(self.client.cache), 0)

    def test_invalid_product_rejected(self):
        with self.assertRaises(ValueError):
            self.client.search("", "9.6")

        self.session.get.assert_not_called()

    def test_api_key_sent_as_header(self):
        client = NVDClient(
            api_key="test-api-key",
            session=self.session,
            requests_per_second=100
        )

        self.set_response(
            200,
            b'{"totalResults":0,"vulnerabilities":[]}'
        )

        client.search("OpenSSH", "9.6")

        kwargs = self.session.get.call_args.kwargs

        self.assertEqual(
            kwargs["headers"]["apiKey"],
            "test-api-key"
        )

        self.assertFalse(kwargs["allow_redirects"])

    def test_partial_results_are_marked(self):
        self.set_response(
            200,
            b'{"totalResults":50,'
            b'"vulnerabilities":['
            b'{"cve":{"id":"CVE-2024-12345"}}]}'
        )

        result = self.client.search("OpenSSH", "9.6")

        self.assertFalse(result.complete)
        self.assertEqual(result.total_results, 50)

    def test_invalid_response_structure(self):
        self.set_response(
            200,
            b'{"totalResults":"wrong",'
            b'"vulnerabilities":[]}'
        )

        with self.assertRaises(NVDError):
            self.client.search("OpenSSH", "9.6")


if __name__ == "__main__":
    unittest.main()