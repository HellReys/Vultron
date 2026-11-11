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

class TestNVDFullRecord(unittest.TestCase):

    def setUp(self):
        self.session = MagicMock()

        self.client = NVDClient(
            session=self.session,
            requests_per_second=100
        )

    def make_response(
        self,
        cve_id="CVE-2024-12345",
        configurations=None,
        status="Analyzed"
    ):
        import json

        body = {
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": cve_id,
                    "vulnStatus": status,
                    "published": "2024-01-01T00:00:00.000",
                    "lastModified": "2024-02-01T00:00:00.000",
                    "configurations": (
                        configurations
                        if configurations is not None
                        else []
                    )
                }
            }]
        }

        response = FakeResponse(
            200,
            json.dumps(body).encode("utf-8")
        )

        self.session.get.return_value = response
        return response

    def test_full_record_retrieval(self):
        configurations = [{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": (
                        "cpe:2.3:a:example:server:*:"
                        "*:*:*:*:*:*:*"
                    )
                }]
            }]
        }]

        self.make_response(
            configurations=configurations
        )

        record = self.client.get_cve(
            "CVE-2024-12345"
        )

        self.assertEqual(
            record.cve_id,
            "CVE-2024-12345"
        )

        self.assertEqual(
            record.vuln_status,
            "Analyzed"
        )

        self.assertEqual(
            len(record.configurations),
            1
        )

    def test_cve_id_query_parameter(self):
        self.make_response()

        self.client.get_cve("CVE-2024-12345")

        kwargs = self.session.get.call_args.kwargs

        self.assertEqual(
            kwargs["params"],
            {"cveId": "CVE-2024-12345"}
        )

        self.assertFalse(
            kwargs["allow_redirects"]
        )

    def test_record_cache(self):
        self.make_response()

        first = self.client.get_cve(
            "CVE-2024-12345"
        )

        second = self.client.get_cve(
            "CVE-2024-12345"
        )

        self.assertIs(first, second)
        self.assertEqual(
            self.session.get.call_count,
            1
        )

    def test_invalid_cve_id_rejected(self):
        with self.assertRaises(ValueError):
            self.client.get_cve(
                "CVE-invalid"
            )

        self.session.get.assert_not_called()

    def test_mismatched_cve_rejected(self):
        self.make_response(
            cve_id="CVE-2024-99999"
        )

        with self.assertRaises(NVDError):
            self.client.get_cve(
                "CVE-2024-12345"
            )

        self.assertEqual(
            len(self.client.record_cache),
            0
        )

    def test_missing_cve_rejected(self):
        response = FakeResponse(
            200,
            b'{"totalResults":0,"vulnerabilities":[]}'
        )

        self.session.get.return_value = response

        with self.assertRaises(NVDError):
            self.client.get_cve(
                "CVE-2024-12345"
            )

    def test_invalid_configurations_rejected(self):
        self.make_response(
            configurations="invalid"
        )

        with self.assertRaises(NVDError):
            self.client.get_cve(
                "CVE-2024-12345"
            )

    def test_record_http_error_not_cached(self):
        response = FakeResponse(
            500,
            b""
        )

        self.session.get.return_value = response

        with self.assertRaises(NVDError):
            self.client.get_cve(
                "CVE-2024-12345"
            )

        self.assertEqual(
            len(self.client.record_cache),
            0
        )

if __name__ == "__main__":
    unittest.main()