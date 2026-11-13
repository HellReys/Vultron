import unittest

from core.http_fingerprint import fingerprint_http_response
from core.http_transport import TransportResponse


def response(url, headers=(), status=200):
    return TransportResponse(
        url=url,
        status=status,
        headers=tuple(headers),
        body=b"",
        truncated=False,
    )


class TestHTTPFingerprint(unittest.TestCase):

    def test_nginx_https(self):
        result = fingerprint_http_response(
            response(
                "https://example.com/",
                [("Server", "nginx/1.24.0")],
            )
        )

        self.assertEqual(result.service, "HTTPS")
        self.assertEqual(result.product, "nginx")
        self.assertEqual(result.version, "1.24.0")
        self.assertEqual(result.confidence, "medium")
        self.assertEqual(
            result.version_source,
            "http_server_header_unverified",
        )

    def test_apache_http(self):
        result = fingerprint_http_response(
            response(
                "http://example.com/",
                [("server", "Apache/2.4.62 (Ubuntu)")],
            )
        )

        self.assertEqual(result.service, "HTTP")
        self.assertEqual(
            result.product,
            "Apache HTTP Server",
        )
        self.assertEqual(result.version, "2.4.62")

    def test_missing_server_header(self):
        result = fingerprint_http_response(
            response(
                "https://example.com/",
                [("Content-Type", "text/html")],
            )
        )

        self.assertEqual(result.service, "HTTPS")
        self.assertIsNone(result.product)
        self.assertIsNone(result.version)
        self.assertEqual(result.confidence, "high")

    def test_unknown_product_not_guessed(self):
        result = fingerprint_http_response(
            response(
                "https://example.com/",
                [("Server", "CustomGateway/9.9")],
            )
        )

        self.assertIsNone(result.product)
        self.assertIsNone(result.version)

    def test_duplicate_server_headers_not_trusted(self):
        result = fingerprint_http_response(
            response(
                "https://example.com/",
                [
                    ("Server", "nginx/1.24.0"),
                    ("Server", "Apache/2.4.62"),
                ],
            )
        )

        self.assertIsNone(result.product)
        self.assertIsNone(result.version)

    def test_invalid_status_rejected(self):
        with self.assertRaises(ValueError):
            fingerprint_http_response(
                response(
                    "https://example.com/",
                    status=999,
                )
            )

    def test_untrusted_header_not_exposed(self):
        result = fingerprint_http_response(
            response(
                "https://example.com/",
                [
                    ("Server", "nginx/1.24.0"),
                    ("Set-Cookie", "session=SECRET"),
                ],
            )
        )

        self.assertEqual(result.banner, "")
        self.assertNotIn(
            "SECRET",
            repr(result),
        )


if __name__ == "__main__":
    unittest.main()
