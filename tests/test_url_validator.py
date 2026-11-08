import unittest

from core.url_validator import validate_http_url


class TestURLValidator(unittest.TestCase):

    def test_valid_https_url(self):
        parsed = validate_http_url(
            "https://api.example.com/users?id=10"
        )

        self.assertEqual(
            parsed.hostname,
            "api.example.com"
        )

    def test_standard_explicit_port(self):
        parsed = validate_http_url(
            "https://example.com:443/"
        )

        self.assertEqual(parsed.port, 443)

    def test_http_standard_port(self):
        parsed = validate_http_url(
            "http://example.com:80/"
        )

        self.assertEqual(parsed.port, 80)

    def test_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            validate_http_url(
                "file:///etc/passwd"
            )

    def test_missing_hostname(self):
        with self.assertRaises(ValueError):
            validate_http_url(
                "https:///missing-host"
            )

    def test_userinfo_rejected(self):
        with self.assertRaises(PermissionError):
            validate_http_url(
                "https://user:pass@example.com/"
            )

    def test_non_standard_port(self):
        with self.assertRaises(PermissionError):
            validate_http_url(
                "https://example.com:8443/"
            )

    def test_encoded_newline(self):
        with self.assertRaises(ValueError):
            validate_http_url(
                "https://example.com/%0d%0aHost:evil.org"
            )

    def test_encoded_backslash(self):
        with self.assertRaises(ValueError):
            validate_http_url(
                "https://example.com/%5cadmin"
            )

    def test_invalid_percent_encoding(self):
        with self.assertRaises(ValueError):
            validate_http_url(
                "https://example.com/%ZZ"
            )

    def test_backslash_rejected(self):
        with self.assertRaises(ValueError):
            validate_http_url(
                "https://example.com\\@external.com/"
            )

    def test_url_fragment_rejected(self):
        with self.assertRaises(ValueError):
            validate_http_url(
                "https://example.com/#section"
            )

    def test_trailing_dot_rejected(self):
        with self.assertRaises(ValueError):
            validate_http_url(
                "https://example.com./"
            )

    def test_empty_port_rejected(self):
        with self.assertRaises(ValueError):
            validate_http_url(
                "https://example.com:/"
            )

    def test_too_long_url(self):
        with self.assertRaises(ValueError):
            validate_http_url(
                "https://example.com/" + "a" * 9000
            )

    def test_unicode_authority_rejected(self):
        with self.assertRaises(ValueError):
            validate_http_url(
                "https://exämple.com/"
            )

    def test_valid_encoded_path(self):
        parsed = validate_http_url(
            "https://example.com/search?q=hello%20world"
        )

        self.assertEqual(
            parsed.query,
            "q=hello%20world"
        )


if __name__ == "__main__":
    unittest.main()
