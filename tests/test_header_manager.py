import unittest

from core.header_manager import HeaderManager


class TestHeaderManager(unittest.TestCase):

    def test_default_headers(self):
        headers = HeaderManager().build()

        self.assertEqual(
            headers["User-Agent"],
            "Vultron/0.1"
        )
        self.assertEqual(headers["Accept"], "*/*")

    def test_custom_researcher_header(self):
        headers = HeaderManager({
            "X-Bug-Bounty-Researcher": "researcher-123"
        }).build()

        self.assertEqual(
            headers["X-Bug-Bounty-Researcher"],
            "researcher-123"
        )

    def test_custom_user_agent(self):
        headers = HeaderManager({
            "user-agent": "Vultron-Test/1.0"
        }).build()

        self.assertEqual(
            headers["user-agent"],
            "Vultron-Test/1.0"
        )
        self.assertNotIn("User-Agent", headers)

    def test_host_header_blocked(self):
        with self.assertRaises(PermissionError):
            HeaderManager({
                "Host": "external.com"
            }).build()

    def test_content_length_blocked(self):
        with self.assertRaises(PermissionError):
            HeaderManager({
                "Content-Length": "100"
            }).build()

    def test_authorization_blocked(self):
        with self.assertRaises(PermissionError):
            HeaderManager({
                "Authorization": "Bearer secret"
            }).build()

    def test_forwarded_header_blocked(self):
        with self.assertRaises(PermissionError):
            HeaderManager({
                "X-Forwarded-For": "127.0.0.1"
            }).build()

    def test_newline_injection_blocked(self):
        with self.assertRaises(ValueError):
            HeaderManager({
                "X-Test": "safe\r\nInjected: evil"
            }).build()

    def test_invalid_header_name(self):
        with self.assertRaises(ValueError):
            HeaderManager({
                "Bad Header": "value"
            }).build()

    def test_duplicate_header_name(self):
        with self.assertRaises(ValueError):
            HeaderManager({
                "X-Test": "first",
                "x-test": "second"
            }).build()

    def test_non_string_value(self):
        with self.assertRaises(ValueError):
            HeaderManager({
                "X-Researcher": 123
            }).build()

    def test_invalid_mapping(self):
        with self.assertRaises(ValueError):
            HeaderManager([
                "X-Test: value"
            ])

    def test_header_too_long(self):
        with self.assertRaises(ValueError):
            HeaderManager({
                "X-Test": "a" * 3000
            }).build()


if __name__ == "__main__":
    unittest.main()