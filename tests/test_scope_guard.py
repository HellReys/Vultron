import unittest

from core.scope_guard import ScopeGuard


class TestScopeGuard(unittest.TestCase):

    def setUp(self):
        self.guard = ScopeGuard(
            allowed=["example.com", "*.example.com"],
            excluded=["admin.example.com"]
        )

    def test_root_domain(self):
        allowed, _ = self.guard.check_host("example.com")
        self.assertTrue(allowed)

    def test_subdomain(self):
        allowed, _ = self.guard.check_host("api.example.com")
        self.assertTrue(allowed)

    def test_excluded_domain(self):
        allowed, _ = self.guard.check_host("admin.example.com")
        self.assertFalse(allowed)

    def test_outside_domain(self):
        allowed, _ = self.guard.check_host("external.com")
        self.assertFalse(allowed)

    def test_fake_subdomain(self):
        allowed, _ = self.guard.check_host("example.com.evil.org")
        self.assertFalse(allowed)

    def test_valid_url(self):
        allowed, _ = self.guard.check_url(
            "https://api.example.com/users"
        )
        self.assertTrue(allowed)

    def test_invalid_scheme(self):
        allowed, _ = self.guard.check_url(
            "file:///etc/passwd"
        )
        self.assertFalse(allowed)

    def test_wildcard_does_not_include_root(self):
        guard = ScopeGuard(allowed=["*.example.com"])
        allowed, _ = guard.check_host("example.com")
        self.assertFalse(allowed)


    def test_explicit_exclusion_check(self):
        self.assertTrue(
            self.guard.is_excluded("admin.example.com")
        )

    def test_non_excluded_host(self):
        self.assertFalse(
            self.guard.is_excluded("api.example.com")
        )



if __name__ == "__main__":
    unittest.main()
