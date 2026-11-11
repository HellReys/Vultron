import unittest

from core.service_version import ServiceVersionExtractor


class TestServiceVersionExtractor(unittest.TestCase):

    def test_openssh_version(self):
        result = ServiceVersionExtractor.extract(
            b"SSH-2.0-OpenSSH_9.6\r\n"
        )

        self.assertEqual(result.product, "OpenSSH")
        self.assertEqual(result.version, "9.6")
        self.assertEqual(result.source, "ssh_banner")

    def test_openssh_patch_version(self):
        result = ServiceVersionExtractor.extract(
            b"SSH-2.0-OpenSSH_9.6p1 Debian\r\n"
        )

        self.assertEqual(result.product, "OpenSSH")
        self.assertEqual(result.version, "9.6p1")

    def test_apache_http_server(self):
        result = ServiceVersionExtractor.extract(
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Apache/2.4.58\r\n"
            b"Content-Length: 0\r\n\r\n"
        )

        self.assertEqual(
            result.product,
            "Apache HTTP Server"
        )
        self.assertEqual(result.version, "2.4.58")
        self.assertEqual(
            result.source,
            "http_server_header"
        )

    def test_nginx_http_server(self):
        result = ServiceVersionExtractor.extract(
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx/1.24.0\r\n\r\n"
        )

        self.assertEqual(result.product, "nginx")
        self.assertEqual(result.version, "1.24.0")

    def test_unknown_banner(self):
        result = ServiceVersionExtractor.extract(
            b"Welcome to Example Server\r\n"
        )

        self.assertIsNone(result.product)
        self.assertIsNone(result.version)

    def test_empty_banner(self):
        result = ServiceVersionExtractor.extract(b"")

        self.assertIsNone(result.product)
        self.assertIsNone(result.version)

    def test_invalid_input(self):
        with self.assertRaises(TypeError):
            ServiceVersionExtractor.extract(
                "SSH-2.0-OpenSSH_9.6"
            )

    def test_no_version_guessing(self):
        result = ServiceVersionExtractor.extract(
            b"SSH-2.0-CustomSSH_9.6\r\n"
        )

        self.assertIsNone(result.product)
        self.assertIsNone(result.version)

    def test_fake_http_header_rejected(self):
        result = ServiceVersionExtractor.extract(
            b"Hello Server: Apache/2.4.58\r\n"
        )

        self.assertIsNone(result.product)

    def test_banner_size_limit(self):
        result = ServiceVersionExtractor.extract(
            b"A" * 256
            + b"SSH-2.0-OpenSSH_9.6\r\n"
        )

        self.assertIsNone(result.product)


if __name__ == "__main__":
    unittest.main()