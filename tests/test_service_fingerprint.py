import unittest

from core.service_fingerprint import ServiceFingerprinter


class TestServiceFingerprinter(unittest.TestCase):

    def test_ssh_banner(self):
        result = ServiceFingerprinter.identify(
            b"SSH-2.0-OpenSSH_9.6\r\n"
        )

        self.assertEqual(result.service, "SSH")
        self.assertEqual(result.confidence, "high")
        self.assertEqual(
            result.banner,
            "SSH-2.0-OpenSSH_9.6"
        )

    def test_smtp_banner(self):
        result = ServiceFingerprinter.identify(
            b"220 mail.example.com ESMTP SMTP ready\r\n"
        )

        self.assertEqual(result.service, "SMTP")

    def test_ftp_banner(self):
        result = ServiceFingerprinter.identify(
            b"220 FTP Server ready\r\n"
        )

        self.assertEqual(result.service, "FTP")

    def test_http_banner(self):
        result = ServiceFingerprinter.identify(
            b"HTTP/1.1 200 OK\r\n"
        )

        self.assertEqual(result.service, "HTTP")

    def test_unknown_banner(self):
        result = ServiceFingerprinter.identify(
            b"Welcome to Example Service\r\n"
        )

        self.assertEqual(result.service, "Unknown")
        self.assertEqual(result.confidence, "none")

    def test_empty_banner(self):
        result = ServiceFingerprinter.identify(b"")

        self.assertEqual(result.service, "Unknown")
        self.assertEqual(result.banner, "")

    def test_banner_size_limit(self):
        result = ServiceFingerprinter.identify(
            b"A" * 1000
        )

        self.assertEqual(len(result.banner), 256)

    def test_invalid_input(self):
        with self.assertRaises(TypeError):
            ServiceFingerprinter.identify("SSH-2.0")

    def test_version_information_propagated(self):
        result = ServiceFingerprinter.identify(
            b"SSH-2.0-OpenSSH_9.6\r\n"
        )

        self.assertEqual(result.service, "SSH")
        self.assertEqual(result.product, "OpenSSH")
        self.assertEqual(result.version, "9.6")
        self.assertEqual(
            result.version_source,
            "ssh_banner"
        )


if __name__ == "__main__":
    unittest.main()