import unittest

from core.terminal_output import safe_terminal_text


class TestTerminalOutput(unittest.TestCase):

    def test_control_characters(self):
        text = "OpenSSH\n\x1b[31mALERT"

        result = safe_terminal_text(text)

        self.assertNotIn("\n", result)
        self.assertNotIn("\x1b", result)
        self.assertIn("OpenSSH", result)

    def test_length_limit(self):
        result = safe_terminal_text(
            "A" * 500,
            max_length=60,
        )

        self.assertEqual(len(result), 60)

    def test_invalid_input(self):
        self.assertEqual(
            safe_terminal_text(None),
            "UNKNOWN",
        )

        with self.assertRaises(ValueError):
            safe_terminal_text(
                "example",
                max_length=True,
            )


if __name__ == "__main__":
    unittest.main()
