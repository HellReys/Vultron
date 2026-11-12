import unicodedata


def safe_terminal_text(value, max_length=200):
    """Render untrusted text without terminal controls."""

    if type(max_length) is not int or max_length < 1:
        raise ValueError("Invalid terminal text limit.")

    if not isinstance(value, str):
        return "UNKNOWN"

    cleaned = []

    for char in value[:max_length]:
        category = unicodedata.category(char)

        if category in {"Cc", "Cf", "Cs"}:
            cleaned.append("?")
        else:
            cleaned.append(char)

    return "".join(cleaned)
