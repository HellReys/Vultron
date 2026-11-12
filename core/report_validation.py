import json
from datetime import datetime


MAX_REPORT_BYTES = 1_000_000
MAX_RESULTS = 4096


def validate_report(report):
    """Validate a Vultron JSON report before writing."""

    if not isinstance(report, dict):
        raise ValueError("Invalid report structure.")

    required = {
        "schema_version",
        "target",
        "scan_timestamp",
        "total_open_ports",
        "attempted_connections",
        "tcp_budget",
        "results",
        "cve_assessment",
    }

    if set(report) != required:
        raise ValueError("Invalid report fields.")

    if type(report["schema_version"]) is not int:
        raise ValueError("Invalid schema version.")

    if report["schema_version"] != 1:
        raise ValueError("Unsupported schema version.")

    target = report["target"]

    if (
        not isinstance(target, str)
        or not 1 <= len(target) <= 253
        or any(ord(c) < 32 or ord(c) == 127 for c in target)
    ):
        raise ValueError("Invalid report target.")

    timestamp = report["scan_timestamp"]

    if not isinstance(timestamp, str):
        raise ValueError("Invalid report timestamp.")

    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError as error:
        raise ValueError("Invalid report timestamp.") from error

    if parsed.utcoffset() is None:
        raise ValueError("Timestamp must have a timezone.")

    results = report["results"]

    if not isinstance(results, list):
        raise ValueError("Invalid TCP results.")

    if len(results) > MAX_RESULTS:
        raise ValueError("Too many TCP results.")

    for item in results:
        if not isinstance(item, dict):
            raise ValueError("Invalid TCP result.")

        if set(item) != {
            "port", "status", "service",
            "banner", "confidence",
        }:
            raise ValueError("Invalid TCP result fields.")

        port = item["port"]

        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Invalid TCP port.")

        if item["status"] not in {"OPEN", "NOT_OPEN"}:
            raise ValueError("Invalid TCP status.")

        for field, limit in (
            ("service", 200),
            ("confidence", 50),
        ):
            value = item[field]

            if value is not None and (
                not isinstance(value, str)
                or len(value) > limit
                or any(
                    ord(c) < 32 or ord(c) == 127
                    for c in value
                )
            ):
                raise ValueError(
                    f"Invalid TCP {field}."
                )

        if item["banner"] not in (None, "[REDACTED]"):
            raise ValueError("Raw banner export is prohibited.")

    def check_counter(value, name):
        if type(value) is not int or value < 0:
            raise ValueError(f"Invalid {name}.")
        return value

    open_count = check_counter(
        report["total_open_ports"], "open port count"
    )

    attempts = check_counter(
        report["attempted_connections"], "attempt count"
    )

    if open_count != sum(
        item["status"] == "OPEN" for item in results
    ):
        raise ValueError("Open port count mismatch.")

    if attempts != len(results):
        raise ValueError("TCP attempt count mismatch.")

    budget = report["tcp_budget"]

    if not isinstance(budget, dict) or set(budget) != {
        "used", "limit"
    }:
        raise ValueError("Invalid TCP budget structure.")

    used = check_counter(budget["used"], "TCP budget used")
    limit = check_counter(budget["limit"], "TCP budget limit")

    if limit < 1 or used > limit:
        raise ValueError("Invalid TCP budget values.")

    assessment = report["cve_assessment"]

    if not isinstance(assessment, dict):
        raise ValueError("Invalid CVE assessment.")

    if assessment.get("status") not in {
        "NOT_PERFORMED",
        "NO_ELIGIBLE_SERVICES",
        "COMPLETE",
        "PARTIAL",
        "ERROR",
    }:
        raise ValueError("Invalid CVE assessment status.")

    if assessment.get("vulnerability_confirmed") is not False:
        raise ValueError("Unexpected vulnerability confirmation.")

    if assessment.get("confirmed_vulnerabilities") != 0:
        raise ValueError("Unexpected confirmed vulnerability count.")

    try:
        encoded = json.dumps(
            report,
            indent=4,
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError("Report is not valid JSON.") from error

    if len(encoded) > MAX_REPORT_BYTES:
        raise ValueError("Report size limit exceeded.")

    return True
