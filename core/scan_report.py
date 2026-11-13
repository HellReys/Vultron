import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from core.assessment_report import AssessmentReport
from core.http_report import build_http_report
from core.nvd_scan_analysis import NVDScanBatch
from core.report_validation import validate_report
from core.terminal_output import safe_terminal_text


class ScanReportWriter:
    """Export policy-controlled scan results as JSON."""

    def __init__(self, output_dir="reports"):
        self.output_dir = Path(output_dir)
        self.last_assessment_section = None


    @staticmethod
    def _safe_target(target):
        if not isinstance(target, str) or not target:
            raise ValueError("Invalid report target.")

        safe = re.sub(
            r"[^a-zA-Z0-9._-]",
            "_",
            target
        )

        safe = safe.strip("._-")[:80]

        if not safe:
            raise ValueError("Invalid report target.")

        return safe

    @staticmethod
    def _build_assessment_section(assessment):
        if isinstance(assessment, NVDScanBatch):
            try:
                return AssessmentReport.build(assessment)
            except (ValueError, TypeError, AttributeError):
                return AssessmentReport.nvd_report_error()

        return AssessmentReport.build(assessment)

    @staticmethod
    def _atomic_write(filepath, report):
        """
        Write a complete JSON report without overwriting
        an existing file or leaving partial JSON behind.
        """
        temp_path = None

        try:
            fd, temp_name = tempfile.mkstemp(
                prefix=".vultron_",
                suffix=".tmp",
                dir=filepath.parent,
            )
            temp_path = Path(temp_name)

            with os.fdopen(fd, "w", encoding="utf-8") as file:
                json.dump(
                    report,
                    file,
                    indent=4,
                    ensure_ascii=False,
                    allow_nan=False,
                )
                file.flush()
                os.fsync(file.fileno())

            # Atomic creation without replacing an existing report.
            # Both paths are on the same filesystem.
            os.link(temp_path, filepath)

        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    def write(
        self,
        summary,
        tcp_budget_used,
        tcp_budget_limit,
        assessment=None,
        http_results=None,
    ):
        """Create a new report without overwriting old reports."""

        if (
            type(tcp_budget_used) is not int
            or type(tcp_budget_limit) is not int
            or not 0 <= tcp_budget_used <= tcp_budget_limit
            or tcp_budget_limit < 1
        ):
            raise ValueError("Invalid TCP budget information.")

        timestamp = datetime.now(timezone.utc)

        results = []

        for result in summary.results:
            results.append({
                "port": result.port,
                "status": (
                    "OPEN" if result.open else "NOT_OPEN"
                ),
                "service": safe_terminal_text(
                    result.service,
                    max_length=200,
                ),
                "banner": (
                    "[REDACTED]" if result.banner else None
                ),
                "confidence": safe_terminal_text(
                    result.confidence,
                    max_length=50,
                ),
            })


        assessment_section = self._build_assessment_section(
            assessment
        )

        report = {
            "schema_version": 1,
            "target": summary.target,
            "scan_timestamp": timestamp.isoformat(),
            "total_open_ports": len(summary.open_ports),
            "attempted_connections": (
                summary.attempted_connections
            ),
            "tcp_budget": {
                "used": tcp_budget_used,
                "limit": tcp_budget_limit
            },
            "results": results,
            "cve_assessment": assessment_section
        }

        if http_results is not None:
            report["schema_version"] = 2
            report["http_fingerprints"] = (
                build_http_report(http_results)
            )

        validate_report(report)

        self.output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        target_name = self._safe_target(
            summary.target
        )

        timestamp_name = timestamp.strftime(
            "%Y%m%d_%H%M%S_%f"
        )

        filename = (
            f"vultron_{target_name}_{timestamp_name}.json"
        )

        filepath = self.output_dir / filename

        self._atomic_write(filepath, report)

        self.last_assessment_section = assessment_section

        return filepath