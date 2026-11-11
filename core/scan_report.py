import json
import re
from datetime import datetime, timezone
from pathlib import Path
from core.assessment_report import AssessmentReport


class ScanReportWriter:
    """Export policy-controlled scan results as JSON."""

    def __init__(self, output_dir="reports"):
        self.output_dir = Path(output_dir)

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

    def write(
        self,
        summary,
        tcp_budget_used,
        tcp_budget_limit,
        assessment=None
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
                "service": result.service,
                "banner": result.banner,
                "confidence": result.confidence
            })

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
            "cve_assessment": AssessmentReport.build(
                assessment
            )
        }

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

        # Exclusive creation prevents accidental overwrites.
        with filepath.open(
            "x", encoding="utf-8"
        ) as file:
            json.dump(
                report,
                file,
                indent=4,
                ensure_ascii=False
            )

        return filepath