import argparse
import sys

from core.config_manager import ConfigurationManager
from core.policy_engine import PolicyEngine
from core.program_context import ProgramContext
from core.scan_orchestrator import ScanOrchestrator
from core.scan_report import ScanReportWriter


def create_parser():
    parser = argparse.ArgumentParser(
        prog="vultron",
        description=(
            "Vultron - Policy-controlled security scanner"
        )
    )

    parser.add_argument(
        "--program",
        required=True,
        help="Path to an authorized program YAML file."
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target hostname or IP address."
    )

    parser.add_argument(
        "--settings",
        default="config/settings.yaml",
        help="Path to global application settings."
    )

    return parser


def run_scan(program_path, target, settings_path):
    """
    Run a scan through the validated program context.

    No direct socket connections are made here.
    """

    settings = ConfigurationManager(
        settings_path
    ).load()

    policy = PolicyEngine(program_path)

    print("\n" + "=" * 60)
    print(f"  {settings.app.name.upper()}")
    print("=" * 60)

    # Reject disabled or unauthorized scanning.
    if not policy.can_scan():
        raise PermissionError(
            "Scanning is disabled or authorization "
            "has not been confirmed."
        )

    tcp_policy = policy.tcp_policy

    if not tcp_policy.enabled:
        raise PermissionError(
            "TCP scanning is disabled by program policy."
        )

    if not tcp_policy.allowed_ports:
        raise PermissionError(
            "No authorized TCP ports are configured."
        )

    context = ProgramContext(
        policy=policy,
        settings=settings
    )

    orchestrator = ScanOrchestrator(context)

    print(f"[TARGET] {target}")
    print(
        "[PORTS] "
        + ", ".join(
            str(port)
            for port in tcp_policy.allowed_ports
        )
    )

    summary = orchestrator.scan_tcp(target)

    print("\n[SCAN COMPLETED]")
    print(
        f"Connection results: "
        f"{summary.attempted_connections}"
    )

    print(f"Open ports: {len(summary.open_ports)}")

    print("\nPORT     STATUS       SERVICE     CONFIDENCE")
    print("-" * 55)

    for result in summary.results:
        status = "OPEN" if result.open else "NOT_OPEN"

        print(
            f"{result.port:<8} "
            f"{status:<12} "
            f"{result.service:<11} "
            f"{result.confidence}"
        )

        if result.open and result.banner:
            print(f"         Banner: {result.banner}")

    budget_used = context.tcp_budget.used
    budget_limit = context.tcp_budget.max_requests

    print(
        f"\nTCP budget used: "
        f"{budget_used}/{budget_limit}"
    )

    reporter = ScanReportWriter()

    report_path = reporter.write(
        summary=summary,
        tcp_budget_used=budget_used,
        tcp_budget_limit=budget_limit
    )

    print(f"[REPORT] Saved to: {report_path}")

    return summary


def main(argv=None):
    parser = create_parser()
    args = parser.parse_args(argv)

    try:
        run_scan(
            program_path=args.program,
            target=args.target,
            settings_path=args.settings
        )

    except (
        PermissionError,
        ValueError,
        OSError
    ) as error:
        print(
            f"[ERROR] {error}",
            file=sys.stderr
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())