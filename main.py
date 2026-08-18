import os
from importlib.metadata import version, PackageNotFoundError
import sys
from dotenv import load_dotenv
from src.scanner import FastScanner
from src.vuln_checker import VulnChecker
from src.banner_grabber import grab_banner
from src.reporter import ScanReporter

load_dotenv()


def main():
    target = os.getenv("TARGET_IP")
    threads = int(os.getenv("THREADS"))
    checker = VulnChecker()

    print("\n" + "=" * 60)
    print("🔥 VULTRON 🔥")
    print("=" * 60)

    scanner = FastScanner(target, threads)
    open_ports = scanner.run(port_range=(50, 9000))

    if not open_ports:
        print("❌ No open ports found. Check target IP or network.")
        return

    scan_results = []

    for port in open_ports:
        print(f"📡 Analyzing port {port}...")
        banner = grab_banner(target, port)
        vuln_status = checker.check_vulnerability(banner)

        scan_results.append({
            "port": port,
            "status": "OPEN",
            "banner": banner,
            "vulnerability": vuln_status
        })

    reporter = ScanReporter(target)
    reporter.print_console_report(scan_results)
    reporter.export_to_json(scan_results)


def check_requirements(requirements_file="requirements.txt"):
    try:
        with open(requirements_file, "r", encoding="utf-8") as f:
            missing_packages = []
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                pkg_name = line.split("==")[0].split(">=")[0].split("<=")[0].strip()

                try:
                    version(pkg_name)
                except PackageNotFoundError:
                    missing_packages.append(pkg_name)

        if missing_packages:
            print("\n❌ [ERROR] Missing Python dependencies detected:")
            for pkg in missing_packages:
                print(f"   - {pkg}")
            print(f"\n💡 Please install missing packages by running:\n   pip install -r {requirements_file}\n")
            sys.exit(1)

    except FileNotFoundError:
        print(f"⚠️ [WARNING] {requirements_file} not found. Skipping dependency check.")
    except Exception as e:
        print(f"⚠️ [WARNING] An error occurred while checking requirements: {e}")



if __name__ == "__main__":
    check_requirements()
    main()