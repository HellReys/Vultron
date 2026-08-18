import os
import shutil
import sys
from dotenv import load_dotenv
from src.scanner import FastScanner
from src.vuln_checker import VulnChecker
from src.banner_grabber import grab_banner
from prettytable import PrettyTable

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

    table = PrettyTable(["Port", "Status", "Banner", "Security Report"])
    table.align["Security Report"] = "l"

    for port in open_ports:
        print(f"📡 Analyzing port {port}...")
        banner = grab_banner(target, port)
        vuln_status = checker.check_vulnerability(banner)
        table.add_row([port, "OPEN", banner, vuln_status])

    print("\n" + str(table))

def check_dependencies():
    tools = ["requests", "prettytable", "python-dotenv"]
    missing_tools = []
    for tool in tools:
        if not shutil.which(tool):
            missing_tools.append(tool)

    if missing_tools:
        for tool in missing_tools:
            print(f"❌ [ERROR] {tool.capitalize()} is not installed. Please install {tool} to proceed.")
        sys.exit(1)

if __name__ == "__main__":
    check_dependencies()
    main()