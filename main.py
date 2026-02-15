import os
import sys
from dotenv import load_dotenv
from src.scanner import FastScanner
from prettytable import PrettyTable

load_dotenv()

def main():
    target = os.getenv("TARGET_IP")
    threads = int(os.getenv("THREADS"))

    print("\n" + "="*40)
    print("🔥 VULTRON: VULNERABILITY & RECON ENGINE 🔥")
    print("="*40 + "\n")

    scanner = FastScanner(target, threads)
    open_ports = scanner.run(port_range=(50, 9000))

    if not open_ports:
        print("❌ No open ports found. Check target IP or network.")
        return

    table = PrettyTable(["Port", "Status", "Service"])
    for port in open_ports:
        table.add_row([port, "OPEN", "Analyzing..."])

    print(table)


if __name__ == "__main__":
    main()