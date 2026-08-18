import json
import os
from datetime import datetime
from prettytable import PrettyTable

class ScanReporter:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        # Keep the scan time for the report
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def print_console_report(self, scan_results):
        # Build a simple table for the terminal output
        table = PrettyTable(["Port", "Status", "Banner", "Security Report"])
        table.align["Security Report"] = "l"

        for item in scan_results:
            table.add_row([item["port"], item["status"], item["banner"], item["vulnerability"]])

        print("\n" + str(table))

    def export_to_json(self, scan_results, output_dir="reports"):
        # Create the reports folder if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Use the target IP in the filename
        filename = f"scan_results_{self.target_ip.replace('.', '_')}.json"
        filepath = os.path.join(output_dir, filename)

        # Prepare all scan data for the JSON report
        report_data = {
            "target": self.target_ip,
            "scan_timestamp": self.timestamp,
            "total_open_ports": len(scan_results),
            "results": scan_results
        }

        try:
            # Save the report as a readable JSON file
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=4, ensure_ascii=False)
            print(f"\n💾 [INFO] Detailed JSON report saved to: {filepath}\n")
        except Exception as e:
            # Show the error instead of stopping the scanner
            print(f"\n❌ [ERROR] Failed to save JSON report: {e}\n")