import json
import os
from datetime import datetime
from prettytable import PrettyTable

class ScanReporter:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def print_console_report(self, scan_results):
        table = PrettyTable(["Port", "Status", "Banner", "Security Report"])
        table.align["Security Report"] = "l"

        for item in scan_results:
            table.add_row([item["port"], item["status"], item["banner"], item["vulnerability"]])

        print("\n" + str(table))

    def export_to_json(self, scan_results, output_dir="reports"):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        filename = f"scan_results_{self.target_ip.replace('.', '_')}.json"
        filepath = os.path.join(output_dir, filename)

        report_data = {
            "target": self.target_ip,
            "scan_timestamp": self.timestamp,
            "total_open_ports": len(scan_results),
            "results": scan_results
        }

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=4, ensure_ascii=False)
            print(f"\n💾 [INFO] Detailed JSON report saved to: {filepath}\n")
        except Exception as e:
            print(f"\n❌ [ERROR] Failed to save JSON report: {e}\n")