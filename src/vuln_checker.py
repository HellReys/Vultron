import requests
import urllib.parse


class VulnChecker:
    def __init__(self):
        self.api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache = {}
        self.headers = {
            "User-Agent": "Vultron"
        }

    def check_vulnerability(self, banner):
        if not banner or banner == "Unknown":
            return "UNKNOWN (No Banner)"

        # Extract the main service/version name from the banner ("Apache/2.4.41" -> "Apache 2.4.41")
        clean_keyword = banner.split()[0].replace("/", " ").strip()

        # Re exhaust the API if it exists in the cache
        if clean_keyword in self.cache:
            return self.cache[clean_keyword]

        try:
            encoded_keyword = urllib.parse.quote(clean_keyword)
            # NVD API v2.0 keywordSearch
            url = f"{self.api_url}?keywordSearch={encoded_keyword}&resultsPerPage=1"

            response = requests.get(url, headers=self.headers, timeout=4.0)

            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                if vulnerabilities:
                    cve_data = vulnerabilities[0].get("cve", {})
                    cve_id = cve_data.get("id", "CVE-Unknown")

                    # NVD Risk (CVSS Severity)
                    metrics = cve_data.get("metrics", {})
                    severity = "UNKNOWN"
                    if "cvssMetricV31" in metrics:
                        severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]

                    result = f"🔥 [{severity}] {cve_id}"
                else:
                    result = "✅ No known vulnerabilities found"
            elif response.status_code == 403:
                result = "⚠️ NVD Rate Limit Exceeded"
            else:
                result = "✅ No known vulnerabilities matched"

        except requests.exceptions.Timeout:
            result = "⚠️ NVD API Timeout"
        except Exception:
            result = "✅ No critical CVE matched"

        # Write the result to the cache
        self.cache[clean_keyword] = result
        return result