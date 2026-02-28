class VulnChecker:
    def __init__(self):
        self.vuln_db ={
            "SimpleHTTP/0.6": "🔥 [CRITICAL] Information Disclosure Risk (Dev Server)",
            "Apache/2.4.41": "🔥 [HIGH] CVE-2021-41773 (Path Traversal)",
            "OpenSSH_7.4": "🔥 [MEDIUM] CVE-2016-10012 (Privilege Escalation)"
        }

    def check_vulnerability(self, banner):
        for service, vuln in self.vuln_db.items():
            if service.lower() in banner.lower():
                return vuln

        return "✅ No known vulnerabilities"
