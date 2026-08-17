# Vultron

### Automated Vulnerability & Recon Engine

**Vultron** is a high speed, multi threaded vulnerability scanner designed to perform automated reconnaissance on target systems. It doesn't just find open ports; it identifies the services running on them and maps their versions to known security vulnerabilities (CVEs).



##  Key Features

* **Multi-threaded Port Scanning:** Leverages Python's `threading` and `socket` libraries to scan thousands of ports in seconds.
* **Service Fingerprinting:** Performs "Banner Grabbing" to identify the software and version (e.g., Apache 2.4.41, OpenSSH 7.4) running on open ports.
* **Vulnerability Mapping:** Automatically compares detected service versions against a local vulnerability database to flag critical risks.
* **Smart Probing:** Uses fallback HTTP probes to identify silent services that don't reveal their identity immediately.
* **Clean Reporting:** Generates a structured security report using `PrettyTable` for clear visibility.

##  Project Architecture

* **`src/scanner.py`**: The high performance engine responsible for discovering open TCP ports.
* **`src/banner_grabber.py`**: The "Recon" module that interacts with open ports to extract service information.
* **`src/vuln_checker.py`**: The logic engine that maps service strings to a database of known security threats (CVEs).
* **`main.py`**: The orchestrator that manages the workflow and environment configuration.

##  Installation & Usage

### 1. Requirements
* Python 3.x
* Dependencies: `prettytable`, `python-dotenv`, `requests`

### 2. Setup
```bash
# Clone the repository
git clone https://github.com/HellReys/Vultron.git
cd Vultron

# Install dependencies
pip install -r requirements.txt
```
### 3. Configuration
Create a .env file in the root directory: You can find the example of .env file(.env.example)
```bash
TARGET_IP=127.0.0.1  # Or target hostname like scanme.nmap.org
THREADS=100
```
### 4. Run
```bash
python3 main.py
```

##  Sample Output
```
🔍 [SCANNING] Target: 192.168.1.50
📡 Analyzing port 80...
📡 Analyzing port 22...

+------+--------+-----------------+-------------------------------------------------+
| Port | Status |     Banner      | Security Report                                 |
+------+--------+-----------------+-------------------------------------------------+
| 22   | OPEN   | OpenSSH 7.4     | 🔥 [MEDIUM] CVE-2016-10012 (Privilege Esc.)      |
| 80   | OPEN   | Apache/2.4.41   | 🔥 [HIGH] CVE-2021-41773 (Path Traversal)       |
+------+--------+-----------------+-------------------------------------------------+
```

## ⚠️ Disclaimer
This tool is strictly for educational and authorized security testing purposes. Use it only on systems you own or have explicit permission to test. Unauthorized scanning can be detected and may lead to legal consequences.
