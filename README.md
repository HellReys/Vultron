## Architecture

Vultron uses a policy-controlled architecture designed for authorized security assessments.

The application is organized into several components:

- **`main.py`** — Command-line entry point, scan execution, and report generation.
- **`core/policy_engine.py`** — Enforces scanning authorization and program-specific restrictions.
- **`core/scope_guard.py`** — Validates whether targets are within the permitted scope.
- **`core/program_context.py`** — Coordinates shared policies, request budgets, and rate limits.
- **`core/tcp_scanner.py`** — Performs authorized TCP scans and passive service fingerprinting.
- **`core/nvd_client.py`** — Retrieves vulnerability information from NVD.
- **`core/nvd_scan_analysis.py`** — Processes bounded NVD lookups and vulnerability candidates.
- **`core/scan_report.py`** — Generates validated JSON reports with atomic file writing and banner redaction.
- **`tests/`** — Contains unit and integration tests.
## Installation

Vultron is a Python-based cybersecurity scanning tool designed for authorized security assessments. It supports Windows and Linux environments.

### Prerequisites

Before installing Vultron, ensure that you have:

- Python 3.14 (tested on Windows)
- Git
- pip (Python package manager)
- An internet connection to install dependencies
- Explicit authorization before scanning any target

### 1. Clone the Repository

```bash
git clone https://github.com/HellReys/Vultron.git
cd Vultron
```

To use the latest development version:

```bash
git switch dev
```

### 2. Create a Virtual Environment

Using a virtual environment keeps Vultron's dependencies isolated from other Python projects.

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

If the Linux environment does not include `venv`, install the appropriate Python virtual environment package for your distribution.

### 3. Install Dependencies

Install the required packages:

```bash
python -m pip install -r requirements.txt
```

For development and testing, also install:

```bash
python -m pip install -r requirements-dev.txt
```

Verify dependency compatibility:

```bash
python -m pip check
```

### 4. Verify Installation

Check that the command-line interface starts correctly:

```bash
python main.py --help
```

Run Vultron with the provided example configuration:

```bash
python main.py --program config/programs/example.yaml --target example.com --settings config/settings.yaml
```

The example configuration disables scanning by default. Therefore, the expected response is:

```text
[ERROR] Scanning is disabled or authorization has not been confirmed.
```

This behavior confirms that Vultron is enforcing its authorization requirements.

To perform an actual security assessment, users must configure an explicitly authorized program, including permitted targets, scope restrictions, and applicable scanning limits.

### 5. Run Tests (Optional)

Developers can verify the installation by running:

```bash
python -m unittest discover -s tests
```

Check code quality using Ruff:

```bash
ruff check . --select E4,E7,E9,F,I
```

### Platform Compatibility

- **Windows:** Clean installation and automated tests verified using Python 3.14.
- **Linux:** Installation instructions are provided; automated Linux validation is planned.

### Security Notice

Vultron must only be used on systems for which the operator has explicit permission to conduct security testing. Users are responsible for complying with applicable laws, defined scope, rate limits, and vulnerability disclosure program rules.

See the [Disclaimer](#disclaimer) and [LICENSE](LICENSE) for additional information.
## Usage

Vultron requires an explicitly authorized program configuration before running a scan.

```bash
python main.py --program config/programs/example.yaml --target example.com --settings config/settings.yaml
```

NVD analysis can optionally be enabled using:

```bash
python main.py --program config/programs/example.yaml --target example.com --settings config/settings.yaml --nvd
```

The example program has scanning disabled by default. Users must configure a permitted scope and confirm authorization before running assessments.

NVD keyword matches are vulnerability candidates, not independently verified findings.

Vultron is intended for authorized security research only.

## Disclaimer

Vultron is an open-source cybersecurity tool developed for educational purposes, authorized security assessments, and responsible vulnerability research.

**By using Vultron, you acknowledge and agree to the following:**

- **Authorized Use Only:** Vultron must only be used against systems, networks, and applications for which the user has explicit authorization to perform security assessments.
- **User Responsibility:** Users are solely responsible for ensuring their activities comply with applicable laws, regulations, and the rules of the relevant vulnerability disclosure or bug bounty program.
- **No Unauthorized Testing:** Scanning, probing, or assessing systems without proper authorization is not an intended or supported use of this project.
- **Assessment Limitations:** Vulnerability matches, service fingerprints, and CVE references are informational indicators and must not be treated as confirmed vulnerabilities without appropriate independent verification.
- **No Guarantee of Security:** A successful scan or the absence of reported vulnerabilities does not guarantee that a target system is secure.
- **No Warranty:** Vultron is provided "AS IS", without warranties of any kind, as described in the MIT License.

The developers do not endorse unauthorized or unlawful use of this software. Security assessments must respect defined scope, rate limits, program policies, and applicable legal requirements.

## License

Vultron is licensed under the **MIT License**.

See the [LICENSE](LICENSE) file for the full license terms.

Copyright © 2026 HellReys.