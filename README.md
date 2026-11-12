# Vultron
**Release status:** Vultron 2.0.0 Release Candidate 1 (`2.0.0rc1`).

This is a pre-release development version. The stable v2.0.0 release has not been published yet.

Vultron is designed for authorized, policy-controlled security assessments. Scanning is disabled by default and must only be enabled for explicitly authorized targets.

Check the installed application version:

```bash
python main.py --version
```

The first stable v2.0.0 release will follow cross-platform verification and a limited, authorized live assessment.
## Architecture

Vultron uses a policy-controlled architecture designed for authorized security assessments.

The application is organized into several components:

- **`main.py`** - Command-line entry point, scan execution, and report generation.
- **`core/policy_engine.py`** - Enforces scanning authorization and program-specific restrictions.
- **`core/scope_guard.py`** - Validates whether targets are within the permitted scope.
- **`core/program_context.py`** - Coordinates shared policies, request budgets, and rate limits.
- **`core/tcp_scanner.py`** - Performs authorized TCP scans and passive service fingerprinting.
- **`core/nvd_client.py`** - Retrieves vulnerability information from NVD.
- **`core/nvd_scan_analysis.py`** - Processes bounded NVD lookups and vulnerability candidates.
- **`core/scan_report.py`** - Generates validated JSON reports with atomic file writing and banner redaction.
- **`tests/`** - Contains unit and integration tests.
## Installation

Vultron is an open-source cybersecurity scanner designed for authorized security assessments.

### Requirements

- Python 3.14
- Git
- pip
- Windows or Linux
- Authorization to assess the intended target

### 1. Download Vultron

Clone the repository:

```bash
git clone https://github.com/HellReys/Vultron.git
cd Vultron
```

Alternatively, download the source code from the GitHub Releases page when a stable release is available.

### 2. Create a Virtual Environment

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

### 3. Install Dependencies

```bash
python -m pip install -r requirements.txt
```

This installs the packages required to run Vultron. Development and testing dependencies are not required.

### 4. Verify Installation

```bash
python main.py --help
```

### 5. Configure Vultron

Vultron requires an explicitly authorized scanning configuration.

Start by copying the provided example:

**Windows (PowerShell):**

```powershell
Copy-Item config/programs/example.yaml config/programs/my-program.yaml
```

**Linux:**

```bash
cp config/programs/example.yaml config/programs/my-program.yaml
```

Edit `config/programs/my-program.yaml` and configure the authorized target scope, exclusions, scanning permissions, and applicable rate limits.

Scanning is disabled by default. Enable it only after verifying that you have explicit authorization from the target owner or the relevant security testing program.

### 6. Run Vultron

```bash
python main.py --program config/programs/my-program.yaml --target authorized.example.com --settings config/settings.yaml
```

To enable optional NVD candidate analysis:

```bash
python main.py --program config/programs/my-program.yaml --target authorized.example.com --settings config/settings.yaml --nvd
```

NVD matches are informational candidates and do not independently confirm exploitable vulnerabilities.
### Supported Platforms

- **Windows:** Tested with Python 3.14.
- **Linux:** Support is planned for verification through automated cross-platform testing.

### Security Notice

Only assess systems for which you have explicit authorization. Always comply with defined scope, rate limits, program policies, and applicable laws.

See the [Disclaimer](#disclaimer) and [LICENSE](LICENSE) for further information.

## Contributing

Contributions are welcome!

If you would like to improve Vultron, fix bugs, add tests, or contribute documentation, please read our [Contributing Guidelines](CONTRIBUTING.md).

Development contributions should target the `dev` branch. The `main` branch is intended for stable releases.
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