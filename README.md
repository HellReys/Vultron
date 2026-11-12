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