
# Vultron

**Version:** 2.0.0

Vultron is an open-source, policy-controlled cybersecurity reconnaissance and service fingerprinting tool designed for authorized security assessments, educational use, and responsible vulnerability research.

Vultron supports controlled TCP port scanning, service identification, HTTP/HTTPS fingerprinting, optional NVD vulnerability candidate analysis, and structured JSON reporting.

Security and authorization are central to its design. Scanning is disabled by default and must only be enabled for explicitly authorized targets.

Check the application version:

```bash
python main.py --version
```

## Features

- **Policy-Controlled Scanning:** Enforces explicit authorization, target scope restrictions, exclusions, and configured scanning permissions.
- **TCP Port Scanning:** Performs bounded TCP connection attempts against permitted ports.
- **Service Fingerprinting:** Identifies supported network services using available protocol and banner evidence.
- **HTTP/HTTPS Fingerprinting:** Performs controlled HTTP requests to identify basic web service characteristics.
- **NVD Integration:** Optionally retrieves CVE candidates associated with eligible service and version information.
- **Request and Connection Budgets:** Enforces configurable limits on TCP connections and HTTP requests.
- **Rate Limiting:** Controls scanning rates and concurrent operations.
- **DNS and Connection Safety:** Applies scope validation, destination checks, and IP pinning to help prevent unintended connections.
- **Structured JSON Reports:** Exports validated assessment results with bounded data handling and sensitive banner redaction.
- **Cross-Platform Support:** Developed for Windows and Linux, with automated testing on both platforms.

Vultron prioritizes controlled reconnaissance and evidence-based reporting rather than aggressive scanning or exploitation.

## Architecture

Vultron uses a modular, policy-controlled architecture designed for authorized security assessments.

The application is organized into several components:

- **`main.py`** - Command-line entry point, scan execution, and report generation.
- **`core/policy_engine.py`** - Enforces scanning authorization and program-specific restrictions.
- **`core/scope_guard.py`** - Validates whether targets are within the permitted scope.
- **`core/program_context.py`** - Coordinates shared policies, request budgets, and rate limits.
- **`core/connection_guard.py`** - Validates network destinations and helps prevent unsafe connections.
- **`core/tcp_scanner.py`** - Performs authorized TCP scanning and service identification.
- **`core/service_fingerprint.py`** - Represents identified services and supporting fingerprint evidence.
- **`core/http_transport.py`** - Provides controlled HTTP/HTTPS communication with connection safety and response limits.
- **`core/http_probe.py`** - Performs optional HTTP/HTTPS probing of supported open ports.
- **`core/http_fingerprint.py`** - Extracts conservative HTTP service fingerprints from responses.
- **`core/http_report.py`** - Converts HTTP fingerprint results into structured report entries.
- **`core/nvd_client.py`** - Retrieves vulnerability information from the National Vulnerability Database.
- **`core/nvd_scan_analysis.py`** - Processes bounded NVD lookups and vulnerability candidates.
- **`core/scan_report.py`** - Generates validated JSON reports with atomic file writing and banner redaction.
- **`core/report_validation.py`** - Validates generated assessment reports.
- **`tests/`** - Contains unit, integration, and optional live API tests.

The modular architecture separates scanning, authorization, network communication, vulnerability analysis, and reporting.

## Installation

### Requirements

- Python 3.14
- Git
- pip
- Windows or Linux
- Explicit authorization to assess the intended target

### 1. Download Vultron

Clone the repository:

```bash
git clone https://github.com/HellReys/Vultron.git
cd Vultron
```

The `main` branch is intended for stable releases, while active development takes place on the `dev` branch.

Alternatively, download the source code from the GitHub Releases page when the desired release is available.

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

This installs the packages required to run Vultron.

Development and testing dependencies are not required for normal usage.

### 4. Verify Installation

Display the application version:

```bash
python main.py --version
```

Display the available command-line options:

```bash
python main.py --help
```

### 5. Configure Vultron

Vultron requires an explicitly authorized scanning configuration.

Start by copying the provided example configuration.

**Windows (PowerShell):**

```powershell
Copy-Item config/programs/example.yaml config/programs/my-program.yaml
```

**Linux:**

```bash
cp config/programs/example.yaml config/programs/my-program.yaml
```

Edit `config/programs/my-program.yaml` and configure:

- Authorized target scope
- Excluded domains
- Scanning permissions
- TCP port restrictions
- Request and connection limits
- Rate limits and concurrency
- Applicable program-specific headers

Scanning is disabled by default.

Enable scanning only after confirming that the target owner or relevant security testing program explicitly permits the intended assessment.

A target being publicly accessible does not automatically authorize security scanning.

### 6. Run Vultron

Run an authorized TCP scan:

```bash
python main.py --program config/programs/my-program.yaml --target authorized.example.com --settings config/settings.yaml
```

The target must be permitted by the selected program configuration.

To enable optional NVD candidate analysis:

```bash
python main.py --program config/programs/my-program.yaml --target authorized.example.com --settings config/settings.yaml --nvd
```

NVD matches are informational candidates and do not independently confirm exploitable vulnerabilities.

## HTTP/HTTPS Fingerprinting

Vultron supports optional HTTP/HTTPS fingerprinting for authorized targets.

HTTP probing is limited to supported open TCP ports:

- Port 80 - HTTP
- Port 443 - HTTPS

Enable HTTP/HTTPS fingerprinting:

```bash
python main.py --program config/programs/my-program.yaml --target authorized.example.com --settings config/settings.yaml --http-fingerprint
```

Enable HTTP fingerprinting and optional NVD analysis together:

```bash
python main.py --program config/programs/my-program.yaml --target authorized.example.com --settings config/settings.yaml --http-fingerprint --nvd
```

### HTTP Security Controls

HTTP/HTTPS probing uses the existing policy-controlled networking architecture.

The implementation includes:

- GET-only HTTP probing
- Scope enforcement
- DNS and destination validation
- Pinned network connections
- Configurable request budgets
- Rate limiting
- Bounded response handling
- TLS certificate verification
- No automatic redirect following

These controls are intended to reduce unintended network activity and maintain predictable scanning behavior.

HTTP probing uses shared HTTP request budgets managed through the program context.

### Fingerprinting Results

HTTP fingerprinting may identify:

- HTTP or HTTPS service type
- Product information when available
- Version information when available
- The source of detected version information
- Probe status

Many production systems do not expose their underlying product or version information.

When reliable information is unavailable, Vultron reports null values rather than inventing product or version details.

**Important:** HTTP fingerprints are not independently submitted to NVD for vulnerability analysis in this release.

NVD analysis uses eligible TCP service evidence. Identifying an HTTP service does not automatically establish a product, version, or applicable CVE.

## NVD Vulnerability Candidate Analysis

Vultron provides optional integration with the National Vulnerability Database (NVD).

The analysis component can perform bounded keyword-based vulnerability lookups using eligible service and version information.

NVD processing includes:

- Validation of service identification data
- Bounded vulnerability queries
- Request rate limiting
- Response size restrictions
- Response validation
- Caching
- Error handling
- Partial-result identification
- Structured candidate reporting

NVD queries do not automatically establish that a discovered service is vulnerable.

A matching CVE may refer to a different software configuration, platform, product build, or deployment environment.

**Vultron does not treat NVD keyword matches as confirmed vulnerabilities without independent supporting evidence.**

If insufficient service or version information is available, NVD analysis may report:

```text
NO_ELIGIBLE_SERVICES
```

The availability and reliability of live NVD queries depend on the external NVD API.

If the API is unavailable, rate-limited, or times out, Vultron handles the error without treating an incomplete vulnerability lookup as a successful assessment.

## JSON Reporting

Vultron generates structured JSON reports containing the results of authorized assessments.

Reports are saved to the `reports/` directory.

The report structure depends on the enabled features.

### Schema Version 1

Used for standard scanning without HTTP fingerprinting.

Reports include information such as:

- Target
- Scan timestamp
- Open port count
- TCP connection attempts
- TCP connection budget
- Port and service results
- Optional NVD assessment

### Schema Version 2

Used when HTTP/HTTPS fingerprinting is enabled.

Schema version 2 includes the standard scanning information and an additional:

```json
"http_fingerprints": [
    {
        "port": 443,
        "status": "OK",
        "service": "HTTPS",
        "product": null,
        "version": null,
        "version_source": null,
        "evidence_verified": false
    }
]
```

This example represents a successful HTTPS probe where the underlying product and version could not be identified.

The `evidence_verified` field indicates whether the reported product/version evidence has been independently verified.

Report generation includes validation, bounded data handling, and atomic file writing.

Raw TCP banners and sensitive HTTP response contents are not exported as unrestricted report data.

**A report containing no confirmed vulnerabilities does not establish that the assessed target is secure.**

## Security and Authorization

Vultron is designed around explicit authorization and controlled network activity.

Its security controls include:

- Scanning disabled by default
- Explicit authorization confirmation
- Allowed and excluded target scope validation
- Restricted TCP port selection
- TCP connection budgets
- HTTP request budgets
- Rate and concurrency limits
- Safe destination validation
- HTTP GET-only restrictions
- No automatic HTTP redirects
- Response size restrictions
- Sensitive output handling

These controls help reduce unintended or excessive scanning activity.

However, no technical restriction can replace the requirement to obtain appropriate authorization.

Users must independently verify that their selected targets, scanning methods, request volumes, and HTTP headers comply with the applicable security testing program.

## Supported Platforms

- **Windows:** Tested with Python 3.14.
- **Linux:** Automated tests run with Python 3.14 on Ubuntu through GitHub Actions.

Continuous integration validates unit and integration tests on Windows and Ubuntu.

Compatibility with every operating system version, Linux distribution, or network environment is not guaranteed.

## Development and Testing

Vultron includes automated unit and integration tests.

Development dependencies can be installed with:

```bash
python -m pip install -r requirements-dev.txt
```

Run the full test suite:

```bash
python -m unittest discover -s tests
```

Run Ruff static analysis:

```bash
ruff check . --select E4,E7,E9,F,I
```

Check Python compilation:

```bash
python -m compileall -q core main.py tests
```

Audit project dependencies:

```bash
python -m pip_audit -r requirements.txt -r requirements-dev.txt
```

Check installed dependency compatibility:

```bash
python -m pip check
```

Some tests requiring live external services are intentionally disabled during normal test execution.

These tests must not be treated as successful live integration checks when they are skipped.

GitHub Actions runs automated checks across the supported development platforms.

## Contributing

Contributions are welcome!

If you would like to improve Vultron, fix bugs, add tests, or contribute documentation, please read the [Contributing Guidelines](CONTRIBUTING.md).

Development contributions should target the `dev` branch.

The `main` branch is intended for stable releases.

Contributions must preserve Vultron's authorization controls, scope enforcement, request limits, and defensive safety mechanisms.

## Disclaimer

Vultron is an open-source cybersecurity tool developed for educational purposes, authorized security assessments, and responsible vulnerability research.

**By using Vultron, you acknowledge and agree to the following:**

- **Authorized Use Only:** Vultron must only be used against systems, networks, and applications for which the user has explicit authorization to perform security assessments.
- **User Responsibility:** Users are solely responsible for ensuring their activities comply with applicable laws, regulations, and the rules of the relevant vulnerability disclosure or bug bounty program.
- **No Unauthorized Testing:** Scanning, probing, or assessing systems without proper authorization is not an intended or supported use of this project.
- **Assessment Limitations:** Vulnerability matches, service fingerprints, and CVE references are informational indicators and must not be treated as confirmed vulnerabilities without appropriate independent verification.
- **No Guarantee of Security:** A successful scan or the absence of reported vulnerabilities does not guarantee that a target system is secure.
- **No Warranty:** Vultron is provided "AS IS", without warranties of any kind, as described in the MIT License.

The developers do not endorse unauthorized or unlawful use of this software.

Security assessments must respect defined scope, rate limits, program policies, and applicable legal requirements.

## License

Vultron is licensed under the **MIT License**.

See the [LICENSE](LICENSE) file for the full license terms.

Copyright © 2026 HellReys.
