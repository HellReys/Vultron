# Contributing to Vultron

Thank you for your interest in contributing to Vultron!

Vultron is an open-source cybersecurity project focused on authorized security assessments, responsible vulnerability research, and policy-controlled scanning.

We welcome bug reports, documentation improvements, tests, security fixes, and well-designed feature contributions.

## Development Setup

### 1. Fork and Clone

Fork the repository on GitHub and clone your fork:

```bash
git clone https://github.com/YOUR_USERNAME/Vultron.git
cd Vultron
```

Replace `YOUR_USERNAME` with your GitHub username.

### 2. Switch to the Development Branch

Development contributions should be based on the `dev` branch:

```bash
git switch dev
git pull origin dev
```

Create a separate branch for your changes:

```bash
git switch -c feature/your-feature-name
```

Use descriptive branch names such as `feature/`, `fix/`, `docs/`, or `test/`.

### 3. Set Up a Virtual Environment

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

### 4. Install Dependencies

Install runtime and development dependencies:

```bash
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

Verify the installation:

```bash
python -m pip check
```

## Project Structure

- `main.py` — Command-line interface and application execution.
- `core/` — Scanning, policy enforcement, networking, vulnerability analysis, and reporting components.
- `config/` — Application settings and authorized program configurations.
- `tests/` — Unit and integration tests.
- `requirements.txt` — Runtime dependencies.
- `requirements-dev.txt` — Development and testing dependencies.

## Code Quality

All contributions should follow these guidelines:

- Write clear, maintainable Python code.
- Keep components modular and focused on a single responsibility.
- Avoid unnecessary dependencies or duplicate implementations.
- Preserve existing public interfaces unless a change is justified.
- Handle network errors, invalid inputs, and unexpected responses safely.
- Never expose API keys, credentials, private scan data, or sensitive response contents in logs or reports.

Run Ruff before submitting changes:

```bash
ruff check . --select E4,E7,E9,F,I
```

Fix any reported issues before creating a pull request.

## Testing

All code changes must be tested.

Run the complete test suite:

```bash
python -m unittest discover -s tests
```

Where appropriate, add unit or integration tests covering new behavior.

Changes affecting security controls should include tests demonstrating that unauthorized or unsafe operations remain blocked.

Live external API tests may be disabled by default. Contributors should not enable live scanning or external testing without suitable authorization and an understanding of the associated requests.

## Security Requirements

Security controls are a central part of Vultron's design.

Contributions must preserve:

- Explicit scanning authorization.
- Target scope and exclusion enforcement.
- Request and TCP connection budgets.
- Rate limiting and concurrency restrictions.
- DNS/IP validation and appropriate private-address protections.
- Safe HTTP behavior, including method and redirect restrictions.
- Response-size and timeout limits.
- Accurate vulnerability classification and evidence handling.
- Sensitive-data protection in logs and exported reports.

Do not introduce alternative networking paths that bypass the existing policy-controlled architecture.

Vulnerability candidates must not be presented as independently verified findings without appropriate evidence.

## Pull Requests

Before submitting a pull request:

1. Create a focused feature or bug-fix branch.
2. Make the necessary changes.
3. Add or update relevant tests.
4. Run Ruff and the full test suite.
5. Update documentation when behavior changes.
6. Submit a pull request targeting the `dev` branch.

Keep pull requests focused and explain their purpose, main changes, and testing performed.

## Reporting Bugs

When reporting a bug, please include:

- A clear description of the issue.
- Steps to reproduce it.
- Expected and actual behavior.
- Python version and operating system.
- Relevant error messages or sanitized logs.

Do not share credentials, authentication tokens, private target information, or other sensitive data in public issues.

## Reporting Security Vulnerabilities

Please do not publicly disclose potentially exploitable vulnerabilities affecting Vultron before they can be reviewed.

Use GitHub's private vulnerability reporting feature if it is enabled for the repository. Otherwise, contact the maintainers through an appropriate private channel.

Do not include exploit details or sensitive proof-of-concept data in public issues.

## Responsible Use

Vultron is intended for authorized security research and assessments.

Contributors must not add functionality intended to bypass authorization checks, violate defined assessment scope, or conceal unauthorized network activity.

All development and testing must comply with applicable laws and security testing program rules.

## License

By contributing to Vultron, you agree that your contributions will be distributed under the project's MIT License.

See [LICENSE](LICENSE) for details.