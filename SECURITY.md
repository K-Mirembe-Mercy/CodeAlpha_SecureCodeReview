# Security Policy

## Intentionally vulnerable code

`app_vulnerable.py` contains deliberate security flaws for educational purposes. Reports about the vulnerabilities documented in `REVIEW_REPORT.md` are **not** security issues for this project.

## Safe use

- Run the vulnerable app only on `127.0.0.1`, never on a public or shared network.
- Prefer a virtual machine or container.
- Never use real credentials, personal data, or production systems with it.
- Never deploy `app_vulnerable.py`.

## Reporting a real issue

If you find a problem in `app_secure.py` (a flaw that the report does not cover, or an incomplete fix), please open a GitHub issue or use GitHub's **private vulnerability reporting** (Security tab). Include the affected file and line, steps to reproduce, and the impact.

## Supported versions

Only the latest commit on `main` is maintained.
