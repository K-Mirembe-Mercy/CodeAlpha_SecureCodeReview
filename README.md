# CodeAlpha Secure Code Review

A security audit of a deliberately vulnerable Flask application. The app contains **9 intentional flaws**, including SQL injection, command injection and path traversal. Each finding is rated with **OWASP** and **CWE** references, and a fixed version of the app is included for comparison.

Built for the **CodeAlpha Cyber Security Internship**.

> ⚠️ **Warning:** `app_vulnerable.py` is intentionally insecure. Never deploy it, expose it to a network, or run it on a machine you care about without isolation. Run it only on `localhost`, ideally in a virtual machine or container.

## What's in this repo

| File | Purpose |
|------|---------|
| `app_vulnerable.py` | Flask app with 9 intentional vulnerabilities (the audit target) |
| `REVIEW_REPORT.md` | Full findings: description, severity, OWASP category, CWE ID, and remediation |
| `app_secure.py` | Remediated version of the app |
| `requirements.txt` | Python dependencies |
| `SECURITY.md` | Security policy and safe-use guidance |
| `CONTRIBUTING.md` | How to suggest improvements |

## Quick start

Requires Python 3.9+.

```bash
git clone https://github.com/K-Mirembe-Mercy/CodeAlpha_SecureCodeReview.git
cd CodeAlpha_SecureCodeReview

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Run the fixed version
python app_secure.py

# Run the vulnerable version (localhost only, in an isolated environment)
python app_vulnerable.py
```

Then open the address printed in the terminal (usually `http://127.0.0.1:5000`).

## How to use this project

1. Read `app_vulnerable.py` and try to find the flaws yourself.
2. Compare your list with `REVIEW_REPORT.md`.
3. Diff the two versions to see how each flaw was fixed:
   ```bash
   diff -u app_vulnerable.py app_secure.py
   ```

## Vulnerability classes covered

Includes (among the 9 findings in the report):

- SQL injection (CWE-89, OWASP A03: Injection)
- OS command injection (CWE-78, OWASP A03: Injection)
- Path traversal (CWE-22, OWASP A01: Broken Access Control)

See `REVIEW_REPORT.md` for the complete list with severity ratings and fixes.

## Methodology

Manual code review of the source, followed by classification of each finding using the OWASP Top 10 and the CWE catalog, then remediation and verification in `app_secure.py`.

## Disclaimer

This project is for **education and authorized security testing only**. The author accepts no responsibility for misuse. Only test systems you own or have written permission to test.

## License

Released under the [MIT License](LICENSE).

## Author

**Kafeero Mirembe Mercy**: [GitHub](https://github.com/K-Mirembe-Mercy) · [LinkedIn](https://ug.linkedin.com/in/kafeero-mirembe-mercy-25b953343)
