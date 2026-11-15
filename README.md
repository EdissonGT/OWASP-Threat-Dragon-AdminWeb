# repocheckup

[![CI](https://github.com/EdissonGT/repocheckup/actions/workflows/validate.yml/badge.svg)](https://github.com/EdissonGT/repocheckup/actions/workflows/validate.yml)
[![repocheckup](docs/badge.svg)](docs/USAGE.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**A health checkup for any code repository.** One command reviews security, code quality, repository health and dependencies, gives the project a score from 0 to 100 and tells you how to fix each finding.

No dependencies. Only Python 3.8+. Works offline. Messages in English and Spanish. Optional AI recommendations that write the fix for you.

🇪🇸 [Leer en español](README.es.md)

## Quick start

```bash
git clone https://github.com/EdissonGT/repocheckup.git
cd repocheckup
python3 -m repocheckup /path/to/your/project --html report.html
```

```
[HIGH] INJ001 SQL built by concatenation or interpolation (CWE-89)
  app.py:13
  > cursor.execute("SELECT * FROM users WHERE name = '%s'" % user)
  How to fix: Use parameterized queries or an ORM.

Summary: 11 files analyzed, 49 findings
  Security                   0/100  F  (34)
  Code quality              82/100  B  (6)
  Repository health         76/100  B  (9)
  Overall score             53/100  D
```

Want to see it work first? Run it on the deliberately broken practice project in [`samples/vulnerable-app`](samples/vulnerable-app).

## AI recommendations (optional)

Add `--ai` and Claude reads the findings with the code around them, then returns a prioritized plan, the corrected code for each problem and the findings that look like false positives.

```bash
pip install "repocheckup[ai]" && export ANTHROPIC_API_KEY=...
repocheckup /path/to/your/project --ai --html report.html
```

It is off by default. When on, the findings and a few lines of code around each are sent to the Anthropic API and billed to your key. Details: [docs/USAGE.md](docs/USAGE.md#ai-recommendations---ai).

## What it checks

| Area | Examples |
|---|---|
| **Security** | Hardcoded secrets, SQL and command injection, weak crypto, XSS, disabled TLS, open CORS, unverified JWT, Dockerfile / Terraform / Kubernetes / GitHub Actions misconfigurations |
| **Code quality** | Long or complex functions, too many parameters, silenced errors, mutable defaults, TODO leftovers, duplicated code |
| **Repository health** | Missing README, license, tests, CI, lockfile, security policy; unpinned dependencies; committed `.env` files |
| **Dependencies** (`--deps`) | Known vulnerabilities in pinned PyPI and npm packages, via [OSV.dev](https://osv.dev) |

Output as text, JSON, SARIF (GitHub Code Scanning) or a self-contained HTML report with a Matrix look (`--theme classic` for a plain one). Full options and rule list: [docs/USAGE.md](docs/USAGE.md).

## Built to be adopted

- **Baseline**: accept today's findings and fail only on new ones (`--write-baseline`, `--baseline`).
- **Diff mode**: check only the lines you changed (`--diff origin/main`).
- **Config file**: turn rules off, change severities and thresholds in `.repocheckup.json`.
- **Score history and badge**: track the trend (`--history`) and show the score in your README (`--badge`).
- **Pull request comments**: the GitHub Action posts the score and the top findings.
- **`--fix`** (experimental): applies the AI's fixes, one reviewed diff at a time.

## Use it in GitHub Actions

```yaml
- uses: actions/checkout@v4
- uses: EdissonGT/repocheckup@main
  with:
    fail-on: high      # low | medium | high | critical | never
    min-score: "70"    # optional quality gate
    comment: "true"    # post the summary on the pull request
```

## More than a tool

This repository also includes material to **fix** what the tool finds:

- **Guides** (in Spanish) in [`docs/`](docs): authentication, authorization, input validation and APIs, data and cryptography, infrastructure and logging, supply chain and CI/CD, secure development lifecycle, OWASP Top 10, code quality, repository health.
- **[Release checklist](checklists/checklist-seguridad-aplicacion.md)** for application security.
- **Secure code examples** for [Node/Express](examples/node-express/secure-server.js) and [Python/Flask](examples/python-flask/secure_app.py), plus [recommended security headers](examples/security-headers.md).
- **CI templates** in [`templates/`](templates): security workflow (CodeQL, gitleaks, Trivy), Dependabot and pre-commit.

## Limits

`repocheckup` is pattern-based: expect false positives and false negatives. It is a fast first pass, not a replacement for code review, tests or dedicated tools such as CodeQL, Semgrep or SonarQube.

## Contributing

New rules, languages and translations are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Run the tests with `python3 -m unittest discover -s tests`.

## License

[MIT](LICENSE) © Edisson Payes
