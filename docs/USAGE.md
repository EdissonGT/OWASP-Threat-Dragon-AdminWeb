# repocheckup: usage and rule reference

`repocheckup` reviews a project in four areas and gives it a score from 0 to 100:

| Area | What it checks |
|---|---|
| **Security** | Hardcoded secrets, injection, weak crypto, XSS, insecure config, Docker, Terraform, Kubernetes, GitHub Actions |
| **Code quality** | Long or complex functions, too many parameters, silenced errors, mutable defaults, TODO leftovers, duplicated code |
| **Repository health** | README, license, tests, CI, `.gitignore`, lockfiles, pinned dependencies, security policy, committed `.env` files |
| **Dependencies** (opt-in) | Known vulnerabilities in pinned packages, via the public [OSV.dev](https://osv.dev) database |

It needs only Python 3.8+ and has no dependencies.

## Install and run

```bash
git clone https://github.com/EdissonGT/OWASP-Threat-Dragon-AdminWeb.git
cd OWASP-Threat-Dragon-AdminWeb
python3 -m repocheckup /path/to/your/project          # run without installing
pip install . && repocheckup /path/to/your/project    # or install the command
```

Try it on the deliberately broken practice project:

```bash
python3 -m repocheckup samples/vulnerable-app --html report.html
```

## Options

| Option | Description |
|---|---|
| `--checks security,quality,health` | Which areas to run. `all` adds `deps`. |
| `--deps` | Also look up pinned dependencies in OSV.dev. **Sends package names and versions to api.osv.dev.** |
| `--html FILE` | Write a self-contained HTML report (works offline, light and dark theme). |
| `--format text\|json\|sarif` | Main output format. SARIF can be uploaded to GitHub Code Scanning. |
| `--output FILE` | Write the main output to a file. |
| `--fail-on low\|medium\|high\|critical\|never` | Exit code 1 when a finding of that severity or higher exists (default `high`). |
| `--min-score N` | Exit code 1 when the overall score is below `N`. |
| `--exclude NAME` | Folder name to skip (repeatable). `.git`, `node_modules`, `venv`, `dist`… are always skipped. |
| `--lang en\|es` | Language of the messages (default follows `LANG`). |

To silence a false positive on one line, add the comment `repocheckup-ignore`.

## Scoring

Each area starts at 100 and loses points per finding: critical 25, high 10, medium 4, low 1. The overall score is the average of the areas that ran. Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F below.

## Use it in CI

GitHub Actions:

```yaml
- uses: actions/checkout@v4
- uses: EdissonGT/OWASP-Threat-Dragon-AdminWeb@main
  with:
    fail-on: high
    min-score: "70"
```

The action writes `repocheckup.sarif` and `repocheckup-report.html` and exposes a `score` output. Ready-to-copy files live in [`templates/`](../templates): a full security workflow (CodeQL, gitleaks, dependency review, Trivy, repocheckup), Dependabot and pre-commit.

## Rules

| Rule | Area | Detects |
|---|---|---|
| SEC001–005 | Security | Hardcoded secrets, AWS keys, private keys, GitHub / Slack / Stripe tokens |
| CRY001–003 | Security | MD5/SHA-1, TLS verification disabled, weak randomness for tokens |
| INJ001–005 | Security | SQL injection, `eval`/`exec`, shell commands, insecure deserialization, PHP file inclusion |
| XSS001–002 | Security | Unsafe HTML insertion (JS, React, Vue), unescaped PHP output |
| SSRF001, PATH001 | Security | User-controlled URLs and file paths |
| CFG001–006 | Security | Debug mode, open CORS, insecure cookies, unverified JWT, `http://` links, `curl \| sh` |
| DOC001–002 | Security | Dockerfile without non-root user, `latest` base image |
| TF001–003 | Security | Terraform: public buckets, open ingress, encryption off, public databases |
| K8S001–004 | Security | Kubernetes: privileged, root, host namespaces, `latest` images |
| GHA001–002 | Security | GitHub Actions: script injection, `pull_request_target` |
| QLT001–004 | Quality | Function > 80 lines, complexity > 15, more than 7 parameters, file > 1000 lines |
| QLT005–006 | Quality | Empty `except`/`catch`, TODO/FIXME/HACK notes |
| QLT007 | Quality | Duplicated blocks of 10+ lines |
| QLT008–009 | Quality | Python syntax errors, mutable default arguments |
| HLT001–013 | Health | Missing README, license, tests, CI, `.gitignore`, lockfile, security policy, contributing guide; unpinned dependencies; committed `.env`; large files |
| DEP001 | Dependencies | Pinned package with known vulnerabilities (PyPI `requirements*.txt`, npm `package-lock.json`) |

Function-level quality metrics (QLT001–003, 008, 009) are Python-only; the other quality rules work across languages. Security rules cover Python, JavaScript/TypeScript, Java/Kotlin, Go, PHP, Ruby and C# to different depths.

## Limits

This is pattern-based analysis: it produces **false positives and false negatives**. Use it as a fast first pass and combine it with code review, tests and dedicated tools (CodeQL, Semgrep, SonarQube).

## Adding rules

Security rules live in `repocheckup/rules.py`: `r("ID", (english, spanish), "severity", r"regex", extensions, (advice_en, advice_es), "CWE")`. Add a case to `tests/` and run `python3 -m unittest discover -s tests`.
