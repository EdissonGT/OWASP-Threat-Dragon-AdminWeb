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
git clone https://github.com/EdissonGT/repocheckup.git
cd repocheckup
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
| `--html FILE` | Write a self-contained HTML report (works offline). |
| `--format text\|json\|sarif` | Main output format. SARIF can be uploaded to GitHub Code Scanning. |
| `--output FILE` | Write the main output to a file. |
| `--fail-on low\|medium\|high\|critical\|never` | Exit code 1 when a finding of that severity or higher exists (default `high`). |
| `--min-score N` | Exit code 1 when the overall score is below `N`. |
| `--exclude NAME` | Folder name to skip (repeatable). `.git`, `node_modules`, `venv`, `dist`… are always skipped. |
| `--lang en\|es` | Language of the messages (default follows `LANG`). |
| `--theme matrix\|classic` | Look of the HTML report and the terminal banner. `matrix` (default) is green on black with falling code; `classic` is a plain light and dark theme. |

To silence a false positive on one line, add the comment `repocheckup-ignore`.

## AI recommendations (`--ai`)

Static rules tell you *what* is wrong. With `--ai`, Claude reads the findings together with the code around them and tells you *what to do about it*:

- a short assessment of the repository,
- a prioritized plan that groups findings sharing one fix, with the risk of leaving each as is,
- the corrected code for the flagged lines,
- which findings look like false positives,
- quick wins that take minutes.

```bash
pip install "repocheckup[ai]"
export ANTHROPIC_API_KEY=...            # from console.anthropic.com
repocheckup /path/to/your/project --ai --html report.html
```

The advice appears in the terminal, in the HTML report and under the `ai` key of the JSON output.

| Option | Description |
|---|---|
| `--ai` | Turn AI recommendations on. |
| `--ai-model MODEL` | Model to use (default `claude-opus-5-5`; also `REPOCHECKUP_AI_MODEL`). |
| `--ai-effort low\|medium\|high\|xhigh\|max` | How hard the model thinks. Higher costs more (default `medium`). |
| `--ai-max-findings N` | How many findings, most severe first, are sent (default 40). |

Before you turn it on:

- **Your code leaves your machine.** The findings and about a dozen source lines around each one are sent to the Anthropic API. Nothing is sent without `--ai`.
- **It costs money.** Each run is billed to your API key; the token count is printed after each run.
- **It needs Python 3.10+** (a requirement of the Anthropic SDK). The rest of the tool still runs on 3.8.
- **Review what it suggests.** It is a model reading snippets, not your whole project; treat its fixes as a proposal.
- If the API is unreachable or the key is missing, the normal report is still produced.

## Adopting it in an existing project

A first run on an old codebase can report hundreds of findings. Three options make it usable from day one.

**Baseline: fail only on new problems.** Record today's findings once, commit the file, and from then on only findings that are not in it count. Findings are matched by rule, file and the flagged text, so moving code around does not make them "new".

```bash
repocheckup . --write-baseline .repocheckup-baseline.json    # once
repocheckup . --baseline .repocheckup-baseline.json          # from then on
```

**Diff mode: only what you changed.** Reports findings on lines changed since a git reference, plus new files.

```bash
repocheckup . --diff origin/main
```

**Configuration file.** A `.repocheckup.json` in the scanned folder (or the current one) sets the defaults; command-line flags win over it.

```json
{
  "exclude": ["migrations", "fixtures"],
  "disable": ["QLT006", "K8S"],
  "severity": {"CFG005": "medium"},
  "limits": {"max_function_lines": 120, "max_complexity": 20, "max_params": 8, "max_file_lines": 1500},
  "checks": ["security", "quality", "health"],
  "fail_on": "high",
  "min_score": 70,
  "lang": "en",
  "theme": "matrix"
}
```

`disable` takes exact rule ids or prefixes (`"QLT"` turns off every quality rule). Use `--no-config` to ignore the file, which is worth doing in CI for pull requests from people you do not trust, since the file can relax the checks.

## Tracking and sharing the score

| Option | What you get |
|---|---|
| `--history FILE` | Appends each run to a JSON file. The terminal shows the change since the previous run and the HTML report draws the trend. |
| `--badge FILE` | An SVG badge such as `repocheckup 92/100 A`, colored by grade. Commit it and link it from your README. |
| `--markdown FILE` | A Markdown summary with the scores and the top findings, ready for a pull request comment. |

## Applying AI fixes (`--fix`, experimental)

With `--fix` (which turns on `--ai`), each code fix the model proposes is shown as a diff and applied if you accept it.

```bash
repocheckup . --fix          # asks before each change
repocheckup . --fix --yes    # applies everything without asking
```

A fix is applied only when the lines the model says it is replacing are found verbatim in the file, near the reported line. If they are not, the fix is skipped and nothing changes. Only files inside the scanned folder are touched, and likely false positives are never "fixed". Without a terminal and without `--yes`, the diffs are printed and nothing is written.

It has been tested with canned model answers, not yet against live output, so commit your work first, review every diff and run your tests afterwards.

## Scoring

Each area starts at 100 and loses points per finding: critical 25, high 10, medium 4, low 1. The overall score is the average of the areas that ran. Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F below.

## Use it in CI

GitHub Actions:

```yaml
permissions:
  contents: read
  pull-requests: write        # only needed for comment: "true"
steps:
  - uses: actions/checkout@v4
    with: { fetch-depth: 0 }  # only needed for diff-base
  - uses: EdissonGT/repocheckup@main
    with:
      fail-on: high
      min-score: "70"
      comment: "true"                         # post the summary on the pull request
      baseline: .repocheckup-baseline.json    # optional
      diff-base: origin/main                  # optional
```

The action writes the summary to the job page, updates one comment on the pull request when `comment` is on, writes `repocheckup.sarif`, `repocheckup-report.html` and `repocheckup-badge.svg`, and exposes a `score` output. Ready-to-copy files live in [`templates/`](../templates): a full security workflow (CodeQL, gitleaks, dependency review, Trivy, repocheckup), Dependabot and pre-commit.

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

Function-level metrics (QLT001–003) cover Python, exactly, and JavaScript/TypeScript, approximately (by matching braces, without a parser). QLT008–009 are Python-only; the other quality rules work across languages. Security rules cover Python, JavaScript/TypeScript, Java/Kotlin, Go, PHP, Ruby and C# to different depths.

## Limits

This is pattern-based analysis: it produces **false positives and false negatives**. Use it as a fast first pass and combine it with code review, tests and dedicated tools (CodeQL, Semgrep, SonarQube).

## Adding rules

Security rules live in `repocheckup/rules.py`: `r("ID", (english, spanish), "severity", r"regex", extensions, (advice_en, advice_es), "CWE")`. Add a case to `tests/` and run `python3 -m unittest discover -s tests`.
