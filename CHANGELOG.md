# Changelog

Versions follow [Semantic Versioning](https://semver.org).

## 2.1.0

### Added
- **AI recommendations** (`--ai`): a prioritized plan, corrected code and likely false positives from the Claude API. Opt-in; needs `repocheckup[ai]` and an API key.
- **`--fix`** (experimental): applies AI fixes after showing each diff. A fix is applied only when the code it replaces is found verbatim in the file.
- **Baseline** (`--write-baseline`, `--baseline`): fail only on findings that are new.
- **Diff mode** (`--diff REF`): report only findings on changed lines.
- **Configuration file** (`.repocheckup.json`): disable rules, override severities and thresholds.
- **Score history** (`--history`) with a trend line in the HTML report.
- **Badge** (`--badge`) and **Markdown summary** (`--markdown`).
- **GitHub Action**: job summary, optional pull request comment, badge, `baseline` and `diff-base` inputs.
- Function metrics for JavaScript and TypeScript (approximate).
- Matrix theme for the HTML report and terminal banner (`--theme classic` for the plain look).

### Not yet verified against live services
- `--ai` and `--fix` have been tested with canned model answers only.
- `--deps` has been tested with a mocked OSV response only.
- The pull request comment has not run on a real pull request.

## 2.0.0

- Renamed to `repocheckup`. Added code quality and repository health checks, opt-in OSV dependency lookup, scoring, the HTML report, English and Spanish messages, and rules for Go, PHP, Terraform, Kubernetes and GitHub Actions.

## 1.0.0

- First release as `appsec-scan`: security pattern rules for Python, JavaScript and Dockerfiles.
