#!/usr/bin/env bash
# Entry point of the GitHub Action. Inputs arrive as RC_* environment variables (never interpolated into code).
set -uo pipefail

args=("$RC_PATH" --lang "${RC_LANG:-en}")
for d in ${RC_EXCLUDE:-}; do args+=(--exclude "$d"); done
[ -n "${RC_CHECKS:-}" ] && args+=(--checks "$RC_CHECKS")
[ -n "${RC_BASELINE:-}" ] && args+=(--baseline "$RC_BASELINE")
[ -n "${RC_DIFF:-}" ] && args+=(--diff "$RC_DIFF")
gate=()
[ -n "${RC_FAIL_ON:-}" ] && gate+=(--fail-on "$RC_FAIL_ON")
[ -n "${RC_MIN_SCORE:-}" ] && gate+=(--min-score "$RC_MIN_SCORE")

summary="$(mktemp)"
json="$(mktemp)"

# 1. Reports (never fails the job by itself).
python3 -m repocheckup "${args[@]}" --fail-on never --format sarif --output "$RC_SARIF" \
  --html "$RC_HTML" --badge "$RC_BADGE" --markdown "$summary" || exit 2
python3 -m repocheckup "${args[@]}" --fail-on never --format json --output "$json" || exit 2
score="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["score"])' "$json")"
echo "score=$score" >> "${GITHUB_OUTPUT:-/dev/null}"
cat "$summary" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"

# 2. Optional pull request comment, updated in place on later runs.
if [ "${RC_COMMENT:-false}" = "true" ] && [ -n "${RC_PR:-}" ]; then
  gh pr comment "$RC_PR" --body-file "$summary" --edit-last --create-if-none \
    || echo "::warning::repocheckup could not comment on the pull request (does the job have 'pull-requests: write'?)"
fi

# 3. The gate: this is the step that passes or fails the job.
python3 -m repocheckup "${args[@]}" "${gate[@]}"
