"""Adoption helpers: baseline (accept today's findings), diff mode (only changed lines) and score history."""
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
MAX_HISTORY = 200


class TrackingError(ValueError):
    pass


# --- Baseline ---------------------------------------------------------------
def fingerprint(f):
    """Stable across line shifts: rule + file + the flagged text, not the line number."""
    text = "|".join((f.rule, Path(f.file).as_posix(), " ".join(f.snippet.split())))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:20]


def write_baseline(findings, path):
    counts = {}
    for f in findings:
        counts[fingerprint(f)] = counts.get(fingerprint(f), 0) + 1
    Path(path).write_text(json.dumps({"version": 1, "findings": counts}, indent=1, sort_keys=True) + "\n",
                          encoding="utf-8")
    return len(findings)


def apply_baseline(findings, path):
    """Return (new findings, number hidden because they are in the baseline)."""
    try:
        known = dict(json.loads(Path(path).read_text(encoding="utf-8"))["findings"])
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise TrackingError(f"cannot read baseline {path}: {e}")
    new = []
    for f in findings:
        fp = fingerprint(f)
        if known.get(fp, 0) > 0:
            known[fp] -= 1
        else:
            new.append(f)
    return new, len(findings) - len(new)


# --- Diff mode ----------------------------------------------------------------
def _git(args, cwd):
    try:
        done = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise TrackingError(f"git failed: {e}")
    if done.returncode != 0:
        raise TrackingError(f"git {args[0]} failed: {done.stderr.strip() or done.stdout.strip()}")
    return done.stdout


def changed_lines(ref, cwd="."):
    """Map absolute file path -> list of (start, end) changed line ranges, or None for a whole new file."""
    if not ref or ref.startswith("-"):
        raise TrackingError(f"invalid git reference: {ref!r}")
    root = Path(_git(["rev-parse", "--show-toplevel"], cwd).strip())
    changed, current = {}, None
    for line in _git(["diff", "-U0", "--no-color", "--no-ext-diff", ref, "--"], root).splitlines():
        if line.startswith("+++ "):
            name = line[4:].strip()
            current = None if name == "/dev/null" else str((root / name[2:]).resolve())
            if current:
                changed.setdefault(current, [])
        elif current and line.startswith("@@"):
            m = HUNK_RE.match(line)
            if m:
                start, count = int(m.group(1)), int(m.group(2) or 1)
                if count:
                    changed[current].append((start, start + count - 1))
    for name in _git(["ls-files", "--others", "--exclude-standard"], root).splitlines():
        changed[str((root / name).resolve())] = None
    return changed


def apply_diff(findings, changed):
    """Keep findings on changed lines. File-level findings are kept when their file changed."""
    kept = []
    for f in findings:
        key = str(Path(f.file).resolve())
        if key not in changed:
            continue
        ranges = changed[key]
        if ranges is None or f.category == "health" or any(a <= f.line <= b for a, b in ranges):
            kept.append(f)
    return kept


# --- History ------------------------------------------------------------------
def record_history(path, overall, per, total):
    """Append this run to the history file and return the full list (oldest first)."""
    file = Path(path)
    try:
        history = json.loads(file.read_text(encoding="utf-8")) if file.exists() else []
    except (OSError, ValueError) as e:
        raise TrackingError(f"cannot read history {path}: {e}")
    if not isinstance(history, list):
        raise TrackingError(f"history {path} must contain a JSON list")
    history.append({"date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "score": overall,
                    "scores": per, "findings": total})
    history = history[-MAX_HISTORY:]
    file.write_text(json.dumps(history, indent=1) + "\n", encoding="utf-8")
    return history
