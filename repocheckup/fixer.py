"""Apply AI-suggested fixes (--fix). Experimental.

A fix is applied only when the model's `original_code` is found verbatim in the file near the reported line,
so a wrong line number or a hallucinated snippet changes nothing. Every change is shown as a diff first.
"""
import difflib
from dataclasses import dataclass
from pathlib import Path

SEARCH_RADIUS = 15


@dataclass
class Edit:
    path: Path
    start: int        # 0-based index of the first replaced line
    count: int        # number of replaced lines
    new_lines: list
    fix: dict


def _inside(path, roots):
    resolved = path.resolve()
    for root in roots:
        base = Path(root).resolve()
        if resolved == base or base in resolved.parents:
            return True
    return False


def _indent(line):
    return line[:len(line) - len(line.lstrip())]


def _locate(lines, original, near):
    """Index where `original` occurs (ignoring indentation and trailing spaces), closest to `near`."""
    want = [o.strip() for o in original]
    hits = [i for i in range(len(lines) - len(want) + 1)
            if [l.strip() for l in lines[i:i + len(want)]] == want and abs(i - near) <= SEARCH_RADIUS]
    return min(hits, key=lambda i: abs(i - near)) if hits else None


def _reindent(fixed, original_first, file_first):
    """Shift the fixed code so it sits at the file's indentation, not the model's."""
    model_indent, file_indent = _indent(original_first), _indent(file_first)
    if model_indent == file_indent:
        return fixed
    return [file_indent + line[len(model_indent):] if line.startswith(model_indent) and line.strip() else line
            for line in fixed]


def plan(advice, roots):
    """Return (edits, skipped) where skipped is a list of (fix, reason)."""
    edits, skipped = [], []
    for fix in advice.get("fixes", []):
        original = [l for l in fix.get("original_code", "").splitlines()]
        fixed = fix.get("fixed_code", "").splitlines()
        path = Path(fix.get("file", ""))
        if fix.get("false_positive") or not fixed or not any(l.strip() for l in original):
            continue
        if not path.is_file() or not _inside(path, roots):
            skipped.append((fix, "file is outside the scanned folder"))
            continue
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        at = _locate(lines, original, int(fix.get("line", 1)) - 1)
        if at is None:
            skipped.append((fix, "the original code was not found near that line"))
            continue
        edits.append(Edit(path, at, len(original), _reindent(fixed, original[0], lines[at]), fix))
    return _drop_overlaps(edits, skipped), skipped


def _drop_overlaps(edits, skipped):
    kept = []
    for e in sorted(edits, key=lambda e: (str(e.path), e.start)):
        prev = kept[-1] if kept else None
        if prev and prev.path == e.path and e.start < prev.start + prev.count:
            skipped.append((e.fix, "overlaps another fix"))
        else:
            kept.append(e)
    return kept


def diff(edit):
    lines = edit.path.read_text(encoding="utf-8", errors="ignore").splitlines()
    after = lines[:edit.start] + edit.new_lines + lines[edit.start + edit.count:]
    return "\n".join(difflib.unified_diff(lines, after, f"a/{edit.path}", f"b/{edit.path}", lineterm="", n=2))


def apply(edits, approve):
    """Apply the edits the `approve(edit)` callback accepts. Returns the number applied."""
    accepted = [e for e in edits if approve(e)]
    by_file = {}
    for e in accepted:
        by_file.setdefault(e.path, []).append(e)
    for path, group in by_file.items():
        raw = path.read_bytes().decode("utf-8", errors="ignore")   # bytes: keep the file's own line endings
        newline = "\r\n" if "\r\n" in raw else "\n"
        lines = raw.splitlines()
        for e in sorted(group, key=lambda e: -e.start):   # bottom-up keeps earlier indexes valid
            lines[e.start:e.start + e.count] = e.new_lines
        text = newline.join(lines) + (newline if raw.endswith(("\n", "\r")) else "")
        path.write_bytes(text.encode("utf-8"))
    return len(accepted)
