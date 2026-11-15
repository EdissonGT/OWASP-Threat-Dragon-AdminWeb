"""Motor de análisis: recorre archivos, aplica reglas y produce hallazgos."""
import os
from dataclasses import dataclass, asdict
from pathlib import Path

from .rules import RULES

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "vendor", ".tox", "target"}
MAX_BYTES = 1_000_000
IGNORE_MARK = "appsec-ignore"


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    file: str
    line: int
    snippet: str
    advice: str
    cwe: str

    def to_dict(self):
        return asdict(self)


def _is_text(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return b"\0" not in fh.read(2048)
    except OSError:
        return False


def iter_files(root: Path, exclude=()):
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and d not in exclude]
        for name in filenames:
            p = Path(dirpath) / name
            if any(part in exclude for part in p.parts):
                continue
            yield p


def scan_file(path: Path):
    findings = []
    try:
        if path.stat().st_size > MAX_BYTES or not _is_text(path):
            return findings
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings
    ext, name = path.suffix.lower(), path.name
    lines = text.splitlines()
    for rule in RULES:
        if rule.names:
            if name not in rule.names:
                continue
        elif rule.exts and ext not in rule.exts and name not in {".env"}:
            continue
        if rule.names:  # reglas a nivel de archivo (Dockerfile)
            if rule.id == "DOC001" and not any(l.strip().upper().startswith("USER ") for l in lines):
                findings.append(Finding(rule.id, rule.title, rule.severity, str(path), 1, lines[0][:120] if lines else "",
                                        rule.advice, rule.cwe))
            elif rule.id == "DOC002":
                for i, l in enumerate(lines, 1):
                    if rule.pattern.match(l) and ":" not in l.split()[1].split("@")[0] or l.strip().lower().endswith(":latest"):
                        findings.append(Finding(rule.id, rule.title, rule.severity, str(path), i, l.strip()[:120],
                                                rule.advice, rule.cwe))
            continue
        for i, line in enumerate(lines, 1):
            if IGNORE_MARK in line or len(line) > 2000:
                continue
            if rule.pattern.search(line):
                findings.append(Finding(rule.id, rule.title, rule.severity, str(path), i, line.strip()[:120],
                                        rule.advice, rule.cwe))
    return findings


def scan(paths, exclude=()):
    results = []
    for root in paths:
        for f in iter_files(Path(root), set(exclude)):
            results.extend(scan_file(f))
    results.sort(key=lambda x: (-SEVERITY_ORDER[x.severity], x.file, x.line))
    return results
