"""Security checks: pattern rules over source, config and infrastructure files."""
import re
from pathlib import Path

from .model import IGNORE_MARKS, Finding, pick
from .rules import DOCKER_LATEST, DOCKER_NO_USER, RULES

FROM_RE = re.compile(r"^\s*FROM\s+(\S+)", re.I)


def _applies(rule, ext, name):
    if name in rule.names:
        return True
    if not rule.exts:
        return not rule.names
    return ext in rule.exts or (name == ".env" and ".env" in rule.exts)


def _dockerfile(path, lines, lang):
    out = []
    if not any(l.strip().upper().startswith("USER ") for l in lines):
        rid, title, sev, advice, cwe = DOCKER_NO_USER
        out.append(Finding(rid, "security", sev, pick(title, lang), str(path), 1,
                           lines[0].strip()[:120] if lines else "", pick(advice, lang), cwe))
    for i, line in enumerate(lines, 1):
        m = FROM_RE.match(line)
        if not m or m.group(1).lower() == "scratch":
            continue
        image = m.group(1).split("@")[0]
        tag = image.rsplit(":", 1)[1] if ":" in image.split("/")[-1] else ""
        if "@" not in m.group(1) and tag in ("", "latest"):
            rid, title, sev, advice, cwe = DOCKER_LATEST
            out.append(Finding(rid, "security", sev, pick(title, lang), str(path), i, line.strip()[:120],
                               pick(advice, lang), cwe))
    return out


def check_file(path: Path, text: str, lang="en"):
    findings = []
    ext, name = path.suffix.lower(), path.name
    lines = text.splitlines()
    if name == "Dockerfile" or name.startswith("Dockerfile."):
        findings.extend(_dockerfile(path, lines, lang))
        name = "Dockerfile"
    rules = [r for r in RULES if _applies(r, ext, name)]
    for i, line in enumerate(lines, 1):
        if len(line) > 2000 or any(m in line for m in IGNORE_MARKS):
            continue
        for rule in rules:
            if rule.pattern.search(line):
                findings.append(Finding(rule.id, "security", rule.severity, pick(rule.title, lang), str(path), i,
                                        line.strip()[:120], pick(rule.advice, lang), rule.cwe))
    return findings
