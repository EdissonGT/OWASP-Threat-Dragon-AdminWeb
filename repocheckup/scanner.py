"""Orchestrates the checks over one or more paths."""
from pathlib import Path

from . import deps, health, quality, security
from .files import iter_files, read_text
from .model import SEVERITY_ORDER


def scan(paths, checks=("security", "quality", "health"), exclude=(), lang="en", osv_query=deps.query_osv):
    """Return (findings, warnings, files_scanned)."""
    findings, warnings, sources = [], [], []
    for raw in paths:
        root = Path(raw)
        for path in iter_files(root, exclude):
            text = read_text(path)
            if text is None:
                continue
            sources.append((path, text))
            if "security" in checks:
                findings += security.check_file(path, text, lang)
            if "quality" in checks:
                findings += quality.check_file(path, text, lang)
        if "health" in checks:
            findings += health.check_repo(root, exclude, lang)
        if "deps" in checks:
            found, warn = deps.check_repo(root, exclude, lang, osv_query)
            findings += found
            if warn:
                warnings.append(warn)
    if "quality" in checks:
        findings += quality.find_duplicates(sources, lang)
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.category, f.file, f.line))
    return findings, warnings, len(sources)
