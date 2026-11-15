"""Dependency checks: looks up pinned packages in the public OSV.dev vulnerability database.

Opt-in (--deps) because it sends package names and versions to https://api.osv.dev.
"""
import json
import re
import urllib.request
from pathlib import Path

from .files import iter_files
from .model import Finding, pick

OSV_URL = "https://api.osv.dev/v1/querybatch"
PIN_RE = re.compile(r"^([A-Za-z0-9][\w.\-]*)(?:\[[^\]]*\])?\s*==\s*([\w.\-+!]+)")
TITLE = ("Vulnerable dependency: {pkg} {ver} ({n} known)", "Dependencia vulnerable: {pkg} {ver} ({n} conocidas)")
ADVICE = ("Upgrade to a fixed version. Details: https://osv.dev/vulnerability/{id}",
          "Actualiza a una versión corregida. Detalle: https://osv.dev/vulnerability/{id}")


def parse_requirements(path):
    out = []
    for i, raw in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        m = PIN_RE.match(raw.split("#")[0].strip())
        if m:
            out.append(("PyPI", m.group(1), m.group(2), i))
    return out


def parse_package_lock(path):
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except ValueError:
        return []
    out = []
    for key, info in (data.get("packages") or {}).items():
        if key.startswith("node_modules/") and isinstance(info, dict) and info.get("version"):
            out.append(("npm", key.split("node_modules/")[-1], info["version"], 1))
    for name, info in (data.get("dependencies") or {}).items():
        if isinstance(info, dict) and info.get("version") and not data.get("packages"):
            out.append(("npm", name, info["version"], 1))
    return out


def collect(root: Path, exclude=()):
    """Return [(file, ecosystem, name, version, line)] for pinned dependencies."""
    found = []
    for p in iter_files(root, exclude):
        if p.name.startswith("requirements") and p.name.endswith(".txt"):
            found += [(p, *d) for d in parse_requirements(p)]
        elif p.name == "package-lock.json":
            found += [(p, *d) for d in parse_package_lock(p)]
    return found


def query_osv(packages, timeout=20):
    """packages: [(ecosystem, name, version)] -> list of vulnerability-id lists, same order."""
    results = []
    for start in range(0, len(packages), 500):
        chunk = packages[start:start + 500]
        body = json.dumps({"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]})
        req = urllib.request.Request(OSV_URL, data=body.encode(), headers={"Content-Type": "application/json",
                                                                          "User-Agent": "repocheckup"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # repocheckup-ignore (fixed https URL)
            data = json.load(resp)
        results += [[v["id"] for v in (r.get("vulns") or [])] for r in data.get("results", [])]
    return results


def check_repo(root: Path, exclude=(), lang="en", query=query_osv):
    deps = collect(root, exclude)
    if not deps:
        return [], None
    try:
        vulns = query(sorted({d[1:4] for d in deps}))
    except Exception as e:  # network errors must not break the scan
        return [], f"OSV lookup failed: {e}"
    by_pkg = dict(zip(sorted({d[1:4] for d in deps}), vulns))
    out = []
    for file, eco, name, ver, line in deps:
        ids = by_pkg.get((eco, name, ver)) or []
        if ids:
            out.append(Finding("DEP001", "deps", "high", pick(TITLE, lang).format(pkg=name, ver=ver, n=len(ids)),
                               str(file), line, ", ".join(ids[:6]), pick(ADVICE, lang).format(id=ids[0]), "CWE-1395"))
    return out, None
