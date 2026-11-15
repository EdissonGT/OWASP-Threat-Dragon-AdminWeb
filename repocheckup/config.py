"""Project configuration from .repocheckup.json (JSON keeps the tool dependency-free on Python 3.8+)."""
import json
from pathlib import Path

from .model import CATEGORIES, SEVERITY_ORDER

FILENAME = ".repocheckup.json"
LIMIT_KEYS = ("max_function_lines", "max_complexity", "max_params", "max_file_lines")
KNOWN = {"disable", "exclude", "severity", "limits", "checks", "fail_on", "min_score", "lang", "theme"}


class ConfigError(ValueError):
    pass


def find(paths):
    """Look for the config file in the first scanned folder, then in the current folder."""
    candidates = [Path(p) / FILENAME for p in paths if Path(p).is_dir()] + [Path(FILENAME)]
    return next((c for c in candidates if c.is_file()), None)


def _strings(data, key):
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"'{key}' must be a list of strings")
    return value


def load(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ConfigError(f"cannot read {path}: {e}")
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a JSON object")
    unknown = sorted(set(data) - KNOWN)
    if unknown:
        raise ConfigError(f"unknown keys in {path}: {', '.join(unknown)}")
    severity = data.get("severity", {})
    if not isinstance(severity, dict) or any(v not in SEVERITY_ORDER for v in severity.values()):
        raise ConfigError(f"'severity' must map rule ids to one of: {', '.join(SEVERITY_ORDER)}")
    limits = data.get("limits", {})
    if not isinstance(limits, dict) or any(k not in LIMIT_KEYS or not isinstance(v, int) or v < 1
                                           for k, v in limits.items()):
        raise ConfigError(f"'limits' accepts positive integers for: {', '.join(LIMIT_KEYS)}")
    checks = _strings(data, "checks")
    if any(c not in CATEGORIES for c in checks):
        raise ConfigError(f"'checks' accepts: {', '.join(CATEGORIES)}")
    return {"disable": _strings(data, "disable"), "exclude": _strings(data, "exclude"), "severity": severity,
            "limits": limits, "checks": checks, "fail_on": data.get("fail_on"), "min_score": data.get("min_score"),
            "lang": data.get("lang"), "theme": data.get("theme")}


def apply(findings, config):
    """Drop disabled rules (exact id or prefix such as 'QLT') and apply severity overrides."""
    disabled = tuple(config.get("disable", ()))
    overrides = config.get("severity", {})
    kept = []
    for f in findings:
        if disabled and f.rule.startswith(disabled):
            continue
        if f.rule in overrides:
            f.severity = overrides[f.rule]
        kept.append(f)
    kept.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.category, f.file, f.line))
    return kept
