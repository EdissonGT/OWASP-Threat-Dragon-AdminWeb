"""Shared data model."""
from dataclasses import asdict, dataclass

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CATEGORIES = ("security", "quality", "health", "deps")
IGNORE_MARKS = ("repocheckup-ignore", "appsec-ignore")


@dataclass
class Finding:
    rule: str
    category: str
    severity: str
    title: str
    file: str
    line: int
    snippet: str
    advice: str
    cwe: str = ""

    def to_dict(self):
        return asdict(self)


def pick(text, lang):
    """Text may be a (en, es) tuple or a plain string."""
    if isinstance(text, tuple):
        return text[1] if lang == "es" else text[0]
    return text
