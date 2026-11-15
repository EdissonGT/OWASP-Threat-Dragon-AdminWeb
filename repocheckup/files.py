"""File discovery helpers."""
import os
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "vendor", ".tox", "target",
             ".mypy_cache", ".pytest_cache", "coverage", ".next", ".terraform"}
MAX_BYTES = 1_000_000


def iter_files(root: Path, exclude=()):
    exclude = set(exclude)
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and d not in exclude)
        for name in sorted(filenames):
            yield Path(dirpath) / name


def read_text(path: Path):
    """Return file text, or None for binary/oversized/unreadable files."""
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:2048]:
        return None
    return data.decode("utf-8", errors="ignore")
