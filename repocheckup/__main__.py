"""CLI entry point: python3 -m repocheckup [paths] [options]"""
import argparse
import os
import sys
from pathlib import Path

from . import __version__, report
from .model import CATEGORIES, SEVERITY_ORDER
from .scanner import scan

DEFAULT_CHECKS = "security,quality,health"


def default_lang():
    return "es" if (os.environ.get("LC_ALL") or os.environ.get("LANG") or "").lower().startswith("es") else "en"


def parse_checks(value):
    checks = [c.strip() for c in value.split(",") if c.strip()]
    if checks == ["all"]:
        return list(CATEGORIES)
    bad = [c for c in checks if c not in CATEGORIES]
    if bad or not checks:
        raise argparse.ArgumentTypeError(f"unknown checks: {', '.join(bad) or value!r} (choose from {', '.join(CATEGORIES)}, all)")
    return checks


def build_parser():
    ap = argparse.ArgumentParser(prog="repocheckup",
                                 description="Security, code quality, repository health and dependency checks.")
    ap.add_argument("paths", nargs="*", default=["."], help="files or folders to analyze (default: .)")
    ap.add_argument("--checks", type=parse_checks, default=parse_checks(DEFAULT_CHECKS),
                    help=f"comma-separated: {', '.join(CATEGORIES)} or 'all' (default: {DEFAULT_CHECKS})")
    ap.add_argument("--deps", action="store_true",
                    help="also look up pinned dependencies in OSV.dev (sends package names and versions)")
    ap.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    ap.add_argument("--html", metavar="FILE", help="also write a self-contained HTML report")
    ap.add_argument("--output", metavar="FILE", help="write the main output to a file instead of stdout")
    ap.add_argument("--fail-on", choices=list(SEVERITY_ORDER) + ["never"], default="high",
                    help="exit 1 if a finding of this severity or higher exists (default: high)")
    ap.add_argument("--min-score", type=int, default=0, help="exit 1 if the overall score is below this value")
    ap.add_argument("--exclude", action="append", default=[], help="folder name to exclude (repeatable)")
    ap.add_argument("--lang", choices=["en", "es"], default=default_lang(), help="language of the messages")
    ap.add_argument("--version", action="version", version=__version__)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    checks = list(args.checks)
    if args.deps and "deps" not in checks:
        checks.append("deps")
    missing = [p for p in args.paths if not Path(p).exists()]
    if missing:
        print(f"repocheckup: path not found: {', '.join(missing)}", file=sys.stderr)
        return 2
    findings, warnings, files = scan(args.paths, checks, args.exclude, args.lang)
    for w in warnings:
        print(f"repocheckup: warning: {w}", file=sys.stderr)
    if args.format == "json":
        out = report.to_json(findings, checks, files)
    elif args.format == "sarif":
        out = report.to_sarif(findings)
    else:
        out = report.to_text(findings, checks, files, args.lang, color=sys.stdout.isatty() and not args.output)
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    if args.html:
        Path(args.html).write_text(report.to_html(findings, checks, files, args.lang, ", ".join(args.paths)),
                                   encoding="utf-8")
        print(f"repocheckup: HTML report written to {args.html}", file=sys.stderr)
    _, overall = report.scores(findings, checks)
    threshold = SEVERITY_ORDER.get(args.fail_on, 99)
    failed = any(SEVERITY_ORDER[f.severity] >= threshold for f in findings) or overall < args.min_score
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
