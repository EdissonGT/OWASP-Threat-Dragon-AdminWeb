"""CLI entry point: python3 -m repocheckup [paths] [options]"""
import argparse
import os
import sys
from pathlib import Path

from . import __version__, ai, config, fixer, quality, report, share, tracking
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


def _scan_options(ap):
    ap.add_argument("paths", nargs="*", default=["."], help="files or folders to analyze (default: .)")
    ap.add_argument("--checks", type=parse_checks,
                    help=f"comma-separated: {', '.join(CATEGORIES)} or 'all' (default: {DEFAULT_CHECKS})")
    ap.add_argument("--deps", action="store_true",
                    help="also look up pinned dependencies in OSV.dev (sends package names and versions)")
    ap.add_argument("--exclude", action="append", default=[], help="folder name to exclude (repeatable)")
    ap.add_argument("--config", metavar="FILE", help=f"configuration file (default: {config.FILENAME} if present)")
    ap.add_argument("--no-config", action="store_true", help="ignore any configuration file")
    ap.add_argument("--diff", metavar="REF", help="only report findings on lines changed since this git ref")
    ap.add_argument("--baseline", metavar="FILE", help="hide the findings recorded in this baseline file")
    ap.add_argument("--write-baseline", metavar="FILE", help="record the current findings as the baseline and exit")


def _output_options(ap):
    ap.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    ap.add_argument("--output", metavar="FILE", help="write the main output to a file instead of stdout")
    ap.add_argument("--html", metavar="FILE", help="also write a self-contained HTML report")
    ap.add_argument("--markdown", metavar="FILE", help="also write a Markdown summary (for pull request comments)")
    ap.add_argument("--badge", metavar="FILE", help="also write an SVG badge with the score")
    ap.add_argument("--history", metavar="FILE", help="append this run to a score history file and show the trend")
    ap.add_argument("--fail-on", choices=list(SEVERITY_ORDER) + ["never"],
                    help="exit 1 if a finding of this severity or higher exists (default: high)")
    ap.add_argument("--min-score", type=int, help="exit 1 if the overall score is below this value")
    ap.add_argument("--lang", choices=["en", "es"], help="language of the messages")
    ap.add_argument("--theme", choices=report.THEMES,
                    help="look of the HTML report and terminal banner (default: matrix)")


def _ai_options(ap):
    ap.add_argument("--ai", action="store_true",
                    help="ask Claude for a prioritized plan and concrete fixes (sends findings and nearby code "
                         "to the Anthropic API; needs repocheckup[ai] and ANTHROPIC_API_KEY)")
    ap.add_argument("--ai-model", default=os.environ.get("REPOCHECKUP_AI_MODEL", ai.DEFAULT_MODEL),
                    help=f"model for --ai (default: {ai.DEFAULT_MODEL})")
    ap.add_argument("--ai-effort", choices=["low", "medium", "high", "xhigh", "max"], default="medium",
                    help="how hard the model thinks; higher costs more (default: medium)")
    ap.add_argument("--ai-max-findings", type=int, default=40,
                    help="how many findings, most severe first, are sent to the model (default: 40)")
    ap.add_argument("--fix", action="store_true",
                    help="experimental: apply the AI's code fixes after showing each diff (implies --ai)")
    ap.add_argument("--yes", action="store_true", help="with --fix, apply every fix without asking")


def build_parser():
    ap = argparse.ArgumentParser(prog="repocheckup",
                                 description="Security, code quality, repository health and dependency checks.")
    _scan_options(ap)
    _output_options(ap)
    _ai_options(ap)
    ap.add_argument("--version", action="version", version=__version__)
    return ap


def note(message):
    print(f"repocheckup: {message}", file=sys.stderr)


def resolve_settings(args):
    """Merge the config file under the command line: flags win, then the file, then the defaults."""
    path = None if args.no_config else (args.config or config.find(args.paths))
    cfg = config.load(path) if path else {}
    args.checks = args.checks or cfg.get("checks") or parse_checks(DEFAULT_CHECKS)
    if args.deps and "deps" not in args.checks:
        args.checks = list(args.checks) + ["deps"]
    args.fail_on = args.fail_on or cfg.get("fail_on") or "high"
    args.min_score = args.min_score if args.min_score is not None else (cfg.get("min_score") or 0)
    args.lang = args.lang or cfg.get("lang") or default_lang()
    args.theme = args.theme or cfg.get("theme") or "matrix"
    args.exclude = list(args.exclude) + list(cfg.get("exclude", []))
    args.ai = args.ai or args.fix
    if args.fail_on not in list(SEVERITY_ORDER) + ["never"] or args.lang not in ("en", "es") \
            or args.theme not in report.THEMES:
        raise config.ConfigError(f"invalid fail_on, lang or theme in {path}")
    quality.set_limits(cfg.get("limits"))
    return cfg


def collect(args, cfg):
    """Scan, then narrow the findings: config, diff mode, baseline. Returns (findings, files, hidden)."""
    findings, warnings, files = scan(args.paths, args.checks, args.exclude, args.lang)
    for w in warnings:
        note(f"warning: {w}")
    findings = config.apply(findings, cfg)
    if args.diff:
        findings = tracking.apply_diff(findings, tracking.changed_lines(args.diff))
    hidden = 0
    if args.baseline:
        findings, hidden = tracking.apply_baseline(findings, args.baseline)
        note(f"{hidden} known findings hidden by the baseline")
    return findings, files, hidden


def _advice(args, findings):
    if not args.ai:
        return None
    advice, notes = ai.advise(findings, args.checks, args.lang, args.ai_model, args.ai_effort, args.ai_max_findings)
    for n in notes:
        note(n)
    return advice


def _approve(args):
    def ask(edit):
        print(fixer.diff(edit) + "\n")
        if args.yes:
            return True
        return input(f"Apply this fix to {edit.path}? [y/N] ").strip().lower() in ("y", "yes", "s", "si", "sí")
    return ask


def apply_fixes(args, advice):
    if not (args.fix and advice):
        return
    edits, skipped = fixer.plan(advice, args.paths)
    for fix, reason in skipped:
        note(f"fix for {fix.get('rule')} at {fix.get('file')}:{fix.get('line')} skipped: {reason}")
    if not edits:
        return note("no fixes could be applied automatically")
    if not args.yes and not sys.stdin.isatty():
        for e in edits:
            print(fixer.diff(e) + "\n")
        return note(f"{len(edits)} fixes shown but not applied (no terminal to confirm; pass --yes to apply)")
    done = fixer.apply(edits, _approve(args))
    note(f"{done} of {len(edits)} fixes applied; review the changes and run your tests")


def _main_output(args, findings, files, advice, history):
    if args.format == "json":
        return report.to_json(findings, args.checks, files, advice)
    if args.format == "sarif":
        return report.to_sarif(findings)
    color = sys.stdout.isatty() and not args.output
    out = report.to_text(findings, args.checks, files, args.lang, color, args.theme)
    if history and len(history) > 1:
        out += f"\n  {report.trend_text(history, args.lang)}"
    return out + "\n" + report.ai_to_text(advice, args.lang) if advice else out


def write_outputs(args, findings, files, advice, history, hidden):
    out = _main_output(args, findings, files, advice, history)
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    _, overall = report.scores(findings, args.checks)
    extras = {
        args.html: lambda: report.to_html(findings, args.checks, files, args.lang, target=", ".join(args.paths),
                                          advice=advice, theme=args.theme, history=history),
        args.markdown: lambda: share.to_markdown(findings, args.checks, args.lang, advice, history, hidden),
        args.badge: lambda: share.badge_svg(overall),
    }
    for path, render in extras.items():
        if path:
            Path(path).write_text(render(), encoding="utf-8")
            note(f"wrote {path}")


def run(args):
    cfg = resolve_settings(args)
    findings, files, hidden = collect(args, cfg)
    if args.write_baseline:
        note(f"baseline with {tracking.write_baseline(findings, args.write_baseline)} findings written to "
             f"{args.write_baseline}")
        return 0
    per, overall = report.scores(findings, args.checks)
    history = tracking.record_history(args.history, overall, per, len(findings)) if args.history else None
    advice = _advice(args, findings)
    write_outputs(args, findings, files, advice, history, hidden)
    apply_fixes(args, advice)
    threshold = SEVERITY_ORDER.get(args.fail_on, 99)
    failed = any(SEVERITY_ORDER[f.severity] >= threshold for f in findings) or overall < args.min_score
    return 1 if failed else 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    missing = [p for p in args.paths if not Path(p).exists()]
    if missing:
        note(f"path not found: {', '.join(missing)}")
        return 2
    try:
        return run(args)
    except (config.ConfigError, tracking.TrackingError) as e:
        note(str(e))
        return 2


if __name__ == "__main__":
    sys.exit(main())
