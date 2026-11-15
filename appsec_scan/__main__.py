"""CLI: python3 -m appsec_scan <ruta> [--format text|json|sarif] [--fail-on SEVERIDAD]"""
import argparse
import json
import sys

from . import __version__
from .scanner import SEVERITY_ORDER, scan

COLORS = {"critical": "\033[1;35m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}


def to_sarif(findings):
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "appsec-scan", "version": __version__, "rules": [
                {"id": r, "name": r} for r in sorted({f.rule for f in findings})]}},
            "results": [{
                "ruleId": f.rule, "level": level[f.severity],
                "message": {"text": f"{f.title}. {f.advice}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file},
                                                    "region": {"startLine": f.line}}}],
            } for f in findings],
        }],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(prog="appsec_scan", description="Analizador estático de patrones inseguros.")
    ap.add_argument("paths", nargs="*", default=["."], help="archivos o carpetas a analizar")
    ap.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    ap.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="high",
                    help="código de salida 1 si hay hallazgos de esta severidad o mayor (por defecto: high)")
    ap.add_argument("--exclude", action="append", default=[], help="carpeta a excluir (repetible)")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    findings = scan(args.paths, args.exclude)
    if args.format == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2, ensure_ascii=False))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(findings), indent=2, ensure_ascii=False))
    else:
        color = sys.stdout.isatty()
        for f in findings:
            sev = f"{COLORS[f.severity]}{f.severity.upper()}\033[0m" if color else f.severity.upper()
            print(f"[{sev}] {f.rule} {f.title} ({f.cwe})\n  {f.file}:{f.line}\n  > {f.snippet}\n  Sugerencia: {f.advice}\n")
        counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
        print("Resumen: " + ", ".join(f"{n} {s}" for s, n in sorted(counts.items(), key=lambda x: -SEVERITY_ORDER[x[0]])))
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
