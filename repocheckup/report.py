"""Scoring and output formats: text, JSON, SARIF and a self-contained HTML report."""
import html
import json
from datetime import datetime, timezone

from . import __version__
from .model import SEVERITY_ORDER

PENALTY = {"critical": 25, "high": 10, "medium": 4, "low": 1}
LABELS = {
    "en": {"security": "Security", "quality": "Code quality", "health": "Repository health", "deps": "Dependencies",
           "overall": "Overall score", "title": "Repository checkup", "files": "files analyzed", "findings": "findings",
           "none": "No findings. Well done.", "sev": "Severity", "rule": "Rule", "what": "Finding", "where": "Location",
           "fix": "How to fix", "all": "All", "summary": "Summary", "generated": "Generated"},
    "es": {"security": "Seguridad", "quality": "Calidad de código", "health": "Salud del repositorio",
           "deps": "Dependencias", "overall": "Puntaje general", "title": "Chequeo del repositorio",
           "files": "archivos analizados", "findings": "hallazgos", "none": "Sin hallazgos. Buen trabajo.",
           "sev": "Severidad", "rule": "Regla", "what": "Hallazgo", "where": "Ubicación", "fix": "Cómo corregirlo",
           "all": "Todos", "summary": "Resumen", "generated": "Generado"},
}
COLORS = {"critical": "\033[1;35m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}


def grade(score):
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"


def scores(findings, checks):
    per = {c: max(0, 100 - sum(PENALTY[f.severity] for f in findings if f.category == c)) for c in checks}
    overall = round(sum(per.values()) / len(per)) if per else 100
    return per, overall


def to_text(findings, checks, files, lang, color=False):
    L, out = LABELS[lang], []
    for f in findings:
        sev = f"{COLORS[f.severity]}{f.severity.upper()}\033[0m" if color else f.severity.upper()
        cwe = f" ({f.cwe})" if f.cwe else ""
        loc = f"{f.file}:{f.line}"
        out.append(f"[{sev}] {f.rule} {f.title}{cwe}\n  {loc}" + (f"\n  > {f.snippet}" if f.snippet else "")
                   + f"\n  {L['fix']}: {f.advice}\n")
    per, overall = scores(findings, checks)
    out.append(f"{L['summary']}: {files} {L['files']}, {len(findings)} {L['findings']}")
    for c in checks:
        n = sum(1 for f in findings if f.category == c)
        out.append(f"  {L[c]:<24} {per[c]:>3}/100  {grade(per[c])}  ({n})")
    out.append(f"  {L['overall']:<24} {overall:>3}/100  {grade(overall)}")
    return "\n".join(out)


def to_json(findings, checks, files):
    per, overall = scores(findings, checks)
    return json.dumps({"version": __version__, "files": files, "score": overall, "grade": grade(overall),
                       "scores": per, "findings": [f.to_dict() for f in findings]}, indent=2, ensure_ascii=False)


def to_sarif(findings):
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    rules = {}
    for f in findings:
        rules.setdefault(f.rule, {"id": f.rule, "name": f.rule, "shortDescription": {"text": f.title},
                                  "properties": {"category": f.category}})
    return json.dumps({
        "version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "repocheckup", "version": __version__,
                                      "informationUri": "https://github.com/EdissonGT/repocheckup",
                                      "rules": list(rules.values())}},
                  "results": [{"ruleId": f.rule, "level": level[f.severity],
                               "message": {"text": f"{f.title}. {f.advice}"},
                               "locations": [{"physicalLocation": {
                                   "artifactLocation": {"uri": f.file.replace("\\", "/")},
                                   "region": {"startLine": max(1, f.line)}}}]} for f in findings]}]},
        indent=2, ensure_ascii=False)


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1a1d21;--muted:#5d6672;--line:#dfe3e8;--accent:#2f6fed;
--critical:#8e24aa;--high:#d32f2f;--medium:#b26a00;--low:#0277bd;--good:#2e7d32}
@media (prefers-color-scheme:dark){:root{--bg:#14171a;--card:#1d2226;--text:#e6e9ec;--muted:#9aa4af;--line:#2e353c;
--accent:#7aa5ff;--critical:#ce93d8;--high:#ef9a9a;--medium:#ffcc80;--low:#81d4fa;--good:#a5d6a7}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}h1{margin:0 0 4px;font-size:26px}
.muted{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.card b{display:block;font-size:30px}.card.main{border-color:var(--accent)}
.bar{height:6px;border-radius:3px;background:var(--line);margin-top:8px;overflow:hidden}.bar i{display:block;height:100%;background:var(--accent)}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}
button{font:inherit;padding:6px 12px;border-radius:16px;border:1px solid var(--line);background:var(--card);color:var(--text);cursor:pointer}
button.on{background:var(--accent);border-color:var(--accent);color:#fff}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;min-width:720px}th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}tr:last-child td{border-bottom:0}
code{font:12.5px ui-monospace,Menlo,Consolas,monospace;word-break:break-all}.nw code{word-break:normal;white-space:nowrap}
.sev{font-weight:600;text-transform:uppercase;font-size:12px}.critical{color:var(--critical)}.high{color:var(--high)}
.medium{color:var(--medium)}.low{color:var(--low)}.ok{color:var(--good);padding:24px;text-align:center}
"""
JS = """
document.querySelectorAll('button[data-c]').forEach(function(b){b.addEventListener('click',function(){
document.querySelectorAll('button[data-c]').forEach(function(x){x.classList.toggle('on',x===b)});
var c=b.dataset.c;document.querySelectorAll('tbody tr').forEach(function(r){r.hidden=c!=='all'&&r.dataset.c!==c})})});
"""


def to_html(findings, checks, files, lang, target=""):
    L, e = LABELS[lang], html.escape
    per, overall = scores(findings, checks)
    cards = [f'<div class="card main"><span class="muted">{e(L["overall"])}</span><b>{overall} · {grade(overall)}</b>'
             f'<div class="bar"><i style="width:{overall}%"></i></div></div>']
    for c in checks:
        n = sum(1 for f in findings if f.category == c)
        cards.append(f'<div class="card"><span class="muted">{e(L[c])}</span><b>{per[c]} · {grade(per[c])}</b>'
                     f'<span class="muted">{n} {e(L["findings"])}</span><div class="bar"><i style="width:{per[c]}%"></i></div></div>')
    filters = [f'<button class="on" data-c="all">{e(L["all"])} ({len(findings)})</button>'] + [
        f'<button data-c="{c}">{e(L[c])} ({sum(1 for f in findings if f.category == c)})</button>' for c in checks]
    rows = []
    for f in findings:
        cwe = f' <span class="muted">{e(f.cwe)}</span>' if f.cwe else ""
        snippet = f"<br><code>{e(f.snippet)}</code>" if f.snippet else ""
        rows.append(f'<tr data-c="{e(f.category)}"><td class="sev {e(f.severity)}">{e(f.severity)}</td>'
                    f'<td class="nw"><code>{e(f.rule)}</code></td><td>{e(f.title)}{cwe}{snippet}</td>'
                    f'<td><code>{e(f.file)}:{f.line}</code></td><td>{e(f.advice)}</td></tr>')
    table = (f'<div class="wrap"><table><thead><tr><th>{e(L["sev"])}</th><th>{e(L["rule"])}</th><th>{e(L["what"])}</th>'
             f'<th>{e(L["where"])}</th><th>{e(L["fix"])}</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>'
             if rows else f'<div class="card ok">{e(L["none"])}</div>')
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return (f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(L["title"])}</title>'
            f'<style>{CSS}</style></head><body><main><h1>{e(L["title"])}</h1>'
            f'<div class="muted">{e(target)} · {files} {e(L["files"])} · {e(L["generated"])} {when} · repocheckup {__version__}</div>'
            f'<div class="cards">{"".join(cards)}</div><div class="filters">{"".join(filters)}</div>{table}'
            f'</main><script>{JS}</script></body></html>')
