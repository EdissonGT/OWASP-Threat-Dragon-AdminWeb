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
           "fix": "How to fix", "all": "All", "summary": "Summary", "generated": "Generated",
           "ai": "AI recommendations", "priorities": "What to fix first", "quick": "Quick wins",
           "fixes": "Suggested fixes", "fp": "Likely false positive", "effort": "effort", "why": "Why"},
    "es": {"security": "Seguridad", "quality": "Calidad de código", "health": "Salud del repositorio",
           "deps": "Dependencias", "overall": "Puntaje general", "title": "Chequeo del repositorio",
           "files": "archivos analizados", "findings": "hallazgos", "none": "Sin hallazgos. Buen trabajo.",
           "sev": "Severidad", "rule": "Regla", "what": "Hallazgo", "where": "Ubicación", "fix": "Cómo corregirlo",
           "all": "Todos", "summary": "Resumen", "generated": "Generado",
           "ai": "Recomendaciones de IA", "priorities": "Qué corregir primero", "quick": "Mejoras rápidas",
           "fixes": "Correcciones sugeridas", "fp": "Probable falso positivo", "effort": "esfuerzo",
           "why": "Por qué"},
}
COLORS = {"critical": "\033[1;35m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m"}


def grade(score):
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"


def scores(findings, checks):
    per = {c: max(0, 100 - sum(PENALTY[f.severity] for f in findings if f.category == c)) for c in checks}
    overall = round(sum(per.values()) / len(per)) if per else 100
    return per, overall


BANNER = {"en": "Wake up... the repo has you. Follow the findings.",
          "es": "Despierta... el repo te tiene. Sigue los hallazgos."}
GREEN, RESET = "\033[1;32m", "\033[0m"


def to_text(findings, checks, files, lang, color=False, theme="matrix"):
    L, out = LABELS[lang], []
    matrix = color and theme == "matrix"
    if matrix:
        out.append(f"{GREEN}> repocheckup_  {BANNER[lang]}{RESET}\n")
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
    last = f"  {L['overall']:<24} {overall:>3}/100  {grade(overall)}"
    out.append(f"{GREEN}{last}{RESET}" if matrix else last)
    return "\n".join(out)


def ai_to_text(advice, lang):
    L, out = LABELS[lang], [f"\n=== {LABELS[lang]['ai']} ===", advice["summary"], f"\n{LABELS[lang]['priorities']}:"]
    for i, p in enumerate(advice["priorities"], 1):
        out.append(f"{i}. {p['title']} [{L['effort']}: {p['effort']}] ({', '.join(p['rules'])})")
        out.append(f"   {L['why']}: {p['why']}")
        out += [f"   - {step}" for step in p["steps"]]
    if advice["quick_wins"]:
        out.append(f"\n{L['quick']}:")
        out += [f"- {q}" for q in advice["quick_wins"]]
    if advice["fixes"]:
        out.append(f"\n{L['fixes']}:")
    for f in advice["fixes"]:
        flag = f" [{L['fp']}]" if f["false_positive"] else ""
        out.append(f"* {f['rule']} {f['file']}:{f['line']}{flag}\n  {f['explanation']}")
        if f["fixed_code"]:
            out.append("\n".join("    " + line for line in f["fixed_code"].splitlines()))
    return "\n".join(out)


def to_json(findings, checks, files, advice=None):
    per, overall = scores(findings, checks)
    data = {"version": __version__, "files": files, "score": overall, "grade": grade(overall),
            "scores": per, "findings": [f.to_dict() for f in findings]}
    if advice is not None:
        data["ai"] = advice
    return json.dumps(data, indent=2, ensure_ascii=False)


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
.ai{margin:20px 0;border-color:var(--accent)}.ai b{display:inline;font-size:inherit}.ai h2{margin:0 0 8px;font-size:19px}.ai h3{margin:18px 0 6px;font-size:15px}
.ai ol,.ai ul{margin:4px 0;padding-left:22px}.ai li{margin:6px 0}.ai pre{margin:6px 0;padding:10px;border-radius:8px;
background:var(--bg);border:1px solid var(--line);overflow-x:auto;font:12.5px ui-monospace,Menlo,Consolas,monospace}
.tag{display:inline-block;font-size:12px;padding:1px 8px;border-radius:10px;border:1px solid var(--line);color:var(--muted)}
"""
MATRIX_CSS = """
:root{--bg:#000;--card:rgba(0,14,2,.88);--text:#00ff41;--muted:#00b32d;--line:#00501a;--accent:#00ff41;
--critical:#ff5cf4;--high:#ff5c5c;--medium:#ffd75c;--low:#5cd6ff;--good:#00ff41}
body{font-family:ui-monospace,Menlo,Consolas,"Courier New",monospace;font-size:14px}
#rain{position:fixed;inset:0;width:100%;height:100%;z-index:0;opacity:.22;pointer-events:none}
main{position:relative;z-index:1}
h1{text-transform:lowercase;letter-spacing:.06em;text-shadow:0 0 8px #00ff41}h1::before{content:"> "}
h1::after{content:"_";animation:blink 1s steps(1) infinite}@keyframes blink{50%{opacity:0}}
.card,.wrap,button{border-radius:2px}.card.main,.ai{box-shadow:0 0 14px rgba(0,255,65,.35)}
.card b{text-shadow:0 0 6px rgba(0,255,65,.7)}.ai b{text-shadow:none}.bar,.bar i{border-radius:0}
button{font-family:inherit}button.on{color:#000;font-weight:700}
th{color:var(--accent)}.ai pre{background:#000}
@media (prefers-reduced-motion:reduce){#rain{display:none}h1::after{animation:none}}
"""
RAIN_JS = """
(function(){if(matchMedia('(prefers-reduced-motion: reduce)').matches)return;
var c=document.getElementById('rain');if(!c)return;var x=c.getContext('2d'),s=16,d=[];
var g='\\u30a2\\u30a4\\u30a6\\u30a8\\u30aa\\u30ab\\u30ad\\u30af\\u30b1\\u30b3\\u30b5\\u30b7\\u30b9\\u30bb\\u30bd0123456789ABCDEF<>/{}';
function fit(){c.width=innerWidth;c.height=innerHeight;d=[];for(var i=0;i<c.width/s;i++)d.push(Math.random()*-50)}
function draw(){x.fillStyle='rgba(0,0,0,.08)';x.fillRect(0,0,c.width,c.height);x.fillStyle='#00ff41';x.font=s+'px monospace';
for(var i=0;i<d.length;i++){x.fillText(g.charAt(Math.floor(Math.random()*g.length)),i*s,d[i]*s);
if(d[i]*s>c.height&&Math.random()>.975)d[i]=0;d[i]++}}
fit();addEventListener('resize',fit);setInterval(draw,60)})();
"""
THEMES = ("matrix", "classic")
JS = """
document.querySelectorAll('button[data-c]').forEach(function(b){b.addEventListener('click',function(){
document.querySelectorAll('button[data-c]').forEach(function(x){x.classList.toggle('on',x===b)});
var c=b.dataset.c;document.querySelectorAll('tbody tr').forEach(function(r){r.hidden=c!=='all'&&r.dataset.c!==c})})});
"""


def ai_to_html(advice, lang):
    L, e = LABELS[lang], html.escape
    parts = [f'<div class="card ai"><h2>{e(L["ai"])}</h2><p>{e(advice["summary"])}</p><h3>{e(L["priorities"])}</h3><ol>']
    for p in advice["priorities"]:
        steps = "".join(f"<li>{e(s)}</li>" for s in p["steps"])
        parts.append(f'<li><b>{e(p["title"])}</b> <span class="tag">{e(L["effort"])}: {e(p["effort"])}</span> '
                     f'<span class="muted">{e(", ".join(p["rules"]))}</span><br>{e(p["why"])}<ul>{steps}</ul></li>')
    parts.append("</ol>")
    if advice["quick_wins"]:
        parts.append(f'<h3>{e(L["quick"])}</h3><ul>' + "".join(f"<li>{e(q)}</li>" for q in advice["quick_wins"]) + "</ul>")
    if advice["fixes"]:
        parts.append(f'<h3>{e(L["fixes"])}</h3>')
    for f in advice["fixes"]:
        flag = f' <span class="tag">{e(L["fp"])}</span>' if f["false_positive"] else ""
        code = f'<pre>{e(f["fixed_code"])}</pre>' if f["fixed_code"] else ""
        parts.append(f'<p><code>{e(f["rule"])}</code> <code>{e(f["file"])}:{int(f["line"])}</code>{flag}<br>'
                     f'{e(f["explanation"])}</p>{code}')
    return "".join(parts) + "</div>"


def to_html(findings, checks, files, lang, target="", advice=None, theme="matrix"):
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
    matrix = theme == "matrix"
    rain = '<canvas id="rain" aria-hidden="true"></canvas>' if matrix else ""
    return (f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(L["title"])}</title>'
            f'<style>{CSS}{MATRIX_CSS if matrix else ""}</style></head><body>{rain}<main><h1>{e(L["title"])}</h1>'
            f'<div class="muted">{e(target)} · {files} {e(L["files"])} · {e(L["generated"])} {when} · repocheckup {__version__}</div>'
            f'<div class="cards">{"".join(cards)}</div>{ai_to_html(advice, lang) if advice else ""}<div class="filters">{"".join(filters)}</div>{table}'
            f'</main><script>{JS}{RAIN_JS if matrix else ""}</script></body></html>')
