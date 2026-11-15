"""Shareable outputs: an SVG score badge and a Markdown summary for pull requests and CI job summaries."""
from .report import LABELS, grade, scores

MARKER = "<!-- repocheckup -->"
GRADE_COLORS = {"A": "#2e9e44", "B": "#7cb518", "C": "#d4a017", "D": "#e07b1a", "F": "#d32f2f"}
EMOJI = {"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🔵"}


def badge_svg(overall):
    """A flat two-part badge: 'repocheckup | 92/100 A'."""
    g = grade(overall)
    left, right = "repocheckup", f"{overall}/100 {g}"
    lw, rw = len(left) * 7 + 12, len(right) * 7 + 12
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{lw + rw}" height="20" role="img" '
            f'aria-label="{left}: {right}"><title>{left}: {right}</title>'
            f'<rect width="{lw}" height="20" fill="#333"/><rect x="{lw}" width="{rw}" height="20" fill="{GRADE_COLORS[g]}"/>'
            f'<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
            f'<text x="{lw / 2}" y="14">{left}</text><text x="{lw + rw / 2}" y="14">{right}</text></g></svg>\n')


def _cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;")


def _delta(history, lang):
    if not history or len(history) < 2:
        return ""
    change = history[-1]["score"] - history[-2]["score"]
    word = {"en": "vs previous run", "es": "respecto a la ejecución anterior"}[lang]
    return f" ({change:+d} {word})" if change else ""


def to_markdown(findings, checks, lang, advice=None, history=None, hidden=0, limit=15):
    L = LABELS[lang]
    per, overall = scores(findings, checks)
    out = [MARKER, f"## repocheckup: {overall}/100 · {grade(overall)}{_delta(history, lang)}", "",
           f"| {L['summary']} | | | {L['findings']} |", "|---|---:|:---:|---:|"]
    for c in checks:
        n = sum(1 for f in findings if f.category == c)
        out.append(f"| {L[c]} | {per[c]}/100 | {grade(per[c])} | {n} |")
    if hidden:
        out += ["", {"en": f"{hidden} known findings hidden by the baseline.",
                     "es": f"{hidden} hallazgos conocidos ocultos por la línea base."}[lang]]
    if advice:
        out += ["", f"### {L['ai']}", "", _cell(advice["summary"]), ""]
        out += [f"{i}. **{_cell(p['title'])}**: {_cell(p['why'])}" for i, p in enumerate(advice["priorities"], 1)]
    if findings:
        out += ["", f"### {L['findings']}", "", f"| {L['sev']} | {L['rule']} | {L['what']} | {L['where']} |",
                "|---|---|---|---|"]
        out += [f"| {EMOJI[f.severity]} {f.severity} | `{f.rule}` | {_cell(f.title)} | `{_cell(f.file)}:{f.line}` |"
                for f in findings[:limit]]
        if len(findings) > limit:
            out.append({"en": f"\n…and {len(findings) - limit} more.",
                        "es": f"\n…y {len(findings) - limit} más."}[lang])
    else:
        out += ["", L["none"]]
    return "\n".join(out) + "\n"
