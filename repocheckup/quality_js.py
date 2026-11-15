"""Function metrics for JavaScript and TypeScript, by brace matching (no parser, so approximate)."""
import re

KEYWORDS = {"if", "for", "while", "switch", "catch", "function", "return", "else", "do", "try", "with", "super"}
PATTERNS = (
    re.compile(r"\bfunction\s*\*?\s*([\w$]*)\s*\(([^)]*)\)\s*(?::[^{;=]+)?\{"),
    re.compile(r"([\w$]+)\s*[:=]\s*(?:async\s*)?(?:\(([^)]*)\)|[\w$]+)\s*(?::[^{;=()]+)?=>\s*\{"),
    re.compile(r"^[ \t]*(?:(?:public|private|protected|static|async|override|readonly|get|set)\s+)*"
               r"([\w$]+)\s*\(([^)]*)\)\s*(?::[^{;=]+)?\{", re.M),
)
BRANCH_RE = re.compile(r"\b(?:if|for|while|case|catch)\b|&&|\|\||\?(?![.?:])")


def strip_literals(text):
    """Blank out comments and string contents, keeping length and newlines, so braces can be matched."""
    out, i, n = [], 0, len(text)
    while i < n:
        two = text[i:i + 2]
        if two == "//":
            j = text.find("\n", i)
            j = n if j == -1 else j
        elif two == "/*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
        elif text[i] in "\"'`":
            j = _string_end(text, i)
        else:
            out.append(text[i])
            i += 1
            continue
        out.append("".join(c if c == "\n" else " " for c in text[i:j]))
        i = j
    return "".join(out)


def _string_end(text, start):
    quote, i = text[start], start + 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == quote or (text[i] == "\n" and quote != "`"):
            return i + 1
        i += 1
    return len(text)


def _body_end(clean, open_brace):
    depth = 0
    for i in range(open_brace, len(clean)):
        if clean[i] == "{":
            depth += 1
        elif clean[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(clean) - 1


def _count_params(params):
    depth, count, seen = 0, 0, False
    for ch in params:
        if ch in "{[(<":
            depth += 1
        elif ch in "}])>":
            depth -= 1
        elif ch == "," and depth == 0:
            count += 1
        if not ch.isspace():
            seen = True
    return count + 1 if seen else 0


def functions(text):
    """Yield (name, line, length_in_lines, complexity, param_count) for each function found."""
    clean, seen = strip_literals(text), set()
    for pattern in PATTERNS:
        for m in pattern.finditer(clean):
            name, brace = m.group(1) or "(anonymous)", m.end() - 1
            if name in KEYWORDS or brace in seen:
                continue
            seen.add(brace)
            end = _body_end(clean, brace)
            line = clean.count("\n", 0, m.start(1) if m.group(1) else m.start()) + 1
            length = clean.count("\n", m.start(), end) + 1
            complexity = 1 + len(BRANCH_RE.findall(clean[brace:end]))
            yield name, line, length, complexity, _count_params(m.group(2) or "")
