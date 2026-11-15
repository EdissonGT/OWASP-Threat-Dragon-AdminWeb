"""Code quality checks: size, complexity, error handling, leftovers and duplication."""
import ast
import hashlib
import re
from pathlib import Path

from . import quality_js
from .model import IGNORE_MARKS, Finding, pick

CODE_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".go", ".php", ".rb", ".cs"}
DUP_WINDOW = 10
JS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
DEFAULT_LIMITS = {"max_function_lines": 80, "max_complexity": 15, "max_params": 7, "max_file_lines": 1000}
LIMITS = dict(DEFAULT_LIMITS)


def set_limits(overrides=None):
    """Reset the thresholds to the defaults, then apply the given overrides (from the config file)."""
    LIMITS.clear()
    LIMITS.update(DEFAULT_LIMITS)
    LIMITS.update(overrides or {})

T = {
    "QLT001": (("Function too long ({n} lines)", "Función demasiado larga ({n} líneas)"), "medium",
               ("Split it into smaller functions with one responsibility each.",
                "Divídela en funciones más pequeñas con una sola responsabilidad.")),
    "QLT002": (("High cyclomatic complexity ({n})", "Complejidad ciclomática alta ({n})"), "medium",
               ("Simplify branching: early returns, lookup tables, helper functions.",
                "Simplifica las ramas: retornos tempranos, tablas de búsqueda, funciones auxiliares.")),
    "QLT003": (("Too many parameters ({n})", "Demasiados parámetros ({n})"), "low",
               ("Group related parameters into an object or dataclass.",
                "Agrupa los parámetros relacionados en un objeto o dataclass.")),
    "QLT004": (("File too long ({n} lines)", "Archivo demasiado largo ({n} líneas)"), "low",
               ("Split the file into cohesive modules.", "Divide el archivo en módulos cohesivos.")),
    "QLT005": (("Empty or silenced error handler", "Manejo de errores vacío o silenciado"), "medium",
               ("Handle the error, log it or let it propagate.", "Maneja el error, regístralo o deja que se propague.")),
    "QLT006": (("Pending TODO/FIXME/HACK note", "Nota TODO/FIXME/HACK pendiente"), "low",
               ("Resolve it or track it in an issue.", "Resuélvela o regístrala en un issue.")),
    "QLT007": (("Duplicated code block (also at {n})", "Bloque de código duplicado (también en {n})"), "low",
               ("Extract the shared logic into one function.", "Extrae la lógica común a una función.")),
    "QLT008": (("Syntax error: file cannot be parsed", "Error de sintaxis: el archivo no se puede analizar"), "high",
               ("Fix the syntax error.", "Corrige el error de sintaxis.")),
    "QLT009": (("Mutable default argument", "Argumento por defecto mutable"), "medium",
               ("Use None as default and create the object inside the function.",
                "Usa None por defecto y crea el objeto dentro de la función.")),
}
TODO_RE = re.compile(r"(?:#|//|/\*|\*|<!--)\s*(?:TODO|FIXME|HACK|XXX)\b", re.I)
EMPTY_CATCH_RE = re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}")
BRANCHES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.With, ast.AsyncWith,
            ast.BoolOp, ast.IfExp, ast.comprehension, ast.Assert)


def _f(rule, path, line, snippet, lang, n=""):
    title, sev, advice = T[rule]
    return Finding(rule, "quality", sev, pick(title, lang).format(n=n), str(path), line, snippet[:120], pick(advice, lang))


def _function(node, path, lines, lang):
    out, head = [], lines[node.lineno - 1].strip()
    length = (node.end_lineno or node.lineno) - node.lineno + 1
    if length > LIMITS["max_function_lines"]:
        out.append(_f("QLT001", path, node.lineno, head, lang, length))
    complexity = 1 + sum(isinstance(n, BRANCHES) for n in ast.walk(node))
    if complexity > LIMITS["max_complexity"]:
        out.append(_f("QLT002", path, node.lineno, head, lang, complexity))
    a = node.args
    params = [p for p in a.posonlyargs + a.args + a.kwonlyargs if p.arg not in ("self", "cls")]
    if len(params) > LIMITS["max_params"]:
        out.append(_f("QLT003", path, node.lineno, head, lang, len(params)))
    if any(isinstance(d, (ast.List, ast.Dict, ast.Set)) for d in a.defaults + a.kw_defaults if d):
        out.append(_f("QLT009", path, node.lineno, head, lang))
    return out


def _silenced(node):
    only_pass = len(node.body) == 1 and isinstance(node.body[0], (ast.Pass, ast.Continue))
    broad = node.type is None or (isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"))
    return only_pass and broad


def _python(path, text, lines, lang):
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError) as e:
        return [_f("QLT008", path, getattr(e, "lineno", 1) or 1, str(e), lang)]
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out += _function(node, path, lines, lang)
        elif isinstance(node, ast.ExceptHandler) and _silenced(node):
            out.append(_f("QLT005", path, node.lineno, lines[node.lineno - 1].strip(), lang))
    return out


def _javascript(path, text, lines, lang):
    out = []
    for name, line, length, complexity, params in quality_js.functions(text):
        head = lines[line - 1].strip() if line <= len(lines) else name
        if length > LIMITS["max_function_lines"]:
            out.append(_f("QLT001", path, line, head, lang, length))
        if complexity > LIMITS["max_complexity"]:
            out.append(_f("QLT002", path, line, head, lang, complexity))
        if params > LIMITS["max_params"]:
            out.append(_f("QLT003", path, line, head, lang, params))
    return out


def check_file(path: Path, text: str, lang="en"):
    ext = path.suffix.lower()
    if ext not in CODE_EXTS:
        return []
    lines = text.splitlines()
    out = _python(path, text, lines, lang) if ext == ".py" else []
    if ext in JS_EXTS:
        out += _javascript(path, text, lines, lang)
    if len(lines) > LIMITS["max_file_lines"]:
        out.append(_f("QLT004", path, 1, lines[0] if lines else "", lang, len(lines)))
    for i, line in enumerate(lines, 1):
        if any(m in line for m in IGNORE_MARKS):
            continue
        if TODO_RE.search(line):
            out.append(_f("QLT006", path, i, line.strip(), lang))
    if ext != ".py":
        for m in EMPTY_CATCH_RE.finditer(text):
            n = text.count("\n", 0, m.start()) + 1
            out.append(_f("QLT005", path, n, lines[n - 1].strip(), lang))
    return out


def find_duplicates(sources, lang="en"):
    """sources: list of (path, text). Reports blocks of DUP_WINDOW identical significant lines."""
    seen, out = {}, []
    for path, text in sources:
        if path.suffix.lower() not in CODE_EXTS:
            continue
        sig = [(i, l.strip()) for i, l in enumerate(text.splitlines(), 1)
               if len(l.strip()) > 3 and not l.strip().startswith(("import ", "from ", "#", "//", "*", "/*"))]
        last = -DUP_WINDOW
        for k in range(len(sig) - DUP_WINDOW + 1):
            window = sig[k:k + DUP_WINDOW]
            if sum(len(s) for _, s in window) < 200:
                continue
            h = hashlib.sha1("\n".join(s for _, s in window).encode()).hexdigest()  # repocheckup-ignore (not security)
            first = seen.setdefault(h, (path, window[0][0]))
            if first != (path, window[0][0]) and k - last >= DUP_WINDOW and (first[0] != path or window[0][0] - first[1] >= DUP_WINDOW):
                out.append(_f("QLT007", path, window[0][0], window[0][1], lang, f"{first[0]}:{first[1]}"))
                last = k
    return out
