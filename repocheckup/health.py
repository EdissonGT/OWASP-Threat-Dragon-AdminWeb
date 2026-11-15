"""Repository health checks: documentation, tests, CI, hygiene and dependency pinning."""
import re
from pathlib import Path

from .files import iter_files
from .model import Finding, pick

T = {
    "HLT001": (("No README", "Falta el README"), "high",
               ("Add a README that explains what the project does and how to run it.",
                "Agrega un README que explique qué hace el proyecto y cómo ejecutarlo.")),
    "HLT002": (("No license file", "Falta el archivo de licencia"), "medium",
               ("Add a LICENSE so others know how they may use the code.",
                "Agrega un LICENSE para que otros sepan cómo pueden usar el código.")),
    "HLT003": (("No automated tests found", "No se encontraron pruebas automáticas"), "high",
               ("Add tests; start with the most critical paths.", "Agrega pruebas; empieza por los flujos más críticos.")),
    "HLT004": (("No CI configuration", "Falta configuración de CI"), "medium",
               ("Run tests and checks automatically on every push.",
                "Ejecuta pruebas y revisiones automáticamente en cada push.")),
    "HLT005": (("No .gitignore", "Falta .gitignore"), "low",
               ("Add a .gitignore to keep build output and secrets out of git.",
                "Agrega un .gitignore para dejar fuera de git los artefactos y secretos.")),
    "HLT006": (("Dependency manifest without lockfile", "Manifiesto de dependencias sin lockfile"), "medium",
               ("Commit the lockfile so builds are reproducible.", "Versiona el lockfile para tener builds reproducibles.")),
    "HLT007": (("Unpinned dependencies ({n})", "Dependencias sin versión fija ({n})"), "low",
               ("Pin exact versions (==) or use a lockfile.", "Fija versiones exactas (==) o usa un lockfile.")),
    "HLT008": (("No security policy (SECURITY.md)", "Falta política de seguridad (SECURITY.md)"), "low",
               ("Tell people how to report vulnerabilities privately.",
                "Indica cómo reportar vulnerabilidades de forma privada.")),
    "HLT009": (("No contributing guide", "Falta guía de contribución"), "low",
               ("Add CONTRIBUTING.md to help newcomers.", "Agrega CONTRIBUTING.md para ayudar a quienes llegan.")),
    "HLT010": (("Environment file committed", "Archivo de entorno versionado"), "high",
               ("Remove it from git, rotate any secret in it and add it to .gitignore.",
                "Quítalo de git, rota los secretos que contenga y agrégalo a .gitignore.")),
    "HLT011": (("Large file in repository ({n} MB)", "Archivo grande en el repositorio ({n} MB)"), "low",
               ("Use Git LFS or external storage for large binaries.",
                "Usa Git LFS o almacenamiento externo para binarios grandes.")),
    "HLT012": (("No automated dependency updates", "Sin actualización automática de dependencias"), "low",
               ("Enable Dependabot or Renovate.", "Activa Dependabot o Renovate.")),
    "HLT013": (("README is very short", "El README es muy corto"), "low",
               ("Document installation, usage and how to contribute.", "Documenta instalación, uso y cómo contribuir.")),
}
CI_PATHS = (".github/workflows", ".gitlab-ci.yml", "azure-pipelines.yml", "Jenkinsfile", ".circleci",
            "bitbucket-pipelines.yml", ".travis.yml")
TEST_RE = re.compile(r"(?:^test_.*\.py$|_test\.(?:py|go)$|\.(?:test|spec)\.[jt]sx?$|Tests?\.(?:java|cs|kt)$)")
TEST_DIRS = {"tests", "test", "__tests__", "spec"}
LOCKS = {"package.json": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"),
         "Pipfile": ("Pipfile.lock",), "composer.json": ("composer.lock",), "Gemfile": ("Gemfile.lock",),
         "go.mod": ("go.sum",), "Cargo.toml": ("Cargo.lock",)}
UPDATERS = (".github/dependabot.yml", ".github/dependabot.yaml", "renovate.json", ".renovaterc",
            ".renovaterc.json", ".github/renovate.json")
REQ_LINE = re.compile(r"^[A-Za-z0-9][\w.\-\[\]]*\s*(.*)$")


def _f(rule, file, lang, n="", line=1, snippet=""):
    title, sev, advice = T[rule]
    return Finding(rule, "health", sev, pick(title, lang).format(n=n), str(file), line, snippet, pick(advice, lang))


def _find(root, *names):
    low = {p.name.lower(): p for p in root.iterdir()}
    for n in names:
        for key, p in low.items():
            if key == n or key.startswith(n + "."):
                return p
    return None


def _unpinned(path):
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return 0
    count = 0
    for raw in lines:
        line = raw.split("#")[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = REQ_LINE.match(line)
        if m and "==" not in m.group(1) and "@" not in m.group(1):
            count += 1
    return count


def _root_checks(root, lang):
    out = []
    readme = _find(root, "readme")
    if not readme:
        out.append(_f("HLT001", root, lang))
    elif readme.stat().st_size < 300:
        out.append(_f("HLT013", readme, lang))
    present = {
        "HLT002": _find(root, "license", "licence", "copying"),
        "HLT005": (root / ".gitignore").exists(),
        "HLT004": any((root / p).exists() for p in CI_PATHS),
        "HLT008": _find(root, "security") or (root / ".github" / "SECURITY.md").exists(),
        "HLT009": _find(root, "contributing") or (root / ".github" / "CONTRIBUTING.md").exists(),
    }
    return out + [_f(rule, root, lang) for rule, ok in present.items() if not ok]


def _is_env_file(name):
    return name == ".env" or (name.startswith(".env.") and not name.endswith((".example", ".sample", ".template")))


def _file_checks(p, lang):
    """Return (findings, is_manifest) for one file."""
    out, name, manifest = [], p.name, False
    if _is_env_file(name):
        out.append(_f("HLT010", p, lang))
    if name in LOCKS:
        manifest = True
        if not any((p.parent / lock).exists() for lock in LOCKS[name]):
            out.append(_f("HLT006", p, lang))
    elif name.startswith("requirements") and name.endswith(".txt"):
        manifest = True
        n = _unpinned(p)
        if n:
            out.append(_f("HLT007", p, lang, n))
    elif name == "pyproject.toml":
        manifest = True
    try:
        mb = p.stat().st_size / 1_048_576
    except OSError:
        mb = 0
    if mb > 5:
        out.append(_f("HLT011", p, lang, round(mb, 1)))
    return out, manifest


def check_repo(root: Path, exclude=(), lang="en"):
    if not root.is_dir():
        return []
    out = _root_checks(root, lang)
    has_tests = has_manifest = False
    for p in iter_files(root, exclude):
        if TEST_RE.search(p.name) or TEST_DIRS & set(p.relative_to(root).parts[:-1]):
            has_tests = True
        found, manifest = _file_checks(p, lang)
        out += found
        has_manifest = has_manifest or manifest
    if not has_tests:
        out.append(_f("HLT003", root, lang))
    if has_manifest and not any((root / p).exists() for p in UPDATERS):
        out.append(_f("HLT012", root, lang))
    return out
