"""Reglas de detección. Cada regla: id, título, severidad, regex, extensiones, consejo."""
import re
from dataclasses import dataclass, field

ANY = ()  # todas las extensiones
PY = (".py",)
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
JAVA = (".java", ".kt")
PHP = (".php",)
WEB = JS + (".html", ".vue")
CODE = PY + JS + JAVA + PHP + (".go", ".rb", ".cs")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str  # critical | high | medium | low
    pattern: re.Pattern
    exts: tuple = ANY
    advice: str = ""
    cwe: str = ""
    names: tuple = field(default_factory=tuple)  # nombres de archivo exactos (p. ej. Dockerfile)


def r(id, title, sev, rx, exts=ANY, advice="", cwe="", names=()):
    return Rule(id, title, sev, re.compile(rx, re.I), exts, advice, cwe, names)


RULES = [
    # --- Secretos ---
    r("SEC001", "Posible secreto o contraseña embebida", "high",
      r"""(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|client[_-]?secret)\w*\s*[:=]\s*["'](?!\s*["'])(?![^"']*(?:\$\{|\{\{|<|%s|process\.env|os\.environ|example|changeme|your[_-]|xxx|\*\*\*))[^"'\s]{8,}["']""",
      advice="Mueve el secreto a un gestor de secretos o variable de entorno y rota la credencial.", cwe="CWE-798"),
    r("SEC002", "Llave de acceso de AWS", "critical", r"\bAKIA[0-9A-Z]{16}\b",
      advice="Revoca la llave, rótala y usa roles IAM.", cwe="CWE-798"),
    r("SEC003", "Llave privada en el repositorio", "critical", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
      advice="Elimina la llave, revócala y genera una nueva.", cwe="CWE-321"),
    r("SEC004", "Token de GitHub", "critical", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
      advice="Revoca el token inmediatamente.", cwe="CWE-798"),
    # --- Criptografía ---
    r("CRY001", "Hash débil (MD5/SHA-1)", "medium",
      r"""(?:hashlib\.(?:md5|sha1)\b|createHash\(\s*["'](?:md5|sha1)["']|MessageDigest\.getInstance\(\s*["'](?:MD5|SHA-?1)["']|\bmd5\s*\(|\bsha1\s*\()""",
      CODE, "No uses MD5/SHA-1 para contraseñas ni firmas: usa Argon2id/bcrypt o SHA-256+.", "CWE-327"),
    r("CRY002", "Verificación TLS deshabilitada", "high",
      r"""(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0))""",
      CODE, "Mantén la verificación de certificados activa.", "CWE-295"),
    r("CRY003", "Aleatoriedad no criptográfica para seguridad", "medium",
      r"""(?:token|secret|password|session|nonce|otp)\w*\s*[:=].*(?:Math\.random\(|\brandom\.(?:random|randint|choice)\()""",
      PY + JS, "Usa crypto.randomBytes / secrets para valores de seguridad.", "CWE-338"),
    # --- Inyección ---
    r("INJ001", "SQL construido por concatenación o interpolación", "high",
      r"""(?:execute|query|raw)\w*\(\s*f["'].*\b(?:select|insert|update|delete)\b|(?:execute|query|raw)\w*\(.*\b(?:select\s|insert\s+into|update\s+\w+\s+set|delete\s+from).*(?:["'`]\s*(?:\+|%)\s*[\w(]|\$\{|\.format\()""",
      CODE, "Usa consultas parametrizadas / ORM.", "CWE-89"),
    r("INJ002", "Ejecución dinámica de código (eval/exec)", "high",
      r"""(?<![\w.])(?:eval|exec)\s*\(\s*(?!["'][^"']*["']\s*\))""", PY + JS + PHP,
      "Evita eval/exec con datos externos; usa parsers o listas blancas.", "CWE-95"),
    r("INJ003", "Ejecución de comandos del sistema con shell", "high",
      r"""(?:subprocess\.\w+\([^)]*shell\s*=\s*True|os\.system\(|child_process\.exec\(|\bexec\(\s*[`"'].*\$\{|Runtime\.getRuntime\(\)\.exec\(|\b(?:shell_exec|passthru|system)\()""",
      CODE, "Usa APIs sin shell con lista de argumentos y valida la entrada.", "CWE-78"),
    r("INJ004", "Deserialización insegura", "high",
      r"""(?:pickle\.loads?\(|yaml\.load\((?![^)]*SafeLoader)|marshal\.loads?\(|unserialize\(|ObjectInputStream\()""",
      CODE, "Usa formatos seguros (JSON) o yaml.safe_load.", "CWE-502"),
    r("XSS001", "Inserción de HTML sin sanear (XSS)", "medium",
      r"""(?:\.innerHTML\s*=|\.outerHTML\s*=|document\.write\(|dangerouslySetInnerHTML|v-html\s*=)""",
      WEB, "Usa textContent o sanea con una librería (DOMPurify) y aplica CSP.", "CWE-79"),
    r("SSRF001", "Petición HTTP con URL controlable (posible SSRF)", "low",
      r"""(?:requests\.(?:get|post|put|delete)|axios\.(?:get|post)|fetch|urlopen)\(\s*(?:req\.|request\.|f["']|\w+\s*\+)""",
      PY + JS, "Valida el destino con una lista blanca de hosts.", "CWE-918"),
    r("PATH001", "Posible path traversal al abrir archivos", "medium",
      r"""(?:open|readFile(?:Sync)?|createReadStream|send_file)\(\s*(?:req\.|request\.|f["'][^"']*\{|[\w.]+\s*\+\s*(?:req|request|filename|name|path))""",
      PY + JS, "Normaliza la ruta y verifica que quede dentro del directorio permitido.", "CWE-22"),
    # --- Configuración ---
    r("CFG001", "Modo debug activo", "medium",
      r"""(?:app\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True|FLASK_DEBUG\s*=\s*1)""", PY + (".env", ".cfg", ".ini"),
      "Desactiva debug en producción.", "CWE-489"),
    r("CFG002", "CORS abierto a cualquier origen", "medium",
      r"""(?:origin\s*:\s*["']\*["']|Access-Control-Allow-Origin["']?\s*[:,=]\s*["']?\*|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|allow_origins\s*=\s*\[\s*["']\*["'])""",
      ANY, "Restringe CORS a orígenes conocidos.", "CWE-942"),
    r("CFG003", "Cookie sin atributos de seguridad", "low",
      r"""(?:httpOnly\s*:\s*false|secure\s*:\s*false|SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False)""",
      CODE, "Activa HttpOnly, Secure y SameSite.", "CWE-1004"),
    r("CFG004", "JWT con algoritmo 'none' o sin verificación", "high",
      r"""(?:algorithms?\s*[:=]\s*\[?\s*["']none["']|verify_signature["']?\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False)""",
      PY + JS + JAVA, "Verifica siempre la firma con un algoritmo explícito.", "CWE-347"),
    r("CFG005", "Enlace http:// sin cifrar", "low",
      r"""["']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.|www\.w3\.org|schemas\.)[\w.-]+""",
      CODE + (".html", ".yml", ".yaml", ".json"), "Usa https:// para tráfico externo.", "CWE-319"),
    r("DOC001", "Contenedor sin usuario no-root", "medium", r"^(?!.*\bUSER\b)(?s:.*)$", ANY,
      "Agrega una instrucción USER no privilegiada.", "CWE-250", names=("Dockerfile",)),
    r("DOC002", "Imagen base con etiqueta 'latest'", "low", r"^\s*FROM\s+[\w./-]+(?::latest)?\s*(?:AS\s+\w+)?\s*$",
      ANY, "Fija la versión (o digest) de la imagen base.", "CWE-1104", names=("Dockerfile",)),
]
