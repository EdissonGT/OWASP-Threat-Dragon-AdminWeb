"""Security rules. Each rule: id, (en, es) title, severity, regex, extensions, (en, es) advice, CWE."""
import re
from dataclasses import dataclass, replace

ANY = ()
PY = (".py",)
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
JAVA = (".java", ".kt")
PHP = (".php",)
GO = (".go",)
WEB = JS + (".html", ".vue")
CODE = PY + JS + JAVA + PHP + GO + (".rb", ".cs")
YAML = (".yml", ".yaml")
TF = (".tf",)
SHELLISH = (".sh", ".bash") + YAML


@dataclass(frozen=True)
class Rule:
    id: str
    title: tuple
    severity: str
    pattern: re.Pattern
    exts: tuple
    advice: tuple
    cwe: str
    names: tuple = ()


def r(id, title, sev, rx, exts, advice, cwe):
    return Rule(id, title, sev, re.compile(rx, re.I), exts, advice, cwe)


RULES = [
    # --- Secrets ---
    r("SEC001", ("Possible hardcoded secret or password", "Posible secreto o contraseña embebida"), "high",
      r"""(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|client[_-]?secret)\w*\s*[:=]\s*["'](?!\s*["'])(?![^"']*(?:\$\{|\{\{|<|%s|process\.env|os\.environ|example|changeme|your[_-]|xxx|\*\*\*))[^"'\s]{8,}["']""",
      ANY, ("Move it to a secrets manager or environment variable and rotate the credential.",
            "Muévelo a un gestor de secretos o variable de entorno y rota la credencial."), "CWE-798"),
    r("SEC002", ("AWS access key", "Llave de acceso de AWS"), "critical", r"\bAKIA[0-9A-Z]{16}\b", ANY,
      ("Revoke and rotate the key; use IAM roles.", "Revoca y rota la llave; usa roles IAM."), "CWE-798"),
    r("SEC003", ("Private key committed", "Llave privada en el repositorio"), "critical",
      r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", ANY,
      ("Remove it, revoke it and generate a new one.", "Elimínala, revócala y genera una nueva."), "CWE-321"),
    r("SEC004", ("GitHub token", "Token de GitHub"), "critical", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", ANY,
      ("Revoke the token immediately.", "Revoca el token inmediatamente."), "CWE-798"),
    r("SEC005", ("Slack or Stripe token", "Token de Slack o Stripe"), "critical",
      r"\b(?:xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{16,})\b", ANY,
      ("Revoke the token immediately.", "Revoca el token inmediatamente."), "CWE-798"),
    # --- Cryptography ---
    r("CRY001", ("Weak hash (MD5/SHA-1)", "Hash débil (MD5/SHA-1)"), "medium",
      r"""(?:hashlib\.(?:md5|sha1)\b|createHash\(\s*["'](?:md5|sha1)["']|MessageDigest\.getInstance\(\s*["'](?:MD5|SHA-?1)["']|\bmd5\.(?:New|Sum)\b|\bsha1\.(?:New|Sum)\b|\bmd5\s*\(|\bsha1\s*\()""",
      CODE, ("Do not use MD5/SHA-1 for passwords or signatures: use Argon2id/bcrypt or SHA-256+.",
             "No uses MD5/SHA-1 para contraseñas ni firmas: usa Argon2id/bcrypt o SHA-256+."), "CWE-327"),
    r("CRY002", ("TLS verification disabled", "Verificación TLS deshabilitada"), "high",
      r"""(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0))""",
      CODE, ("Keep certificate verification enabled.", "Mantén activa la verificación de certificados."), "CWE-295"),
    r("CRY003", ("Non-cryptographic randomness used for security", "Aleatoriedad no criptográfica para seguridad"), "medium",
      r"""(?:token|secret|password|session|nonce|otp)\w*\s*[:=].*(?:Math\.random\(|\brandom\.(?:random|randint|choice)\(|\brand\.Intn?\()""",
      PY + JS + GO, ("Use crypto.randomBytes / secrets / crypto/rand for security values.",
                     "Usa crypto.randomBytes / secrets / crypto/rand para valores de seguridad."), "CWE-338"),
    # --- Injection ---
    r("INJ001", ("SQL built by concatenation or interpolation", "SQL construido por concatenación o interpolación"), "high",
      r"""(?:execute|query|raw)\w*\(\s*f["'].*\b(?:select|insert|update|delete)\b|(?:execute|query|raw)\w*\(.*\b(?:select\s|insert\s+into|update\s+\w+\s+set|delete\s+from).*(?:["'`]\s*(?:\+|%|\.)\s*[\w($]|\$\{|\.format\()|(?:Query|Exec)\w*\(\s*fmt\.Sprintf""",
      CODE, ("Use parameterized queries or an ORM.", "Usa consultas parametrizadas o un ORM."), "CWE-89"),
    r("INJ002", ("Dynamic code execution (eval/exec)", "Ejecución dinámica de código (eval/exec)"), "high",
      r"""(?<![\w.])eval\s*\(\s*(?!["'][^"']*["']\s*\))""", PY + JS + PHP,
      ("Avoid eval/exec on external data; use parsers or allow-lists.",
       "Evita eval/exec con datos externos; usa parsers o listas blancas."), "CWE-95"),
    r("INJ002", ("Dynamic code execution (eval/exec)", "Ejecución dinámica de código (eval/exec)"), "high",
      r"""(?<![\w.])exec\s*\(\s*(?!["'][^"']*["']\s*\))""", PY,
      ("Avoid eval/exec on external data; use parsers or allow-lists.",
       "Evita eval/exec con datos externos; usa parsers o listas blancas."), "CWE-95"),
    r("INJ003", ("System command executed through a shell", "Ejecución de comandos del sistema con shell"), "high",
      r"""(?:subprocess\.\w+\([^)]*shell\s*=\s*True|os\.system\(|child_process\.exec\(|\bexec\(\s*[`"'].*\$\{|Runtime\.getRuntime\(\)\.exec\(|\b(?:shell_exec|passthru|system)\(|exec\.Command\(\s*"(?:sh|bash)"\s*,\s*"-c")""",
      CODE, ("Use shell-less APIs with an argument list and validate input.",
             "Usa APIs sin shell con lista de argumentos y valida la entrada."), "CWE-78"),
    r("INJ004", ("Insecure deserialization", "Deserialización insegura"), "high",
      r"""(?:pickle\.loads?\(|yaml\.load\((?![^)]*SafeLoader)|marshal\.loads?\(|unserialize\(|ObjectInputStream\()""",
      CODE, ("Use safe formats (JSON) or yaml.safe_load.", "Usa formatos seguros (JSON) o yaml.safe_load."), "CWE-502"),
    r("XSS001", ("Unsanitized HTML insertion (XSS)", "Inserción de HTML sin sanear (XSS)"), "medium",
      r"""(?:\.innerHTML\s*=|\.outerHTML\s*=|document\.write\(|dangerouslySetInnerHTML|v-html\s*=)""", WEB,
      ("Use textContent or sanitize (DOMPurify) and apply a CSP.",
       "Usa textContent o sanea (DOMPurify) y aplica CSP."), "CWE-79"),
    r("XSS002", ("Request data echoed without escaping (PHP)", "Datos de la petición impresos sin escapar (PHP)"), "high",
      r"""(?:echo|print)\b.*\$_(?:GET|POST|REQUEST|COOKIE)""", PHP,
      ("Escape output with htmlspecialchars().", "Escapa la salida con htmlspecialchars()."), "CWE-79"),
    r("INJ005", ("File inclusion from request data (PHP)", "Inclusión de archivo desde datos de la petición (PHP)"), "high",
      r"""(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST)""", PHP,
      ("Never include paths taken from the request; use an allow-list.",
       "No incluyas rutas tomadas de la petición; usa una lista blanca."), "CWE-98"),
    r("SSRF001", ("HTTP request with controllable URL (possible SSRF)", "Petición HTTP con URL controlable (posible SSRF)"), "low",
      r"""(?:requests\.(?:get|post|put|delete)|axios\.(?:get|post)|fetch|urlopen)\(\s*(?:req\.|request\.|f["']|\w+\s*\+)""",
      PY + JS, ("Validate the destination against an allow-list of hosts.",
                "Valida el destino con una lista blanca de hosts."), "CWE-918"),
    r("PATH001", ("Possible path traversal when opening files", "Posible path traversal al abrir archivos"), "medium",
      r"""(?:open|readFile(?:Sync)?|createReadStream|send_file)\(\s*(?:req\.|request\.|f["'][^"']*\{|[\w.]+\s*\+\s*(?:req|request|filename|name|path))""",
      PY + JS, ("Normalize the path and check it stays inside the allowed directory.",
                "Normaliza la ruta y verifica que quede dentro del directorio permitido."), "CWE-22"),
    # --- Configuration ---
    r("CFG001", ("Debug mode enabled", "Modo debug activo"), "medium",
      r"""(?:app\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True|FLASK_DEBUG\s*=\s*1)""", PY + (".env", ".cfg", ".ini"),
      ("Disable debug in production.", "Desactiva debug en producción."), "CWE-489"),
    r("CFG002", ("CORS open to any origin", "CORS abierto a cualquier origen"), "medium",
      r"""(?:origin\s*:\s*["']\*["']|Access-Control-Allow-Origin["']?\s*[:,=]\s*["']?\*|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|allow_origins\s*=\s*\[\s*["']\*["'])""",
      ANY, ("Restrict CORS to known origins.", "Restringe CORS a orígenes conocidos."), "CWE-942"),
    r("CFG003", ("Cookie without security attributes", "Cookie sin atributos de seguridad"), "low",
      r"""(?:httpOnly\s*:\s*false|secure\s*:\s*false|SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False)""",
      CODE, ("Enable HttpOnly, Secure and SameSite.", "Activa HttpOnly, Secure y SameSite."), "CWE-1004"),
    r("CFG004", ("JWT with 'none' algorithm or unverified", "JWT con algoritmo 'none' o sin verificación"), "high",
      r"""(?:algorithms?\s*[:=]\s*\[?\s*["']none["']|verify_signature["']?\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False)""",
      PY + JS + JAVA, ("Always verify the signature with an explicit algorithm.",
                       "Verifica siempre la firma con un algoritmo explícito."), "CWE-347"),
    r("CFG005", ("Unencrypted http:// link", "Enlace http:// sin cifrar"), "low",
      r"""["']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.|www\.w3\.org|schemas\.)[\w.-]+""",
      CODE + (".html", ".json") + YAML, ("Use https:// for external traffic.", "Usa https:// para tráfico externo."), "CWE-319"),
    r("CFG006", ("Remote script piped into a shell", "Script remoto ejecutado directamente en el shell"), "medium",
      r"""(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b""", SHELLISH, 
      ("Download, verify (checksum/signature) and then run.", "Descarga, verifica (checksum/firma) y luego ejecuta."),
      "CWE-494"),
    # --- Infrastructure as code ---
    r("TF001", ("Publicly readable storage bucket", "Bucket de almacenamiento con lectura pública"), "high",
      r"""acl\s*=\s*"public-read(?:-write)?\"""", TF,
      ("Make the bucket private and grant access through policies.", "Haz privado el bucket y da acceso mediante políticas."), "CWE-732"),
    r("TF002", ("Network rule open to the whole internet", "Regla de red abierta a todo internet"), "medium",
      r"""cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]""", TF,
      ("Restrict ingress to known ranges.", "Restringe el ingreso a rangos conocidos."), "CWE-284"),
    r("TF003", ("Encryption disabled or database publicly accessible", "Cifrado deshabilitado o base de datos pública"), "high",
      r"""(?:\b(?:storage_)?encrypted\s*=\s*false|publicly_accessible\s*=\s*true)""", TF,
      ("Enable encryption at rest and keep databases private.", "Activa el cifrado en reposo y mantén privadas las bases de datos."), "CWE-311"),
    r("K8S001", ("Privileged container or privilege escalation allowed", "Contenedor privilegiado o con escalada de privilegios"), "high",
      r"""^\s*(?:privileged|allowPrivilegeEscalation)\s*:\s*true""", YAML,
      ("Set privileged: false and allowPrivilegeEscalation: false.", "Usa privileged: false y allowPrivilegeEscalation: false."), "CWE-250"),
    r("K8S002", ("Container running as root", "Contenedor ejecutándose como root"), "medium",
      r"""^\s*(?:runAsUser\s*:\s*0\b|runAsNonRoot\s*:\s*false)""", YAML,
      ("Use runAsNonRoot: true with a non-zero UID.", "Usa runAsNonRoot: true con un UID distinto de 0."), "CWE-250"),
    r("K8S003", ("Host namespaces shared with the container", "Namespaces del host compartidos con el contenedor"), "medium",
      r"""^\s*host(?:Network|PID|IPC)\s*:\s*true""", YAML,
      ("Avoid hostNetwork/hostPID/hostIPC.", "Evita hostNetwork/hostPID/hostIPC."), "CWE-668"),
    r("K8S004", ("Image with 'latest' tag", "Imagen con etiqueta 'latest'"), "low",
      r"""^\s*-?\s*image\s*:\s*["']?[\w./-]+:latest\b""", YAML,
      ("Pin the image version or digest.", "Fija la versión o digest de la imagen."), "CWE-1104"),
    # --- CI workflows ---
    r("GHA001", ("Script injection in workflow (untrusted event data in run)", "Inyección de script en workflow (datos del evento en run)"), "high",
      r"""\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|head_commit)\.[\w.]*(?:title|body|message|name|ref|label)|head_ref)""", YAML,
      ("Pass the value through an env variable instead of interpolating it.",
       "Pasa el valor mediante una variable de entorno en lugar de interpolarlo."), "CWE-94"),
    r("GHA002", ("pull_request_target trigger", "Disparador pull_request_target"), "medium",
      r"""^\s*(?:-\s*)?pull_request_target\s*:?""", YAML,
      ("It runs with secrets on untrusted code: never check out the PR head.",
       "Se ejecuta con secretos sobre código no confiable: no hagas checkout del PR."), "CWE-829"),
]

RULES = [replace(x, names=("Dockerfile", "Makefile")) if x.id == "CFG006" else x for x in RULES]

DOCKER_NO_USER = ("DOC001", ("Container without a non-root user", "Contenedor sin usuario no-root"), "medium",
                  ("Add a non-privileged USER instruction.", "Agrega una instrucción USER no privilegiada."), "CWE-250")
DOCKER_LATEST = ("DOC002", ("Base image with 'latest' tag", "Imagen base con etiqueta 'latest'"), "low",
                 ("Pin the base image version or digest.", "Fija la versión o digest de la imagen base."), "CWE-1104")
