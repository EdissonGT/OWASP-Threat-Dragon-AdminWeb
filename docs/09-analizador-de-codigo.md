# 9. Analizador de código (appsec-scan)

Herramienta incluida en este repositorio para **analizar tu propio código** y detectar patrones inseguros. Es ligera (solo Python 3.8+, sin dependencias) y complementa, no reemplaza, herramientas como CodeQL, Semgrep o SonarQube.

## Instalación y uso

```bash
git clone https://github.com/EdissonGT/OWASP-Threat-Dragon-AdminWeb.git
cd OWASP-Threat-Dragon-AdminWeb

# Sin instalar
python3 -m appsec_scan /ruta/a/tu/proyecto

# O instalado
pip install .
appsec-scan /ruta/a/tu/proyecto
```

Opciones:

| Opción | Descripción |
|---|---|
| `--format text\|json\|sarif` | Formato de salida. SARIF se sube a GitHub Code Scanning. |
| `--fail-on low\|medium\|high\|critical` | Devuelve código de salida 1 si hay hallazgos de esa severidad o mayor (por defecto `high`). |
| `--exclude carpeta` | Excluye carpetas (repetible). `.git`, `node_modules`, `venv`, `dist`… ya se omiten. |

Para ignorar un falso positivo en una línea, agrega el comentario `appsec-ignore`.

## Probar con el código vulnerable de práctica

```bash
python3 -m appsec_scan samples/vulnerable-app
```

`samples/vulnerable-app/` contiene código **deliberadamente inseguro** (Python, JavaScript y Dockerfile) para ver qué detecta la herramienta y practicar las correcciones. Compara con los ejemplos seguros en `examples/`.

## Qué detecta

| Regla | Qué busca | CWE |
|---|---|---|
| SEC001–004 | Secretos embebidos, llaves AWS, llaves privadas, tokens de GitHub | 798, 321 |
| CRY001 | Hash débil (MD5/SHA-1) | 327 |
| CRY002 | Verificación TLS deshabilitada | 295 |
| CRY003 | Aleatoriedad no criptográfica en tokens | 338 |
| INJ001 | SQL por concatenación/interpolación | 89 |
| INJ002 | `eval`/`exec` dinámico | 95 |
| INJ003 | Comandos del sistema con shell | 78 |
| INJ004 | Deserialización insegura (pickle, yaml.load…) | 502 |
| XSS001 | `innerHTML`, `document.write`, `v-html`… | 79 |
| SSRF001 / PATH001 | Peticiones y rutas controladas por el usuario | 918, 22 |
| CFG001–005 | Debug activo, CORS abierto, cookies inseguras, JWT sin verificar, enlaces http | 489, 942, 1004, 347, 319 |
| DOC001–002 | Dockerfile sin USER no-root / imagen `latest` | 250, 1104 |

> Es un análisis por patrones: puede dar **falsos positivos y falsos negativos**. Úsalo como primera barrera y combínalo con revisión de código, pruebas y SAST/DAST profesionales.

## Integrarlo en tu proyecto (CI/CD)

En `templates/` hay configuraciones listas para copiar:

- `templates/github-actions/security.yml`: CodeQL, gitleaks, revisión de dependencias, appsec-scan y Trivy.
- `templates/dependabot.yml`: actualizaciones automáticas de dependencias.
- `templates/pre-commit-config.yaml`: escaneo de secretos y análisis antes de cada commit.

## Cómo aplicar las correcciones

Cada hallazgo incluye una sugerencia y su CWE. Para el detalle de cómo corregirlo, consulta las guías `docs/01` a `docs/08` y la [checklist](../checklists/checklist-seguridad-aplicacion.md).

## Extender las reglas

Las reglas están en `appsec_scan/rules.py`. Agrega una con `r("ID", "Título", "severidad", r"regex", extensiones, "consejo", "CWE")` y un caso en `tests/test_scanner.py`. Ejecuta las pruebas con `python3 -m unittest discover -s tests`.
