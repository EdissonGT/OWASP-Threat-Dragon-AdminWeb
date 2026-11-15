# 9. Uso de la herramienta `repocheckup`

`repocheckup` revisa un proyecto en cuatro áreas y le da un puntaje de 0 a 100:

| Área | Qué revisa |
|---|---|
| **Seguridad** | Secretos embebidos, inyección, criptografía débil, XSS, configuración insegura, Docker, Terraform, Kubernetes, GitHub Actions |
| **Calidad de código** | Funciones largas o complejas, demasiados parámetros, errores silenciados, valores por defecto mutables, notas TODO, código duplicado |
| **Salud del repositorio** | README, licencia, pruebas, CI, `.gitignore`, lockfiles, dependencias fijadas, política de seguridad, archivos `.env` versionados |
| **Dependencias** (opcional) | Vulnerabilidades conocidas en paquetes fijados, con la base pública [OSV.dev](https://osv.dev) |

Solo necesita Python 3.8 o superior, sin dependencias.

## Instalar y ejecutar

```bash
git clone https://github.com/EdissonGT/repocheckup.git
cd repocheckup
python3 -m repocheckup /ruta/a/tu/proyecto --lang es          # sin instalar
pip install . && repocheckup /ruta/a/tu/proyecto --lang es    # o instalando el comando
```

Pruébalo con el proyecto de práctica, roto a propósito:

```bash
python3 -m repocheckup samples/vulnerable-app --lang es --html reporte.html
```

## Opciones

| Opción | Descripción |
|---|---|
| `--checks security,quality,health` | Áreas a ejecutar. `all` agrega `deps`. |
| `--deps` | Consulta también las dependencias en OSV.dev. **Envía nombres y versiones de paquetes a api.osv.dev.** |
| `--html ARCHIVO` | Genera un informe HTML autónomo (funciona sin conexión, tema claro y oscuro). |
| `--format text\|json\|sarif` | Formato de la salida principal. SARIF se sube a GitHub Code Scanning. |
| `--output ARCHIVO` | Escribe la salida principal en un archivo. |
| `--fail-on low\|medium\|high\|critical\|never` | Código de salida 1 si hay hallazgos de esa severidad o mayor (por defecto `high`). |
| `--min-score N` | Código de salida 1 si el puntaje general es menor que `N`. |
| `--exclude NOMBRE` | Carpeta a omitir (repetible). |
| `--lang en\|es` | Idioma de los mensajes. |

Para silenciar un falso positivo en una línea, agrega el comentario `repocheckup-ignore`.

## Puntaje

Cada área empieza en 100 y pierde puntos por hallazgo: crítico 25, alto 10, medio 4, bajo 1. El puntaje general es el promedio de las áreas ejecutadas. Notas: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F por debajo.

## Usarlo en CI

```yaml
- uses: actions/checkout@v4
- uses: EdissonGT/repocheckup@main
  with:
    fail-on: high
    min-score: "70"
    lang: es
```

En [`templates/`](../templates) hay archivos listos para copiar: workflow de seguridad completo, Dependabot y pre-commit.

## Cómo corregir los hallazgos

Cada hallazgo trae una sugerencia. Para el detalle: seguridad en las guías `01` a `08`, calidad en la [guía 10](10-calidad-de-codigo.md) y salud del repositorio en la [guía 11](11-salud-del-repositorio.md). La lista completa de reglas está en [USAGE.md](USAGE.md).

## Límites

Es un análisis por patrones: da **falsos positivos y falsos negativos**. Úsalo como primera revisión rápida y combínalo con revisión de código, pruebas y herramientas dedicadas (CodeQL, Semgrep, SonarQube).
