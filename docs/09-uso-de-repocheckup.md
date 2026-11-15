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
| `--html ARCHIVO` | Genera un informe HTML autónomo (funciona sin conexión). |
| `--format text\|json\|sarif` | Formato de la salida principal. SARIF se sube a GitHub Code Scanning. |
| `--output ARCHIVO` | Escribe la salida principal en un archivo. |
| `--fail-on low\|medium\|high\|critical\|never` | Código de salida 1 si hay hallazgos de esa severidad o mayor (por defecto `high`). |
| `--min-score N` | Código de salida 1 si el puntaje general es menor que `N`. |
| `--exclude NOMBRE` | Carpeta a omitir (repetible). |
| `--lang en\|es` | Idioma de los mensajes. |
| `--theme matrix\|classic` | Aspecto del informe HTML y del encabezado en la terminal. `matrix` (por defecto) es verde sobre negro con lluvia de código; `classic` es un tema claro y oscuro sencillo. |

Para silenciar un falso positivo en una línea, agrega el comentario `repocheckup-ignore`.

## Recomendaciones de IA (`--ai`)

Las reglas dicen *qué* está mal. Con `--ai`, Claude lee los hallazgos junto con el código que los rodea y te dice *qué hacer*:

- una evaluación breve del repositorio,
- un plan priorizado que agrupa los hallazgos que comparten una misma corrección, con el riesgo de dejar cada uno como está,
- el código corregido de las líneas señaladas,
- qué hallazgos parecen falsos positivos,
- mejoras rápidas que toman minutos.

```bash
pip install "repocheckup[ai]"
export ANTHROPIC_API_KEY=...            # desde console.anthropic.com
repocheckup /ruta/a/tu/proyecto --ai --lang es --html reporte.html
```

Las recomendaciones salen en la terminal, en el informe HTML y en la clave `ai` de la salida JSON.

| Opción | Descripción |
|---|---|
| `--ai` | Activa las recomendaciones de IA. |
| `--ai-model MODELO` | Modelo a usar (por defecto `claude-opus-5-5`; también `REPOCHECKUP_AI_MODEL`). |
| `--ai-effort low\|medium\|high\|xhigh\|max` | Cuánto razona el modelo. Más alto cuesta más (por defecto `medium`). |
| `--ai-max-findings N` | Cuántos hallazgos, los más graves primero, se envían (por defecto 40). |

Antes de activarla:

- **Tu código sale de tu máquina.** Se envían a la API de Anthropic los hallazgos y unas doce líneas de código alrededor de cada uno. Sin `--ai` no se envía nada.
- **Tiene costo.** Cada ejecución se cobra a tu API key; al terminar se muestra cuántos tokens usó.
- **Requiere Python 3.10 o superior** (lo exige el SDK de Anthropic). El resto de la herramienta sigue funcionando en 3.8.
- **Revisa lo que sugiere.** Es un modelo leyendo fragmentos, no tu proyecto completo; toma sus correcciones como una propuesta.
- Si la API no responde o falta la key, el informe normal se genera igual.

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
