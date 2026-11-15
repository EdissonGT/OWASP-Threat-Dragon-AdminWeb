# repocheckup

**Un chequeo de salud para cualquier repositorio de código.** Un solo comando revisa seguridad, calidad de código, salud del repositorio y dependencias, le da al proyecto un puntaje de 0 a 100 y te dice cómo corregir cada hallazgo.

Sin dependencias. Solo Python 3.8+. Funciona sin conexión. Mensajes en español e inglés.

🇬🇧 [Read in English](README.md)

## Inicio rápido

```bash
git clone https://github.com/EdissonGT/repocheckup.git
cd repocheckup
python3 -m repocheckup /ruta/a/tu/proyecto --lang es --html reporte.html
```

```
[HIGH] INJ001 SQL construido por concatenación o interpolación (CWE-89)
  app.py:13
  > cursor.execute("SELECT * FROM users WHERE name = '%s'" % user)
  Cómo corregirlo: Usa consultas parametrizadas o un ORM.

Resumen: 11 archivos analizados, 49 hallazgos
  Seguridad                  0/100  F  (34)
  Calidad de código         82/100  B  (6)
  Salud del repositorio     76/100  B  (9)
  Puntaje general           53/100  D
```

¿Quieres verlo funcionar primero? Ejecútalo sobre el proyecto de práctica, roto a propósito, en [`samples/vulnerable-app`](samples/vulnerable-app).

## Qué revisa

| Área | Ejemplos |
|---|---|
| **Seguridad** | Secretos embebidos, inyección SQL y de comandos, criptografía débil, XSS, TLS desactivado, CORS abierto, JWT sin verificar, errores de configuración en Dockerfile / Terraform / Kubernetes / GitHub Actions |
| **Calidad de código** | Funciones largas o complejas, demasiados parámetros, errores silenciados, valores por defecto mutables, notas TODO, código duplicado |
| **Salud del repositorio** | Falta de README, licencia, pruebas, CI, lockfile o política de seguridad; dependencias sin fijar; archivos `.env` versionados |
| **Dependencias** (`--deps`) | Vulnerabilidades conocidas en paquetes fijados de PyPI y npm, con [OSV.dev](https://osv.dev) |

Salida en texto, JSON, SARIF (GitHub Code Scanning) o un informe HTML autónomo. Opciones completas en la [guía de uso](docs/09-uso-de-repocheckup.md).

## Usarlo en GitHub Actions

```yaml
- uses: actions/checkout@v4
- uses: EdissonGT/repocheckup@main
  with:
    fail-on: high
    min-score: "70"
    lang: es
```

## Guías para corregir lo que encuentra

| # | Tema |
|---|---|
| [01](docs/01-autenticacion-y-sesiones.md) | Autenticación, contraseñas y sesiones |
| [02](docs/02-autorizacion.md) | Autorización y control de acceso |
| [03](docs/03-validacion-y-api.md) | Validación de entrada/salida y seguridad de APIs |
| [04](docs/04-datos-secretos-y-criptografia.md) | Datos, secretos y criptografía |
| [05](docs/05-infraestructura-bd-y-logging.md) | Base de datos, infraestructura, logging y disponibilidad |
| [06](docs/06-cadena-de-suministro-y-cicd.md) | Cadena de suministro y CI/CD |
| [07](docs/07-ciclo-de-desarrollo-seguro.md) | Ciclo de desarrollo seguro y modelado de amenazas |
| [08](docs/08-owasp-top-10.md) | OWASP Top 10 y su mitigación |
| [09](docs/09-uso-de-repocheckup.md) | Uso de la herramienta `repocheckup` |
| [10](docs/10-calidad-de-codigo.md) | Calidad y mantenibilidad del código |
| [11](docs/11-salud-del-repositorio.md) | Salud del repositorio y del proyecto |

También incluye una [checklist de release](checklists/checklist-seguridad-aplicacion.md), ejemplos de código seguro en [`examples/`](examples) y plantillas de CI en [`templates/`](templates).

## Límites

`repocheckup` analiza por patrones: da falsos positivos y falsos negativos. Es una primera revisión rápida, no un reemplazo de la revisión de código, las pruebas ni herramientas dedicadas como CodeQL, Semgrep o SonarQube.

## Contribuir

Se aceptan reglas nuevas, más lenguajes y traducciones. Ver [CONTRIBUTING.md](CONTRIBUTING.md) y [SECURITY.md](SECURITY.md). Pruebas: `python3 -m unittest discover -s tests`.

## Licencia

[MIT](LICENSE) © Edisson Payes
