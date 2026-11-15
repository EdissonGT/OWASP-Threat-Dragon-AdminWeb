# Mejores prácticas de seguridad de aplicaciones

Guía abierta y práctica para **mejorar la seguridad de una aplicación web**, con un **analizador de código ejecutable** para revisar tu proyecto. Pensada para equipos de desarrollo que quieren una referencia concisa, accionable y alineada con estándares ([OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/), [OWASP Top 10](https://owasp.org/www-project-top-ten/), NIST SSDF, SLSA).

## Analiza tu código en 30 segundos

```bash
git clone https://github.com/EdissonGT/OWASP-Threat-Dragon-AdminWeb.git
cd OWASP-Threat-Dragon-AdminWeb
python3 -m appsec_scan /ruta/a/tu/proyecto      # solo requiere Python 3.8+
python3 -m appsec_scan samples/vulnerable-app   # prueba con código vulnerable de práctica
```

Detecta secretos embebidos, inyección SQL/comandos, criptografía débil, XSS, TLS deshabilitado, CORS abierto, JWT inseguro, Dockerfiles sin usuario no-root y más. Salida en texto, JSON o SARIF. Ver [docs/09](docs/09-analizador-de-codigo.md).

## Guías

| # | Tema |
|---|---|
| [01](docs/01-autenticacion-y-sesiones.md) | Autenticación, contraseñas y sesiones |
| [02](docs/02-autorizacion.md) | Autorización y control de acceso |
| [03](docs/03-validacion-y-api.md) | Validación de entrada/salida y seguridad de APIs |
| [04](docs/04-datos-secretos-y-criptografia.md) | Datos, secretos y criptografía |
| [05](docs/05-infraestructura-bd-y-logging.md) | Base de datos, infraestructura, logging y disponibilidad |
| [06](docs/06-cadena-de-suministro-y-cicd.md) | Cadena de suministro y CI/CD |
| [07](docs/07-ciclo-de-desarrollo-seguro.md) | Ciclo de desarrollo seguro y modelado de amenazas (STRIDE) |
| [08](docs/08-owasp-top-10.md) | OWASP Top 10 y su mitigación |
| [09](docs/09-analizador-de-codigo.md) | Analizador de código `appsec-scan` |

## Recursos prácticos

- [Checklist de seguridad](checklists/checklist-seguridad-aplicacion.md) para cada release.
- [Ejemplo Node/Express](examples/node-express/secure-server.js) con helmet, rate limiting, validación y autorización.
- [Ejemplo Python/Flask](examples/python-flask/secure_app.py) con Argon2id, límites y headers.
- [Headers de seguridad recomendados](examples/security-headers.md).
- [Plantillas de CI/CD](templates/) listas para copiar: GitHub Actions (CodeQL, gitleaks, Trivy), Dependabot y pre-commit.
- [Código vulnerable de práctica](samples/vulnerable-app/) para aprender a detectar y corregir.

## Por dónde empezar

1. Autenticación y autorización en el **servidor**, y TLS en todo el tráfico.
2. Gestión de secretos y almacenamiento seguro de contraseñas.
3. Validación de entrada y control de dependencias.
4. Logging, monitoreo y pipeline CI/CD seguro.
5. Mejora continua: modelado de amenazas en cada cambio importante.

## Contribuir y seguridad

- [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Pruebas: `python3 -m unittest discover -s tests`. GitHub Actions las ejecuta junto con `scripts/check_secrets.py`.

Autor: Edisson Payes · Licencia: [MIT](LICENSE)
