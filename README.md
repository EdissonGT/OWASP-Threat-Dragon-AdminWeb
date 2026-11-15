# Cómo mejorar la seguridad de una aplicación web

Guía práctica de mejora de seguridad con un **modelo de amenazas STRIDE de ejemplo** (OWASP Threat Dragon). Empieza por [`docs/guia-mejora-seguridad.md`](docs/guia-mejora-seguridad.md).

El modelo de amenazas es **de referencia** para una aplicación web administrativa genérica: SPA, API, base de datos relacional, scheduler y pipeline CI/CD. Es un **ejemplo ilustrativo con datos ficticios**; no describe ningún sistema real ni sus configuraciones.

Autor: Edisson Payes. Repositorio: https://github.com/EdissonGT/OWASP-Threat-Dragon-AdminWeb

## Contenido

| Ruta | Descripción |
|---|---|
| `docs/guia-mejora-seguridad.md` | Guía de buenas prácticas por área, con prioridades |
| `threat-models/AdminWeb/AdminWeb.json` | Modelo de Threat Dragon (4 diagramas, 50 amenazas) |
| `docs/amenazas.csv` | Inventario de las 50 amenazas STRIDE en formato tabular |
| `scripts/validate_model.py` | Valida los JSON y busca IPs o llaves privadas |

## Diagramas

- Nivel 0: contexto general.
- Nivel 1: procesos, almacenes de datos, flujos y límites de confianza.
- Nivel 2A: autenticación y control de acceso.
- Nivel 2B: pipeline CI/CD y despliegue.

Ábrelo con [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon) (Open a Threat Model) para ver los diagramas.

## Uso

Sirve como plantilla para aprender a aplicar STRIDE de punta a punta: diagramas de flujo de datos, límites de confianza, amenazas por severidad y mitigaciones generales.

## Contribuir y seguridad

- [CONTRIBUTING.md](CONTRIBUTING.md): cómo colaborar.
- [SECURITY.md](SECURITY.md): cómo reportar información sensible.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md): código de conducta.
- `scripts/validate_model.py` y el workflow de GitHub Actions validan el modelo en cada push.

## Licencia

MIT. Ver [LICENSE](LICENSE).
