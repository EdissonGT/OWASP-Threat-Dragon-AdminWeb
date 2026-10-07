# AdminWeb - Modelo de amenazas (OWASP Threat Dragon)

Modelo de amenazas STRIDE de **AdminWeb** (frontend React, API Node.js/Express, base de datos DB2, scheduler y pipeline CI/CD).
Autor: Edisson Payes. Versión actual: **v1.2**.
Repositorio: https://github.com/EdissonGT/OWASP-Threat-Dragon-AdminWeb.git

Los datos de infraestructura (IPs, esquemas, tablas, llaves, identificadores) están anonimizados.

## Contenido

| Ruta | Descripción |
|---|---|
| `threat-models/AdminWeb/AdminWeb.json` | Modelo vigente de Threat Dragon (4 diagramas, 50 amenazas) |
| `threat-models/AdminWeb/versions/` | Copias del modelo de cada versión (v0.1, v0.5, v1.0, v1.1, v1.2) |
| `Diagramas/` | PNG exportados desde Threat Dragon v2.6.2 (evidencia de la herramienta) |
| `docs/amenazas.csv` | Inventario de las 50 amenazas STRIDE en formato tabular |

## Diagramas

- Nivel 0: contexto general.
- Nivel 1: procesos, almacenes de datos, flujos y límites de confianza.
- Nivel 2A: autenticación y control de acceso.
- Nivel 2B: pipeline CI/CD y despliegue a QA.

Las amenazas se asocian una sola vez, en el nivel 1 (componentes de la aplicación) y en el nivel 2B (pipeline).

## Resumen del modelo

| Severidad | Cantidad |
|---|---|
| Crítico | 12 |
| Alto | 29 |
| Medio | 9 |

## Versionado

Las versiones del modelo se conservan como copias del archivo JSON en `threat-models/AdminWeb/versions/`:

| Versión | Contenido |
|---|---|
| v0.1 | DFD de nivel 0 y 1 |
| v0.5 | Estructura completa, con DFD de nivel 2A y 2B |
| v1.0 | Modelo con las 49 amenazas STRIDE |
| v1.1 | Disposición corregida de los diagramas y capturas de Threat Dragon |
| v1.2 | Sugerencias automáticas de Threat Dragon y amenaza T-50 (vigente) |
