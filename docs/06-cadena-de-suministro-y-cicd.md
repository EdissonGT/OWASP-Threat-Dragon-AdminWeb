# 6. Cadena de suministro y CI/CD

## Dependencias
- Análisis SCA continuo (Dependabot, Renovate, `npm audit`, `pip-audit`, OWASP Dependency-Check).
- Fija versiones con lockfile y revisa dependencias nuevas; minimiza el número de paquetes.
- Genera un **SBOM** (CycloneDX/SPDX) en cada release.

## Pipeline
- Construye artefactos en CI, **firmalos** y verifica integridad antes de desplegar; no instales paquetes en el servidor de producción.
- Agentes efímeros y con mínimo privilegio; nunca cuentas administrativas.
- Secretos del pipeline en el almacén de secretos, con alcance mínimo; enmascarados en logs.
- Incorpora: **SAST** (CodeQL, Semgrep), **SCA**, escaneo de secretos, escaneo de contenedores, **DAST** en QA.
- Ramas protegidas, revisión obligatoria de PR, commits firmados, MFA para desarrolladores.
- Despliegues con aprobación, versionado trazable y **rollback** probado.
- Pin de acciones/imágenes por versión o hash (`uses: actions/checkout@<sha>`).

Referencias: OWASP SAMM · SLSA · NIST SSDF.
