# 11. Salud del repositorio y del proyecto

Un proyecto sano es uno que otra persona puede clonar, entender, ejecutar y mejorar sin preguntarte nada. Estas prácticas corresponden a las reglas `HLT` y `DEP` de `repocheckup`.

## Documentación mínima
- **README** (HLT001, HLT013): qué hace, cómo se instala, cómo se usa, cómo se prueba.
- **LICENSE** (HLT002): sin licencia, legalmente nadie puede reutilizar el código.
- **CONTRIBUTING** (HLT009) y **SECURITY.md** (HLT008): cómo colaborar y cómo reportar vulnerabilidades en privado.
- **CHANGELOG** y versiones semánticas (`MAYOR.MENOR.PARCHE`).

## Automatización
- **Pruebas automáticas** (HLT003) ejecutadas por **CI** en cada push (HLT004).
- Ramas protegidas: nada llega a `main` sin revisión y CI en verde.
- Releases reproducibles y automatizados.

## Dependencias
- **Lockfile versionado** (HLT006) y **versiones fijadas** (HLT007): builds reproducibles.
- **Actualización automática** con Dependabot o Renovate (HLT012).
- **Vulnerabilidades conocidas** (DEP001): revisa con `repocheckup --deps`, `npm audit` o `pip-audit`.
- Menos dependencias, menos superficie de ataque y menos mantenimiento.

## Higiene de git
- **`.gitignore`** (HLT005) desde el primer commit.
- **Nunca versiones `.env`** ni secretos (HLT010). Si ocurrió: rota el secreto y límpialo del historial.
- Binarios grandes fuera del repositorio o en Git LFS (HLT011).
- Commits pequeños con mensajes que expliquen el porqué.

## Operación
- Configuración por variables de entorno (12-factor), no en el código.
- Logs estructurados, métricas y health checks.
- Entornos reproducibles: contenedores o scripts de instalación.
- Plan de respaldo y recuperación probado.

## Comunidad
- Plantillas de issue y PR, código de conducta.
- Etiqueta `good first issue` para quien llega por primera vez.
- Responde issues y PR aunque sea con un "lo reviso esta semana".

Referencias: [OpenSSF Scorecard](https://securityscorecards.dev) · [OpenSSF Best Practices](https://www.bestpractices.dev) · [The Twelve-Factor App](https://12factor.net) · [Semantic Versioning](https://semver.org).
