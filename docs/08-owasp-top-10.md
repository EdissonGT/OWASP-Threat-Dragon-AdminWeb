# 8. OWASP Top 10 (2021) y cómo mitigarlo

| # | Categoría | Mitigación clave | Guía |
|---|---|---|---|
| A01 | Broken Access Control | Deny by default, autorización por objeto en servidor | [02](02-autorizacion.md) |
| A02 | Cryptographic Failures | TLS, cifrado en reposo, algoritmos modernos | [04](04-datos-secretos-y-criptografia.md) |
| A03 | Injection | Consultas parametrizadas, validación, codificación de salida | [03](03-validacion-y-api.md) |
| A04 | Insecure Design | Modelado de amenazas, requisitos de seguridad | [07](07-ciclo-de-desarrollo-seguro.md) |
| A05 | Security Misconfiguration | Hardening, errores genéricos, CORS/headers correctos | [05](05-infraestructura-bd-y-logging.md) |
| A06 | Vulnerable Components | SCA, lockfiles, SBOM | [06](06-cadena-de-suministro-y-cicd.md) |
| A07 | Identification & Authentication Failures | MFA, rate limiting, sesiones seguras | [01](01-autenticacion-y-sesiones.md) |
| A08 | Software & Data Integrity Failures | Firmas, CI seguro, verificación de artefactos | [06](06-cadena-de-suministro-y-cicd.md) |
| A09 | Logging & Monitoring Failures | Logs centralizados, alertas | [05](05-infraestructura-bd-y-logging.md) |
| A10 | SSRF | Lista blanca de destinos, segmentación de red | [03](03-validacion-y-api.md) |
