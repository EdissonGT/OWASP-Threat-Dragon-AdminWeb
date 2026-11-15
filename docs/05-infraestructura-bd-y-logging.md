# 5. Base de datos, infraestructura, logging y disponibilidad

## Base de datos
- Cuentas por función con **mínimo privilegio**; la aplicación no usa cuentas administrativas.
- La app no debe poder modificar su propia bitácora de auditoría (solo anexar).
- Pool de conexiones con límites y timeouts; conexiones cifradas con verificación de certificado.

## Infraestructura
- Segmenta redes; expón solo lo necesario; WAF delante de aplicaciones públicas.
- Contenedores sin root, imágenes mínimas, escaneo de imágenes; sistema de archivos de solo lectura cuando sea posible.
- Parches de SO y runtimes al día; endurece configuración (CIS Benchmarks).
- Evita puntos únicos de fallo; define RTO/RPO y prueba la recuperación.

## Logging y monitoreo
- Registra: autenticación, cambios de permisos, accesos denegados, operaciones críticas, errores.
- Centraliza (SIEM) con integridad y retención; no registres secretos ni datos personales completos.
- Alertas sobre intentos de fuerza bruta, picos de errores 4xx/5xx y accesos fuera de patrón.
- Determina la IP de origen solo a través de proxies de confianza (`X-Forwarded-For` es falsificable).

## Disponibilidad
- Rate limiting, timeouts, límites de recursos, paginación y circuit breakers.

Referencias: OWASP ASVS V7, V14 · CIS Benchmarks.
