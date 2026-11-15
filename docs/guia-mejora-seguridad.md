# Guía para mejorar la seguridad de una aplicación web

Guía práctica organizada por área. Cada punto referencia amenazas del modelo de ejemplo (`docs/amenazas.csv`) y estándares como [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) y [OWASP Top 10](https://owasp.org/www-project-top-ten/).

## 1. Autenticación y sesiones (T-01, T-05, T-07, T-43, T-44)
- Verifica la identidad en **todas** las rutas protegidas del backend, no solo en la interfaz.
- Activa MFA para cuentas administrativas.
- Limita intentos de login (rate limiting, bloqueo progresivo) y alerta ante patrones anómalos.
- Usa tokens de vida corta con renovación y mecanismo de revocación.
- Genera secretos de firma aleatorios por entorno; nunca valores por defecto.

## 2. Autorización (T-02, T-03, T-14, T-45)
- Aplica autorización **en el servidor** en cada operación (mínimo privilegio, deny by default).
- Toma la identidad del actor desde el token verificado, nunca desde datos enviados por el cliente.
- Audita los cambios de permisos y exige doble control en acciones críticas.

## 3. Contraseñas y secretos (T-06, T-08, T-09, T-28, T-46)
- Almacena contraseñas con Argon2id o bcrypt, con sal única.
- Guarda secretos en un gestor de secretos; no en el código ni en el repositorio.
- Rota llaves periódicamente y activa escaneo de secretos en el repositorio y el pipeline.
- No imprimas secretos ni datos sensibles en consola o logs.

## 4. Protección de datos en tránsito y reposo (T-10, T-11, T-26)
- TLS en todo el tráfico: cliente-API, API-base de datos y servicios internos. Habilita HSTS.
- Cifra datos sensibles en reposo y verifica certificados.

## 5. Entrada, salida y API (T-13, T-19, T-20, T-21, T-22, T-23)
- Valida la entrada con esquemas centralizados; usa consultas parametrizadas.
- Codifica la salida y aplica una política CSP para mitigar XSS.
- Neutraliza valores que empiecen con `=`, `+`, `-` o `@` al exportar a hojas de cálculo.
- Restringe CORS a orígenes conocidos y devuelve errores genéricos al cliente.
- Guarda el token en cookies `HttpOnly` + `SameSite` en lugar de almacenamiento accesible por scripts (T-12).

## 6. Disponibilidad y rendimiento (T-15, T-16, T-17, T-32, T-50)
- Rate limiting, timeouts y paginación en consultas pesadas.
- Pool de conexiones con límites.
- Evita puntos únicos de fallo; considera WAF y monitoreo de escaneos.

## 7. Base de datos (T-24, T-25, T-27, T-48)
- Cuentas por función con mínimo privilegio; la app no debe poder alterar su propia bitácora.
- Bitácoras de solo anexado, con integridad y retención.

## 8. Logging y monitoreo (T-29, T-30)
- Centraliza logs (SIEM), protege su integridad y define alertas.
- Determina la IP de origen solo mediante proxies de confianza.

## 9. Dependencias y cadena de suministro (T-35, T-37, T-42)
- Análisis de dependencias (SCA) y actualización periódica.
- Construye artefactos en CI, verifica su integridad (firmas, hashes) y no instales paquetes en producción.

## 10. CI/CD y despliegue (T-36, T-38, T-39, T-40, T-41)
- MFA y revisión de accesos para desarrolladores.
- Agentes efímeros y con mínimo privilegio.
- Aprobaciones, versionado, trazabilidad y rollback en cada despliegue.
- Incorpora SAST, SCA y escaneo de secretos al pipeline.

## 11. Personas y procesos (T-43, T-49)
- Capacitación anti-phishing y política de credenciales.
- Cuentas nominales, sin accesos compartidos, con registro de sesiones.

## Cómo priorizar
1. Autenticación/autorización en el servidor y TLS.
2. Gestión de secretos y contraseñas.
3. Validación de entrada y dependencias.
4. Logging, monitoreo y pipeline seguro.
5. Mejora continua: revisar el modelo de amenazas en cada cambio importante.
