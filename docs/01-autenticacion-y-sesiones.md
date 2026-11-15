# 1. Autenticación y sesiones

## Buenas prácticas
- Verifica la identidad en **todas** las rutas protegidas del backend; la interfaz nunca es un control de seguridad.
- Activa **MFA** (TOTP, WebAuthn/passkeys) para cuentas administrativas y de acceso privilegiado.
- Limita intentos de login: rate limiting, bloqueo progresivo, CAPTCHA tras fallos, alertas de patrones anómalos.
- Mensajes de error genéricos ("credenciales inválidas") para evitar enumeración de usuarios.
- Tokens de vida corta (15 min) + refresh token rotativo; permite revocación (lista de revocación o sesiones en servidor).
- Cookies de sesión: `HttpOnly`, `Secure`, `SameSite=Lax/Strict`.
- Secretos de firma aleatorios y distintos por entorno; rotación periódica. Prefiere algoritmos asimétricos (RS256/ES256) si hay varios verificadores.
- Cierra sesión en el servidor al hacer logout y tras cambio de contraseña.

## Contraseñas
- Almacena con **Argon2id** (o bcrypt/scrypt), sal única por usuario; nunca MD5/SHA-1/SHA-256 simples.
- Política moderna: longitud mínima 12, bloquear contraseñas filtradas (HIBP), sin reglas de composición forzosas.
- Recuperación de cuenta con tokens de un solo uso y caducidad corta.

## Referencias
OWASP ASVS V2 y V3 · OWASP Authentication / Session Management Cheat Sheets.
