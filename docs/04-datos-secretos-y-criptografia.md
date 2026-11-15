# 4. Datos, secretos y criptografía

## Datos
- **TLS 1.2+** en todo el tráfico (cliente-API, API-BD, servicios internos); HSTS habilitado.
- Cifra datos sensibles en reposo; minimiza lo que recolectas y por cuánto tiempo.
- Enmascara datos sensibles en logs, errores y entornos de prueba (no uses datos reales en QA).
- Backups cifrados y con restauración probada.

## Secretos
- Nunca en el código ni en el repositorio: usa un gestor (Vault, AWS/Azure/GCP Secrets Manager).
- Rota llaves periódicamente y tras cualquier sospecha de exposición.
- Escaneo de secretos en pre-commit y CI (gitleaks, trufflehog); GitHub secret scanning activado.
- Un secreto distinto por entorno y por servicio.

## Criptografía
- No inventes algoritmos: usa librerías probadas (libsodium, Tink, `cryptography`).
- AES-GCM o ChaCha20-Poly1305 para cifrado; Argon2id para contraseñas; HMAC-SHA256 para integridad.
- Números aleatorios con CSPRNG (`crypto.randomBytes`, `secrets`), nunca `Math.random()`.

Referencias: OWASP ASVS V6, V8, V9 · OWASP Cryptographic Storage Cheat Sheet.
