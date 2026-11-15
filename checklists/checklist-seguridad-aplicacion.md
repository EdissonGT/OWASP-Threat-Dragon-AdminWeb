# Checklist de seguridad de una aplicación web

Copia y marca antes de cada release.

## Identidad y acceso
- [ ] Autenticación verificada en todas las rutas protegidas del servidor
- [ ] MFA en cuentas administrativas
- [ ] Rate limiting y bloqueo progresivo en login
- [ ] Contraseñas con Argon2id/bcrypt + sal
- [ ] Tokens de vida corta con revocación; cookies HttpOnly/Secure/SameSite
- [ ] Autorización por operación y por objeto en el servidor (deny by default)
- [ ] El actor de auditoría proviene del token, no del cliente

## Datos y secretos
- [ ] TLS en todo el tráfico, HSTS activo
- [ ] Datos sensibles cifrados en reposo
- [ ] Sin secretos en el repositorio; escaneo de secretos en CI
- [ ] Secretos únicos por entorno y rotados

## Aplicación
- [ ] Validación de entrada con esquemas; consultas parametrizadas
- [ ] Codificación de salida y CSP estricta
- [ ] CORS restringido; protección CSRF si hay cookies
- [ ] Errores genéricos al cliente
- [ ] Paginación, límites de tamaño y rate limiting en la API
- [ ] Headers de seguridad (ver `examples/`)

## Infraestructura y operación
- [ ] Cuentas de BD con mínimo privilegio; bitácora de solo anexado
- [ ] Logs centralizados con alertas y sin datos sensibles
- [ ] Parches al día; imágenes de contenedor sin root
- [ ] Backups cifrados y restauración probada

## Cadena de suministro y CI/CD
- [ ] SCA y SAST en cada PR
- [ ] Artefactos construidos y verificados en CI (no instalar en producción)
- [ ] Agentes con mínimo privilegio; ramas protegidas; revisión obligatoria
- [ ] Despliegue con aprobación, versionado y rollback
- [ ] SBOM generado

## Proceso
- [ ] Modelo de amenazas actualizado
- [ ] Plan de respuesta a incidentes y contacto de seguridad (SECURITY.md)
