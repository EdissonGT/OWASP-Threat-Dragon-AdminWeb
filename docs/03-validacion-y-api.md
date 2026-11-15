# 3. Validación de entrada, salida y APIs

## Entrada
- Valida con **esquemas** (JSON Schema, Zod, Pydantic) en el borde de la API: tipo, longitud, formato, rango.
- Usa **listas blancas**, no listas negras.
- **Consultas parametrizadas** o ORM; nunca concatenes entradas en SQL/NoSQL/comandos/LDAP.
- Limita tamaño de body, número de campos y profundidad de JSON.
- Subida de archivos: valida tipo real (magic bytes), tamaño, renombra, guarda fuera del webroot, escanea malware.

## Salida
- Codifica según contexto (HTML, atributo, JS, URL) para evitar XSS; frameworks modernos lo hacen por defecto: no uses `innerHTML`/`dangerouslySetInnerHTML` con datos no confiables.
- Política **CSP** estricta, sin `unsafe-inline`.
- Al exportar a Excel/CSV neutraliza celdas que empiezan con `=`, `+`, `-`, `@` (inyección de fórmulas).
- Errores genéricos al cliente; el detalle técnico solo en logs.

## API
- CORS restringido a orígenes conocidos; nunca `*` con credenciales.
- Protección CSRF si usas cookies (SameSite + token).
- Paginación obligatoria, rate limiting y cuotas por cliente.
- Versiona la API y documenta con OpenAPI; desactiva endpoints de debug en producción.
- Protege contra SSRF: valida/limita URLs que el servidor consulta.

Referencias: OWASP ASVS V5, V13 · OWASP API Security Top 10.
