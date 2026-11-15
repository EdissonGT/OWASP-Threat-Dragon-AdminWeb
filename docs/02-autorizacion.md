# 2. Autorización y control de acceso

- **Deny by default**: todo está prohibido salvo permiso explícito.
- Aplica autorización **en el servidor**, en cada operación y por objeto (previene IDOR/BOLA: comprobar que el recurso pertenece al usuario).
- Toma la identidad del actor desde el token verificado, **nunca** del body, query o headers enviados por el cliente.
- Mínimo privilegio: roles pequeños y revisados; separa funciones administrativas.
- Acciones críticas (cambio de permisos, borrados masivos): doble control y auditoría.
- Centraliza la lógica de autorización (middleware/policy) en lugar de repetirla por ruta.
- Prueba la autorización con tests automáticos (usuario A no accede a datos de usuario B).

Referencias: OWASP ASVS V4 · OWASP Top 10 A01 Broken Access Control.
