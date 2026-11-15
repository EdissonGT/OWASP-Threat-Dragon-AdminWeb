# Headers de seguridad recomendados

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=()
Cross-Origin-Opener-Policy: same-origin
Cache-Control: no-store            # en respuestas con datos sensibles
```

Cookies de sesión: `Set-Cookie: sid=...; HttpOnly; Secure; SameSite=Lax; Path=/`

Verifica tu configuración con <https://securityheaders.com> y <https://observatory.mozilla.org>.
