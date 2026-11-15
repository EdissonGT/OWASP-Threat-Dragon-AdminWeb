# 7. Ciclo de desarrollo seguro (SSDLC)

1. **Requisitos**: define requisitos de seguridad (OWASP ASVS nivel 1/2) y de privacidad.
2. **Diseño**: modela amenazas (STRIDE) en cada cambio de arquitectura importante; usa [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon).
3. **Desarrollo**: guías de codificación segura, revisión de código con checklist de seguridad.
4. **Pruebas**: unit tests de seguridad, SAST/SCA en CI, DAST y pruebas de penetración periódicas.
5. **Despliegue**: configuración endurecida, secretos gestionados, rollback.
6. **Operación**: monitoreo, respuesta a incidentes, gestión de vulnerabilidades con SLA por severidad.
7. **Mejora continua**: post-mortems sin culpables, métricas, capacitación (OWASP Juice Shop, WebGoat).

## STRIDE en una línea
Spoofing (identidad) · Tampering (integridad) · Repudiation (no repudio) · Information disclosure (confidencialidad) · Denial of service (disponibilidad) · Elevation of privilege (autorización).

## Personas
Capacitación anti-phishing, cuentas nominales (sin accesos compartidos), política de credenciales y plan de respuesta a incidentes documentado.
