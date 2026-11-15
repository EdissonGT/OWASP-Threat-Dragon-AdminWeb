# Contribuir / Contributing

¡Gracias por tu interés! Las contribuciones son bienvenidas:

- Amenazas STRIDE faltantes o mal clasificadas.
- Mejoras a mitigaciones y a la documentación.
- Correcciones de formato en el JSON o el CSV.

## Cómo contribuir

1. Haz un fork y crea una rama.
2. Edita el modelo con [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon) y exporta el JSON.
3. Si cambia el inventario de amenazas, actualiza `docs/amenazas.csv`.
4. Ejecuta `python3 scripts/validate_model.py` (valida que el JSON sea correcto).
5. Abre un Pull Request describiendo el cambio.

**Importante:** no incluyas datos reales de infraestructura (IPs, credenciales, nombres internos). Todo debe estar anonimizado.
