# 10. Calidad y mantenibilidad del código

El código seguro pero imposible de mantener termina siendo inseguro: nadie se atreve a tocarlo. Estas prácticas corresponden a las reglas `QLT` de `repocheckup`.

## Funciones y módulos
- **Funciones cortas y con una sola responsabilidad** (QLT001). Si necesitas comentarios para separar "secciones", son funciones distintas.
- **Baja complejidad** (QLT002): retornos tempranos en lugar de `if` anidados, tablas de búsqueda en lugar de cadenas de `elif`.
- **Pocos parámetros** (QLT003): agrupa los relacionados en un objeto o dataclass.
- **Archivos cohesivos** (QLT004): un módulo, un tema.
- **Sin duplicación** (QLT007): extrae la lógica repetida; un bug corregido en una copia sigue vivo en las otras.

## Manejo de errores
- Nunca silencies errores con `except: pass` o `catch (e) {}` (QLT005). Maneja, registra o deja propagar.
- Captura excepciones específicas, no `Exception` genérica.
- Falla rápido y con mensajes claros; valida en los bordes del sistema.

## Trampas comunes
- Argumentos por defecto mutables en Python (QLT009): usa `None`.
- Notas `TODO`/`FIXME` sin seguimiento (QLT006): conviértelas en issues.
- Números y cadenas "mágicas": dales nombre con constantes.

## Nombres y legibilidad
- Nombres que digan qué es, no cómo está implementado.
- Comenta el **por qué**, no el qué.
- Formateador y linter automáticos (Black/Ruff, Prettier/ESLint, gofmt) para no discutir estilo en las revisiones.

## Pruebas
- Pirámide: muchas unitarias, algunas de integración, pocas end-to-end.
- Prueba primero lo crítico: dinero, permisos, datos.
- Cada bug corregido gana una prueba que lo reproduce.
- La cobertura es una señal, no un objetivo: 80 % con buenas aserciones vale más que 100 % sin ellas.

## Revisión de código
- PR pequeños (menos de ~400 líneas) y con una sola intención.
- Quien revisa busca: corrección, casos borde, seguridad, legibilidad y pruebas.
- Automatiza todo lo automatizable (formato, lint, pruebas, `repocheckup`) para que la revisión humana se concentre en el diseño.

Referencias: *Clean Code* (R. Martin) · *Refactoring* (M. Fowler) · Google Engineering Practices.
