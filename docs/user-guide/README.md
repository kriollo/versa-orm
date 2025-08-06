# Guía de Uso

En esta sección aprenderás a usar todas las características de VersaORM para interactuar con tu base de datos de forma segura y eficiente.

## 📚 Guías de Funcionalidades

- [Uso Básico (CRUD)](01-basic-usage.md)
- [Guía del Query Builder](02-query-builder.md)
- [🚀 Query Builder - Ejemplos Rápidos](12-query-builder-quick-examples.md)
- [🚀 Operaciones de Lote (Batch)](03-batch-operations.md)
- [Guía de Modelos y Objetos](03-models-and-objects.md)
- [Guía de la Herramienta CLI](04-cli-tool.md)
- [Subconsultas y Expresiones Raw](04-subqueries-raw-expressions.md)
- [Validación y Mass Assignment](05-validation-mass-assignment.md)
- [🎯 Tipado Fuerte y Validación de Esquemas](06-strong-typing-schema-validation.md)
- [🔒 Modo Freeze - Protección de Esquema](07-freeze-mode.md)
- [🏢 Ejemplo Práctico: Modo Freeze en Producción](08-freeze-mode-example.md)
- [Tipos de Datos Avanzados](09-advanced-data-types.md)
- [⚡ Modo Lazy y Planificador de Consultas](10-lazy-mode-query-planner.md)
- [🔄 Operaciones UPSERT y REPLACE INTO](11-upsert-replace-operations.md)

## 🆕 Nuevas Funcionalidades

### Operaciones Avanzadas de Inserción/Actualización
- **[UPSERT Individual](11-upsert-replace-operations.md#operación-upsert-individual)**: Inserción inteligente que actualiza si existe o inserta si es nuevo
- **[REPLACE INTO](11-upsert-replace-operations.md#operación-replace-into-solo-mysql)**: Reemplazo completo de registros (MySQL)
- **[Operaciones Batch Masivas](03-batch-operations.md)**: `upsertMany()` y `replaceIntoMany()` para grandes volúmenes
