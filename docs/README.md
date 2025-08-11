# 📚 Documentación de VersaORM

Bienvenido. Aquí tienes todo lo necesario para usar VersaORM desde cero hasta nivel avanzado, en orden lógico: primero lo básico, luego lo intermedio y finalmente lo avanzado.

## 1) Empieza aquí: Primeros pasos
- [Instalación](getting-started/installation.md)
- [Configuración](getting-started/configuration.md)
- [Resumen de primeros pasos](getting-started/README.md)

## 2) Uso diario (lo esencial)
- [Uso Básico (CRUD)](user-guide/01-basic-usage.md)
- [Query Builder (selección, filtros, joins, orden, paginación)](user-guide/02-query-builder.md)
- [Modelos y Objetos (VersaModel, relaciones, scopes)](user-guide/03-models-and-objects.md)
- [Query Builder - Ejemplos Rápidos](user-guide/12-query-builder-quick-examples.md)

## 3) Productividad y seguridad
- [Validación y Mass Assignment](user-guide/05-validation-mass-assignment.md)
- [🎯 Tipado Fuerte y Validación de Esquemas](user-guide/06-strong-typing-schema-validation.md)
- [🔒 Modo Freeze - Protección de Esquema](user-guide/07-freeze-mode.md)

## 4) Operaciones avanzadas
- [🚀 Operaciones de Lote (insertMany, updateMany, deleteMany)](user-guide/03-batch-operations.md)
- [🔄 UPSERT y REPLACE INTO](user-guide/11-upsert-replace-operations.md)
- [⚡ Modo Lazy y Planificador de Consultas](user-guide/10-lazy-mode-query-planner.md)
- [🚀 Funcionalidades SQL Avanzadas](user-guide/13-advanced-sql-features.md)
- [🗂️ Características Específicas del Motor](user-guide/11-database-specific-features.md)
- [Subconsultas y Expresiones Raw](user-guide/04-subqueries-raw-expressions.md)

## 5) Herramientas y CLI
- [Herramienta de Línea de Comandos (CLI)](user-guide/04-cli-tool.md)

## 6) Contribuir al proyecto
- [Arquitectura del Proyecto](contributor-guide/01-architecture.md)
- [Configuración del Entorno de Desarrollo](contributor-guide/02-development-setup.md)
- [Estándares de Código](contributor-guide/03-coding-standards.md)

---

VersaORM te permite trabajar con tu base de datos usando PHP claro y seguro. Actualmente esta documentación prioriza el **Modo PHP / PDO** (sin núcleo nativo) mientras el binario se estabiliza. Para un resumen práctico de este modo visita: [Modo PHP / PDO](../pdo-mode/README.md).

Si es tu primera vez, sigue la ruta 1 → 2 → 3. Si ya lo usas a diario, guarda 2 y 4 como referencia.
