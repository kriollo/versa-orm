# Guía de Uso

Aprende VersaORM paso a paso. Te recomendamos leer en este orden:

## 1) Lo esencial
- [Uso Básico (CRUD)](01-basic-usage.md)
- [Guía del Query Builder](02-query-builder.md)
- [Guía de Modelos y Objetos](03-models-and-objects.md)
- [⚙️ Query Builder - Ejemplos Rápidos](12-query-builder-quick-examples.md)

## 2) Seguridad y calidad
- [Validación y Mass Assignment](05-validation-mass-assignment.md)
- [🎯 Tipado Fuerte y Validación de Esquemas](06-strong-typing-schema-validation.md)
- [🔒 Modo Freeze - Protección de Esquema](07-freeze-mode.md)

## 3) Potencia y rendimiento
- [🚀 Operaciones de Lote (Batch)](03-batch-operations.md)
- [🔄 UPSERT y REPLACE INTO](11-upsert-replace-operations.md)
- [⚡ Modo Lazy y Planificador de Consultas](10-lazy-mode-query-planner.md)
- [🚀 Funcionalidades SQL Avanzadas](13-advanced-sql-features.md)
- [🗂️ Características Específicas del Motor](11-database-specific-features.md)
- [Subconsultas y Expresiones Raw](04-subqueries-raw-expressions.md)

## 4) Herramientas
- [Guía de la Herramienta CLI](04-cli-tool.md)

## 5) Arquitectura y Ciclo de Vida
- [Arquitecturas y Ciclo de Vida de Conexión](16-architectures-and-lifecycles.md)

La nueva guía cubre:
- Integración en MVC, frameworks (Laravel, Symfony, Slim, etc.)
- Uso estático vs inyectado
- Ciclo de vida en PHP-FPM, Swoole/RoadRunner, CLI y workers
- Fast-path de hidratación y métricas (`$orm->metrics()`, `$orm->metricsReset()`)
- Desconexión explícita (`$orm->disconnect()`) para procesos persistentes

## 🆕 Novedades destacadas
- **[UPSERT Individual](11-upsert-replace-operations.md#operación-upsert-individual)**
- **[REPLACE INTO (MySQL)](11-upsert-replace-operations.md#operación-replace-into-solo-mysql)**
- **[Operaciones Batch Masivas](03-batch-operations.md)**
