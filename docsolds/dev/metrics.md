# Métricas Internas de VersaORM (Motor PDO)

Este documento describe las métricas expuestas vía `$orm->metrics()` cuando el motor activo es `pdo`.

## Lista de Métricas

| Métrica | Tipo | Descripción | Unidad |
|---------|------|-------------|--------|
| queries | int | Número de consultas ejecutadas realmente contra la BD (lecturas y escrituras) | count |
| writes | int | Sub-conjunto de `queries` que son operaciones de escritura (INSERT/UPDATE/DELETE/UPSERT) | count |
| transactions | int | BEGIN ejecutados | count |
| cache_hits | int | Hits de la caché de resultados de consulta (query cache interna) | count |
| cache_misses | int | Misses de la caché de resultados | count |
| last_query_ms | float | Tiempo en ms de la última consulta ejecutada (solo ronda DB) | ms |
| total_query_ms | float | Suma acumulada de ms en ejecución de consultas | ms |
| stmt_cache_hits | int | Hits en la caché LRU de sentencias preparadas | count |
| stmt_cache_misses | int | Misses en la caché de sentencias | count |
| total_prepare_ms | float | Tiempo acumulado preparando sentencias (excluye ejecuciones) | ms |
| hydration_ms | float | Tiempo acumulado de hidratación de objetos (camino estándar) | ms |
| objects_hydrated | int | Número total de instancias de modelos hidratadas | count |
| hydration_fastpath_uses | int | Veces que se invocó el fast-path de hidratación | count |
| hydration_fastpath_rows | int | Filas hidratadas mediante fast-path | count |
| hydration_fastpath_ms | float | Tiempo acumulado invertido en fast-path | ms |

## Fast-Path de Hidratación

Condiciones para activarse en `findAll()` / `findOne()` / `first()`:
- Sin relaciones eager (`with` vacío)
- Modelo base exacto `VersaModel` (no subclase)
- Select es `*` (o no se especifica select)
- Sin `groupBy` ni `having`

Si las condiciones no se cumplen, se recurre al camino estándar.

## Resetear Métricas

```php
$orm->metricsReset();
```
Limpia contadores y caches de sentencia. Útil en pruebas o benchmarks.

## Buenas Prácticas
- Usar `metricsReset()` antes de un benchmark para obtener cifras limpias.
- Observar la relación `stmt_cache_hits` vs `stmt_cache_misses` para ajustar `statement_cache_limit`.
- Revisar `hydration_fastpath_uses` y `hydration_fastpath_rows` para validar que el fast-path se está aprovechando en listados simples.

## Futuro
- Métricas de planificación (optimizer) y latencias separadas por etapa (planificación, binding, fetch) podrían añadirse.
- Exportación opcional a OpenTelemetry.
