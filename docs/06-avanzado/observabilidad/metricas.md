# Métricas y Observabilidad

VersaORM-PHP expone métricas ligeras (motor `pdo`) útiles para diagnosticar rendimiento y detectar patrones (N+1, cache hits, etc.).

## ✅ Prerrequisitos
- Haber usado operaciones CRUD básicas
- Conocer patrones N+1 (ver [Lazy y N+1](../lazy-n+1.md))
- Uso opcional de [Caché Interna](../cache-interna.md)

## Acceso Básico
```php
$metrics = $orm->metrics();
print_r($metrics);
```
Salida típica:
```php
Array (
  [queries] => 42
  [writes] => 10
  [transactions] => 0
  [cache_hits] => 5
  [cache_misses] => 12
  [last_query_ms] => 0.78
  [total_query_ms] => 123.44
)
```
## Campos
| Métrica | Descripción |
|---------|-------------|
| queries | Consultas reales ejecutadas (lecturas + escrituras) |
| writes | Subconjunto de queries que modifican datos |
| transactions | BEGIN ejecutados (instrumentación futura) |
| cache_hits | Lecturas servidas desde caché interna |
| cache_misses | Lecturas que fueron a DB |
| last_query_ms | Duración en ms de la última consulta |
| total_query_ms | Suma de duraciones acumuladas |

## Incrementos
- queries: cada ejecución SQL real.
- writes: insert/insertGetId/update/delete, batch, upsert/replace.
- cache_hits / cache_misses: solo operaciones cacheables (`getAll`, `firstArray`, `count`, `exists`).
- last_query_ms / total_query_ms: medido con microtime alrededor de la ejecución.

## Ejemplo con Caché
```php
$orm->cache('enable');
$orm->table('users')->count();    // miss
$orm->table('users')->count();    // hit
$orm->table('users')->insert(['name' => 'Nuevo']);
print_r($orm->metrics());
```

## Buenas Prácticas
- Úsalas en tests de regresión o smoke de performance.
- No sustituyen APM de producción (usa Prometheus / OTEL si necesitas series temporales).
- Vigila saltos bruscos de queries para detectar N+1 en relaciones.

## Limitaciones Actuales
- Reset manual de métricas aún no expuesto.
- transactions aún puede permanecer en 0 (instrumentación parcial).
- Sin percentiles (p95/p99) todavía.

## Roadmap (Resumen)
- Métricas por tipo de consulta.
- Percentiles y histogramas.
- Conteo de errores y tipos.

## FAQ Rápido
**¿Impacto en rendimiento?** Muy bajo (contadores + microtime).

**¿cache_hits suma a queries?** No, sólo cache_misses incrementa queries.

**¿Puedo extender?** Envuelve `$orm->metrics()` y exporta por HTTP / logs.

## ➡️ Próximos Pasos
- Aplicar optimizaciones: [Caché Interna](../cache-interna.md)
- Mitigar N+1: [Lazy y N+1](../lazy-n+1.md)
- Profundizar en cambios de esquema seguros: [DDL / Freeze](../ddl-freeze-migraciones.md)
