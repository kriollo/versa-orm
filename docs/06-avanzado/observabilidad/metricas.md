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
| writes | Subconjunto de queries que modifican datos |
  Salida típica (campos básicos):
| cache_hits | Lecturas servidas desde caché interna |
| cache_misses | Lecturas que fueron a DB |
| last_query_ms | Duración en ms de la última consulta |
| total_query_ms | Suma de duraciones acumuladas |

## Incrementos
- queries: cada ejecución SQL real.
- writes: insert/insertGetId/update/delete, batch, upsert/replace.
- cache_hits / cache_misses: solo operaciones cacheables (`getAll`, `firstArray`, `count`, `exists`).
- last_query_ms / total_query_ms: medido con microtime alrededor de la ejecución.

  Al activarse más instrumentación verás también:
  ```php
  Array (
    ...
    [stmt_cache_hits] => 30
    [stmt_cache_misses] => 5
    [total_prepare_ms] => 12.31
    [hydration_ms] => 4.12
    [objects_hydrated] => 250
    [hydration_fastpath_uses] => 3
    [hydration_fastpath_rows] => 180
    [hydration_fastpath_ms] => 0.95
  )
  ```
## Ejemplo con Caché
```php
$orm->cache('enable');
$orm->table('users')->count();    // miss
$orm->table('users')->count();    // hit
$orm->table('users')->insert(['name' => 'Nuevo']);
print_r($orm->metrics());
```
**SQL Equivalente emitido:**
```sql
  | stmt_cache_hits | Reutilizaciones de sentencias preparadas cacheadas |
  | stmt_cache_misses | Preparaciones nuevas (se intentó cache pero no existía) |
  | total_prepare_ms | Tiempo acumulado preparando sentencias (optimiza con statement cache) |
  | hydration_ms | Tiempo total construyendo arrays/objetos de resultados |
  | objects_hydrated | Número de objetos (VersaModel) instanciados |
  | hydration_fastpath_uses | Veces que se aplicó ruta rápida (hidratación simplificada sin reflexión) |
  | hydration_fastpath_rows | Filas beneficiadas por fast-path |
  | hydration_fastpath_ms | Tiempo empleado en fast-path (incluido en hydration_ms) |
SELECT COUNT(*) AS aggregate FROM users; -- primera (miss)
  - stmt_cache_hits/misses: cuando la misma cadena SQL + shape de bindings reutiliza `PDOStatement`.
  - hydration_*: envuelven el coste de mapear filas a arrays/objetos; fast-path se activa cuando no hay casting complejo ni relaciones eager.
## Buenas Prácticas
- Úsalas en tests de regresión o smoke de performance.
- No sustituyen APM de producción (usa Prometheus / OTEL si necesitas series temporales).
- Vigila saltos bruscos de queries para detectar N+1 en relaciones.

## Limitaciones Actuales
- Reset manual de métricas aún no expuesto.
- transactions aún puede permanecer en 0 (instrumentación parcial).
  // Si repites identica consulta con diferentes binds, stmt_cache_hits también crece
  ```
  **SQL Equivalente emitido (solo primer count):**
  ```sql
  SELECT COUNT(*) AS aggregate FROM users; -- primera ejecución
  -- segunda: cache interno (no SQL)
- Sin percentiles (p95/p99) todavía.
  Inserción posterior (ejemplo writes + invalidación selectivo):
  ```php
  $orm->table('users')->insert(['name' => 'Nuevo']);
  ```
  **SQL Equivalente:**
  ```sql
  INSERT INTO users (name) VALUES ('Nuevo');
  ```
## FAQ Rápido
  ## Reset y Configuración
  Puedes reiniciar contadores para delimitar una ventana de medición:
  ```php
  $orm->metricsReset(); // reinicia todos los contadores a 0
  ```
  **SQL Equivalente:**
  ```sql
  -- No se ejecuta SQL; operación en memoria.
  ```

  Configura límite de caché de sentencias (por defecto 100, máximo recomendado < 5000):
  ```php
  $config = [
    'driver' => 'mysql',
    'statement_cache_limit' => 300,
    // ... resto
  ];
  $orm = new VersaORM($config);
  ```
  **SQL Equivalente:**
  ```sql
  -- No aplica. Afecta sólo a reutilización interna de PDOStatement.
  ```

  ## Limitaciones Actuales
  - transactions puede permanecer en 0 si tu flujo no ejecuta BEGIN explícitos.
  - No hay percentiles (p95/p99) ni histogramas todavía.
  - Métricas no persistidas: se pierden si recreas instancia.

**¿Puedo extender?** Envuelve `$orm->metrics()` y exporta por HTTP / logs.

  ## Ejemplo: Perfilando un Bloque
  ```php
  $orm->metricsReset();
  $users = $orm->table('users')->where('active','=',true)->limit(50)->get();
  $m = $orm->metrics();
  printf(
    "Queries=%d cache_hits=%d stmt_cache_hits=%d hydration_ms=%.3f\n",
    $m['queries'],$m['cache_hits'],$m['stmt_cache_hits'],$m['hydration_ms']
  );
  ```
  **SQL Equivalente (consulta principal):**
  ```sql
  SELECT * FROM users WHERE active = 1 LIMIT 50;
  ```

  ## ➡️ Próximos Pasos
  - Aplicar optimizaciones: [Caché Interna](../cache-interna.md)
  - Mitigar N+1: [Lazy y N+1](../lazy-n+1.md)
  - Profundizar en cambios de esquema seguros: [DDL / Freeze](../ddl-freeze-migraciones.md)
- Profundizar en cambios de esquema seguros: [DDL / Freeze](../ddl-freeze-migraciones.md)
