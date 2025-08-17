# 15. Métricas y Observabilidad

VersaORM incluye un conjunto ligero de métricas internas cuando se utiliza el motor **PDO**. Estas métricas permiten inspeccionar rápidamente el comportamiento del ORM en pruebas, entornos de staging o durante diagnósticos de rendimiento.

> Nota: Por ahora las métricas sólo están disponibles para el motor `pdo`. El motor Rust tendrá un mapa de métricas extendido en futuras versiones.

## 1. Acceso a las métricas

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

## 2. Campos disponibles

| Métrica | Descripción |
|---------|-------------|
| `queries` | Número de consultas ejecutadas realmente contra la base de datos (lecturas + escrituras). |
| `writes` | Sub–conjunto de `queries` que corresponden a operaciones de modificación (INSERT / UPDATE / DELETE / UPSERT / REPLACE). |
| `transactions` | Conteo de transacciones iniciadas (`BEGIN`); incrementará cuando se añada instrumentación explícita. |
| `cache_hits` | Número de lecturas servidas desde la caché interna de consultas. |
| `cache_misses` | Lecturas que no estaban en caché (se ejecutó la consulta). |
| `last_query_ms` | Duración (ms) de la última consulta ejecutada. |
| `total_query_ms` | Acumulado de tiempo (ms) empleado en todas las consultas registradas. |

## 3. Qué operaciones incrementan cada contador

- `queries`: cualquier ejecución SQL (SELECT, COUNT, EXISTS, INSERT, UPDATE, DELETE, etc.) que llega al motor.
- `writes`: sólo cuando la operación es de escritura (`insert`, `insertGetId`, `update`, `delete`, operaciones batch o upserts).
- `cache_hits` / `cache_misses`: sólo para métodos de lectura cacheables (`get`, `first`, `exists`, `count`). Si la caché está deshabilitada (`VersaORM::cache('disable')`), los misses no se contabilizan como hits.
- `last_query_ms` y `total_query_ms`: se miden con microtime antes/después de ejecutar la consulta.

## 4. Ejemplo práctico

```php
$orm->cache('enable');

// Primera lectura: miss
$orm->table('users')->count();
// Segunda lectura idéntica: hit
$orm->table('users')->count();
// Escritura
$orm->table('users')->insert(['name' => 'Nuevo']);

print_r($orm->metrics());
```

Posible resultado:
```
Array (
  [queries] => 3
  [writes] => 1
  [transactions] => 0
  [cache_hits] => 1
  [cache_misses] => 1
  [last_query_ms] => 0.52
  [total_query_ms] => 5.31
)
```

## 5. Buenas prácticas de uso

- Úsalas en tests de regresión de rendimiento o como señal temprana de explosión de consultas (N+1).
- No las interpretes como métricas exhaustivas de latencia (no incluyen preparación previa ni posibles latencias de red fuera de la ejecución del `PDOStatement`).
- Para producción considera integrar un sistema externo (Prometheus / OpenTelemetry) exponiendo estas métricas vía HTTP o logs estructurados.

## 6. Reset / Reinicio (futuro)

Actualmente las métricas se reinician sólo al inicializar el proceso PHP. Se planea exponer un método público para hacer reset manual (`metricsReset()`), mantente atento al CHANGELOG.

## 7. Extensión planeada

Próximas mejoras consideradas:
- Métricas por tipo de operación (selects vs counts vs first).
- Distribución (p95/p99) de tiempos de consulta.
- Conteo de fallos y tipos de error.
- Métricas para transacciones (BEGIN / COMMIT / ROLLBACK) ya contabilizadas en `transactions`.
- Integración con el núcleo Rust para recopilación unificada.

## 8. Preguntas frecuentes

**¿Afectan el rendimiento?** El overhead es muy bajo (microtime y contadores en memoria). Sólo medirás un impacto apreciable en loops masivos (>100k) en entornos muy restringidos.

**¿Se incluyen las consultas servidas desde caché en `queries`?** No, los `cache_hits` no incre­mentan `queries` porque no se fue a la base real.

**¿Por qué `transactions` está en 0?** La instrumentación de BEGIN/COMMIT se añadirá en una iteración posterior; por ahora se reserva el campo.

---
Con esto puedes monitorear de forma ligera el comportamiento de tu aplicación durante el desarrollo.
