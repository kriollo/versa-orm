# Caché Interna de Lecturas

Mecanismo ligero para reducir roundtrips en operaciones idempotentes frecuentes.

## ✅ Prerrequisitos
- Haber practicado consultas básicas en [CRUD Básico](../03-basico/crud-basico.md)
- Conocer métricas básicas ([Métricas y Observabilidad](observabilidad/metricas.md))
- Haber leído sobre patrones anti N+1 ([Lazy y N+1](lazy-n+1.md)) para evitar cachear ineficiencias

## Qué Se Cachea
| Operación | Cacheable | Clave aproximada |
|-----------|-----------|------------------|
| `count()` | ✅ | `count:tabla:cond-hash` |
| `exists()` | ✅ | `exists:tabla:cond-hash` |
| Lecturas simples (algunos helpers) | ✅ | `sel:tabla:cond-hash` |
| `get()` general | ⚠️ (no por defecto) | — |
| Escrituras (`insert/update/delete`) | ❌ | — |

## Activación
```php
$orm->cache('enable');
$status = $orm->cache('status'); // array estado
```

## Ejemplo
```php
$orm->cache('enable');
$before = $orm->metrics();
$orm->table('users')->count(); // miss
$orm->table('users')->count(); // hit
$after = $orm->metrics();
// ($after['cache_hits'] - $before['cache_hits']) == 1
```
**SQL emitido realmente:**
```sql
SELECT COUNT(*) AS aggregate FROM users; -- solo la primera vez
```

## Invalidación
- Escrituras relevantes deberían invalidar claves asociadas (comportamiento evolutivo: confirma en tu versión si se refleja inmediatamente).
- Fallback manual:
```php
$orm->cache('clear');
```
**SQL en una escritura típica que provoca invalidación:**
```sql
INSERT INTO users (name, email) VALUES ('Ana', 'ana@example.com');
-- La siguiente consulta COUNT se recalcula tras invalidar:
SELECT COUNT(*) AS aggregate FROM users;
```

## Estrategias
| Estrategia | Uso |
|-----------|-----|
| Habilitar sólo en rutas de lectura | Evita incoherencias en flujos de escritura pesada |
| Limpiar tras lotes grandes | Asegura consistencia post `insertMany` |
| Medir hits/misses | Ajustar dónde realmente aporta |

## Limitaciones
- No TTL configurables aún.
- Granularidad por consulta (no por campo individual).
- No cachea joins complejos.

## Patrón de Envoltorio
```php
function cachedCount($orm, $table, $cond) {
  $orm->cache('enable');
  return $orm->table($table)->where(...$cond)->count();
}
```
**SQL Equivalente (primera invocación para una combinación de condición):**
```sql
SELECT COUNT(*) AS aggregate FROM <tabla> WHERE <condición traducida>;
```
En invocaciones subsecuentes con la misma condición no se emite SQL.

## Métricas Relacionadas
- `cache_hits` incrementa cuando una operación retorna desde memoria.
- Solo `cache_misses` incrementa `queries` reales.
```php
$orm->cache('enable');
$start = $orm->metrics();
$orm->table('users')->where('activo', true)->exists(); // miss
$orm->table('users')->where('activo', true)->exists(); // hit
$end = $orm->metrics();
```
**SQL Equivalente (solo primera vez):**
```sql
SELECT 1 FROM users WHERE activo = 1 LIMIT 1;
```

## Cuándo NO Usar
- Tras escrituras intensivas sin invalidación clara.
- Donde la latencia de DB ya es muy baja y la complejidad no compensa.
- Datos que cambian por segundo y requieren frescura absoluta.

## Checklist Caché
- [ ] Activada sólo cuando aporta
- [ ] Monitoreas ratio hits/misses
- [ ] Limpias después de grandes escrituras
- [ ] Evitas cachear datos de alta volatilidad
- [ ] Combinada con métricas para tuning

## ➡️ Próximos Pasos
- Combinar con [Operaciones Batch Avanzadas](batch-operaciones-avanzado.md) para menor latencia total.
- Ajustar invalidación tras escrituras críticas (ver [Errores y Logging](errores-logging.md)).
- Entender el pipeline completo en [Arquitectura y Flujo Interno](arquitectura-flujo-interno.md).
