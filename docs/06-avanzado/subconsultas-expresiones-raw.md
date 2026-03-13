# Subconsultas y Expresiones RAW Seguras

Cómo integrar SQL específico manteniendo seguridad y legibilidad.

## ✅ Prerrequisitos
- Dominio de [Query Builder](../04-query-builder/README.md)
- Conocer operaciones batch básicas para integrar transformaciones (ver [Operaciones Batch Avanzadas](batch-operaciones-avanzado.md))
- Familiaridad con manejo de errores ([Errores y Logging](errores-logging.md))

> Este capítulo es el puente entre la abstracción y la flexibilidad total del SQL.

## Cuándo Usar
- Filtros que el builder aún no abstrae.
- Window functions / CTE temporales.
- Agregaciones avanzadas o ranking.

## Principios
| Regla | Razón |
|-------|-------|
| Placeholders `?` para valores | Previene inyección |
| Separar SQL y datos | Revisión más fácil |
| Encapsular en helpers | Reuso y testabilidad |

## Subconsulta en WHERE
```php
$sql = "SELECT * FROM users WHERE id IN (SELECT user_id FROM posts WHERE created_at > ?)";
$rows = $orm->raw($sql, ['2025-01-01 00:00:00']);
```
**SQL Equivalente:**
```sql
SELECT * FROM users WHERE id IN (SELECT user_id FROM posts WHERE created_at > '2025-01-01 00:00:00');
```

## Expresión Calculada
```php
$rows = $orm->raw(
  "SELECT id, (views / NULLIF(days_active,0)) AS views_per_day FROM stats WHERE days_active > ?",
  [0]
);
```
**SQL Equivalente:**
```sql
SELECT id, (views / NULLIF(days_active,0)) AS views_per_day FROM stats WHERE days_active > 0;
```

## CTE (si la base lo soporta)
```php
$cte = <<<SQL
WITH recent AS (
  SELECT id, created_at FROM users ORDER BY created_at DESC LIMIT 100
)
SELECT * FROM recent ORDER BY created_at;
SQL;
$data = $orm->raw($cte);
```
**SQL Equivalente:**
```sql
WITH recent AS (
  SELECT id, created_at FROM users ORDER BY created_at DESC LIMIT 100
)
SELECT * FROM recent ORDER BY created_at;
```

## Helper Reutilizable
```php
function activeUsersSince($orm, string $date): array {
  $sql = "SELECT * FROM users WHERE last_login >= ?";
  return $orm->raw($sql, [$date]);
}
```
**SQL Equivalente:**
```sql
SELECT * FROM users WHERE last_login >= '2025-01-01';
```

## Combinando con Batch
Puedes preparar datos intermedios con subconsultas y luego ejecutar `insertMany` sobre resultados transformados.
**Tip para principiantes:** Puedes usar subconsultas para filtrar datos y luego insertarlos en otra tabla usando `insertMany`, igual que harías con SQL puro pero con mayor seguridad.

## Errores Comunes
| Problema | Causa | Solución |
|----------|-------|----------|
| Inyección potencial | Concatenar valores en el SQL | Usar placeholders |
| Rendimiento pobre | Subconsulta no indexada | Añadir índice / reescribir join |
| Ambigüedad de columnas | Falta alias | Alias claros `u.id` |

## Checklist RAW
- [ ] Placeholders para todos los valores dinámicos
- [ ] Alias consistentes
- [ ] Helpers para SQL repetido
- [ ] Revisado en tests (resultado y tiempo)
- [ ] Comentarios opcionales en SQL complejo
**Tip para principiantes:** Siempre revisa que tus consultas RAW usen placeholders (`?`) para evitar inyección SQL y prueba los resultados en tu entorno antes de usarlos en producción.

## ➡️ Próximos Pasos
- Optimizar pipeline: [Arquitectura y Flujo Interno](arquitectura-flujo-interno.md)
- Medir impacto: [Métricas](observabilidad/metricas.md)
- Asegurar consistencia de tipos: [Tipado y Validación Avanzada](tipado-validacion-avanzado.md)
