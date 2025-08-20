# Operaciones Batch Avanzadas

Las operaciones batch maximizan el throughput reduciendo roundtrips y coste de parseo.

## ✅ Prerrequisitos
- Dominio de [CRUD Básico](../03-basico/crud-basico.md)
- Familiaridad con [Query Builder](../04-query-builder/README.md)
- Conocer inserciones múltiples con `storeAll()` (visto en CRUD)

> Venido de CRUD: aquí aprendes a escalar inserciones/actualizaciones a grandes volúmenes manteniendo seguridad.

## Resumen Rápido
| Método | Propósito | Devuelve |
|--------|----------|----------|
| insertMany($tabla, $filas) | Inserción masiva | array: ['total_inserted'=>int, 'inserted_ids'=>array|null] |
| updateMany($tabla, $filas, $pk='id') | Actualizaciones múltiples por PK | array: ['affected'=>int] |
| deleteMany($tabla, $ids, $pk='id') | Borrado múltiple por PK | array: ['affected'=>int] |
| upsertMany($tabla, $filas, $uniqueCols) | Insert o update atómico | array: ['affected'=>int] |
| VersaModel::storeAll($modelos) | Persistir lote de modelos nuevos | array de IDs (o nulls) |

## insertMany
```php
$rows = [
  ['name' => 'A', 'email' => 'a@x'],
  ['name' => 'B', 'email' => 'b@x'],
];
$result = $orm->table('users')->insertMany($rows);
// $result['total_inserted'] === 2
// $result['inserted_ids'] puede existir (MySQL/SQLite inferido, PostgreSQL parcial)
// Tip: Si usas batchSize grande, puedes procesar miles de filas en segundos.
```
**SQL Equivalente:**
```sql
INSERT INTO users (name, email) VALUES
  ('A','a@x'),
  ('B','b@x');
```
Notas:
- Columnas ausentes usan DEFAULT / NULL.
- `inserted_ids`: inferido secuencialmente cuando el motor lo permite (MySQL auto_increment + última ID, SQLite rowid). PostgreSQL puede requerir `RETURNING` para precisión total (no implementado todavía aquí).

**Retorno:**
```php
// $result = ['total_inserted' => int, 'inserted_ids' => array|null]
```

### Heurística de `inserted_ids`
```php
$rows = [
  ['name' => 'C'],
  ['name' => 'D'],
  ['name' => 'E'],
];
$r = $orm->table('users')->insertMany($rows);
if (isset($r['inserted_ids'])) {
  // Mapeo directo
  foreach ($r['inserted_ids'] as $id) {
    echo "Nuevo ID: $id\n";
  }
}
```
**SQL Equivalente (única sentencia multi-row):**
```sql
INSERT INTO users (name) VALUES ('C'),('D'),('E');
-- MySQL: last_insert_id() interno devuelve ID de 'E'; se infiere rango continuo.
-- SQLite: rowid autoincremental similar (rango continuo).
-- PostgreSQL: sin RETURNING no se garantiza inferencia (campo puede omitirse o quedar null).
```
Precauciones:
- No asumas continuidad si existe trigger que inserta en otra tabla con su propio autoincrement.
- Para auditoría estricta en PostgreSQL, preferir inserciones individuales por ahora o implementar variante con RETURNING.

**Tip para principiantes:** Si necesitas los IDs generados, revisa siempre el campo `inserted_ids` en el resultado.

## updateMany
```php
$affected = $orm->table('users')
  ->where('id', 'IN', [10, 11])
  ->updateMany(['name' => 'Neo', 'email' => 'trinity@matrix']);
// $affected['affected'] === número de filas actualizadas
```
**SQL Equivalente:**
```sql
UPDATE users SET name = 'Neo', email = 'trinity@matrix' WHERE id IN (10,11);
```
Reglas:
- Debes usar WHERE para evitar actualizaciones masivas accidentales.
- Sólo columnas presentes se actualizan (parcial).

**Tip para principiantes:** Siempre usa condiciones WHERE para evitar modificar todos los registros por error.

## deleteMany
```php
$deleted = $orm->table('users')
  ->where('id', 'IN', [10, 11, 12])
  ->deleteMany();
// $deleted['affected'] === número de filas borradas
```
**SQL Equivalente:**
```sql
DELETE FROM users WHERE id IN (10,11,12);
```
Construye un `DELETE ... WHERE id IN (...)` optimizado.

**Tip para principiantes:** Siempre verifica el número de filas borradas en el resultado para confirmar la operación.

## upsertMany
```php
$rows = [
  ['email' => 'a@x', 'name' => 'A1'],
  ['email' => 'b@x', 'name' => 'B1']
];
$affected = $orm->table('users')->upsertMany($rows, ['email']);
// $affected['affected'] === filas insertadas + actualizadas
// Retorno: array ['affected' => int] - Número total de filas afectadas (insertadas + actualizadas).
// Tip: Para lotes grandes, upsertMany es mucho más rápido que bucles individuales.
```
**SQL Equivalente (MySQL):**
```sql
INSERT INTO users (email,name) VALUES
  ('a@x','A1'),
  ('b@x','B1')
ON DUPLICATE KEY UPDATE name = VALUES(name);
```
**SQL Equivalente (PostgreSQL / SQLite):**
```sql
INSERT INTO users (email,name) VALUES
  ('a@x','A1'),
  ('b@x','B1')
ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name;
```
### Actualizaciones Condicionales Múltiples
```php
$rows = [
  ['email' => 'c@x', 'name' => 'C1', 'active' => true],
  ['email' => 'd@x', 'name' => 'D1', 'active' => false],
];
$res = $orm->table('users')->upsertMany($rows, ['email']);
echo $res['affected']; // filas insertadas + actualizadas
```
**SQL Equivalente (MySQL):**
```sql
INSERT INTO users (email,name,active) VALUES
  ('c@x','C1',1),
  ('d@x','D1',0)
ON DUPLICATE KEY UPDATE
  name = VALUES(name),
  active = VALUES(active);
```
**SQL Equivalente (PostgreSQL/SQLite):**
```sql
INSERT INTO users (email,name,active) VALUES
  ('c@x','C1',TRUE),
  ('d@x','D1',FALSE)
ON CONFLICT (email) DO UPDATE SET
  name = EXCLUDED.name,
  active = EXCLUDED.active;
```

## VersaModel::storeAll
Optimiza múltiples modelos nuevos de la MISMA tabla.
```php
$u1 = VersaModel::dispense('users');
$u1->name = 'A';
$u2 = VersaModel::dispense('users');
$u2->name = 'B';
$ids = VersaModel::storeAll([$u1,$u2]);
// $ids = [idA, idB]
// Retorno: array de IDs (int|string|null) en el mismo orden que los modelos
// Tip: Si algún modelo ya tiene PK, se usará inserción individual para ese modelo. Si todos son nuevos y de la misma tabla, se usa batch optimizado.
// Tip: Si algún modelo ya tiene PK, se usará inserción individual para ese modelo.
```
**SQL Equivalente:**
```sql
INSERT INTO users (name) VALUES ('A'),('B');
```
Condiciones para modo batch optimizado:
1. Todos sin PK asignada.
2. Misma tabla.
Si no se cumplen, recurre a inserciones individuales.

**Retorno:**
```php
// array de IDs (int|string|null) en el mismo orden que los modelos
```

## Estrategias de Rendimiento
- Agrupa por tamaño (50-500 filas) para evitar paquetes SQL enormes.
- Normaliza claves: asegúrate que todas las filas tienen el mismo subconjunto de columnas para evitar rellenos innecesarios.
- Usa transacciones manuales si combinas múltiples batches heterogéneos.

**Tip para principiantes:** Si tienes dudas sobre el tamaño óptimo del batch, comienza con 100 y ajusta según el rendimiento observado.

## Errores Comunes
| Problema | Causa | Mitigación |
|----------|-------|------------|
| IDs desalineados | Fallback heurístico en PostgreSQL | Implementar RETURNING (roadmap) |
| Columnas faltantes | Tipos no-null sin DEFAULT | Añadir columnas o defaults |
| Unique violation | Datos duplicados en upsertMany con set conflictivo | Revisa `uniqueCols` |

**Tip para principiantes:** Si recibes un error de "unique violation", revisa que los datos no estén duplicados en las columnas únicas.

## Buenas Prácticas
- Valida previamente (longitud, formato) antes del batch para reducir rollbacks.
- Registra latencia y tamaño (filas) en logs para tunear chunk size.
- Combina con caché: invalida claves afectadas tras operaciones de escritura masiva.

**Tip para principiantes:** Siempre valida tus datos antes de ejecutar operaciones batch para evitar errores y rollbacks innecesarios.

## Roadmap
- Soporte preciso de `inserted_ids` en PostgreSQL vía `RETURNING`.
- Batch mixto (insert + update) evaluado para futuro.
- Paralelización segura por partición de clave.

## ➡️ Próximos Pasos
- Reforzar observabilidad: [Métricas](observabilidad/metricas.md)
- Optimizar consultas derivadas: [Lazy y N+1](lazy-n+1.md)
- Afinar consistencia de datos: [Tipado y Validación Avanzada](tipado-validacion-avanzado.md)
