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
| insertMany($tabla, $filas) | Inserción masiva | filas insertadas (int) + `inserted_ids` si disponible |
| updateMany($tabla, $filas, $pk='id') | Actualizaciones múltiples por PK | filas actualizadas |
| deleteMany($tabla, $ids, $pk='id') | Borrado múltiple por PK | filas borradas |
| upsertMany($tabla, $filas, $uniqueCols) | Insert o update atómico | filas afectadas |
| VersaModel::storeAll($modelos) | Persistir lote de modelos nuevos | array de IDs (o nulls) |

## insertMany
```php
$rows = [
  ['name' => 'A', 'email' => 'a@x'],
  ['name' => 'B', 'email' => 'b@x'],
];
$result = $orm->insertMany('users', $rows);
// $result['affected'] === 2
// $result['inserted_ids'] puede existir (MySQL/SQLite inferido, PostgreSQL parcial)
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

### Heurística de `inserted_ids`
```php
$rows = [
  ['name' => 'C'],
  ['name' => 'D'],
  ['name' => 'E'],
];
$r = $orm->insertMany('users',$rows);
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

## updateMany
```php
$updates = [
  ['id' => 10, 'name' => 'Neo'],
  ['id' => 11, 'email' => 'trinity@matrix']
];
$affected = $orm->updateMany('users', $updates)['affected'];
```
**SQL Equivalente (conceptual):**
```sql
UPDATE users SET name = 'Neo' WHERE id = 10;
UPDATE users SET email = 'trinity@matrix' WHERE id = 11;
```
Reglas:
- Cada fila DEBE incluir la PK.
- Sólo columnas presentes se actualizan (parcial).

## deleteMany
```php
$deleted = $orm->deleteMany('users', [10,11,12])['affected'];
```
**SQL Equivalente:**
```sql
DELETE FROM users WHERE id IN (10,11,12);
```
Construye un `DELETE ... WHERE id IN (...)` optimizado.

## upsertMany
```php
$rows = [
  ['email' => 'a@x', 'name' => 'A1'],
  ['email' => 'b@x', 'name' => 'B1']
];
$affected = $orm->upsertMany('users', $rows, ['email'])['affected'];
```
- MySQL: `ON DUPLICATE KEY UPDATE`.
- PostgreSQL: `ON CONFLICT (email) DO UPDATE`.
- SQLite: `INSERT INTO ... ON CONFLICT(email) DO UPDATE`.
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
$res = $orm->upsertMany('users',$rows,['email']);
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
// [idA, idB]
```
**SQL Equivalente:**
```sql
INSERT INTO users (name) VALUES ('A'),('B');
```
Condiciones para modo batch optimizado:
1. Todos sin PK asignada.
2. Misma tabla.
Si no se cumplen, recurre a inserciones individuales.

## Estrategias de Rendimiento
- Agrupa por tamaño (50-500 filas) para evitar paquetes SQL enormes.
- Normaliza claves: asegúrate que todas las filas tienen el mismo subconjunto de columnas para evitar rellenos innecesarios.
- Usa transacciones manuales si combinas múltiples batches heterogéneos.

## Errores Comunes
| Problema | Causa | Mitigación |
|----------|-------|------------|
| IDs desalineados | Fallback heurístico en PostgreSQL | Implementar RETURNING (roadmap) |
| Columnas faltantes | Tipos no-null sin DEFAULT | Añadir columnas o defaults |
| Unique violation | Datos duplicados en upsertMany con set conflictivo | Revisa `uniqueCols` |

## Buenas Prácticas
- Valida previamente (longitud, formato) antes del batch para reducir rollbacks.
- Registra latencia y tamaño (filas) en logs para tunear chunk size.
- Combina con caché: invalida claves afectadas tras operaciones de escritura masiva.

## Roadmap
- Soporte preciso de `inserted_ids` en PostgreSQL vía `RETURNING`.
- Batch mixto (insert + update) evaluado para futuro.
- Paralelización segura por partición de clave.

## ➡️ Próximos Pasos
- Reforzar observabilidad: [Métricas](observabilidad/metricas.md)
- Optimizar consultas derivadas: [Lazy y N+1](lazy-n+1.md)
- Afinar consistencia de datos: [Tipado y Validación Avanzada](tipado-validacion-avanzado.md)
