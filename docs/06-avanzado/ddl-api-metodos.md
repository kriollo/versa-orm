# API DDL Programática en VersaORM-PHP

Resumen de métodos soportados para manipular esquema de forma portable (cuando no estás en freeze mode). Complementa la guía conceptual en [DDL, Migraciones y Freeze](ddl-freeze-migraciones.md).

## ✅ Prerrequisitos
- CRUD y batch básicos
- Comprender Freeze Mode
- Necesidad real de cambio de esquema automatizado

> Producción recomendada: aplicar migraciones con scripts SQL auditados; la API DDL es útil para prototipado, tooling interno o tests.

## Tabla Resumen
| Método | Propósito | Operaciones Soportadas | Respeta Freeze | Notas |
|--------|-----------|------------------------|----------------|-------|
| `schema('columns', $tabla)` | Inspección | Listado de columnas | ✅ | Devuelve metadatos (nombre, tipo, etc.) |
| `schema('indexes', $tabla)` | Inspección | Índices presentes | ✅ | Según driver |
| `schema('unique_keys', $tabla)` | Inspección | Uniques | ✅ | |
| `schemaCreate($tabla, $cols, $opts)` | Crear tabla | Columnas, PKs, uniques, FKs, índices | ❌ (bloquea) | Usa definiciones portables |
| `schemaAlter($tabla, $changes)` | Alterar tabla | add/rename/drop/modify col, índice, FK | ❌ | Cambios agrupados |
| `schemaDrop($tabla, $ifExists=true)` | Eliminar tabla | DROP TABLE | ❌ | Usa IF EXISTS por defecto |
| `schemaRename($from,$to)` | Renombrar tabla | RENAME / ALTER RENAME | ❌ | Dialecto-aware |

## Definición de Columnas (`schemaCreate`)
Ejemplo creación con PK, unique e índice:
```php
$orm->schemaCreate('users', [
  ['name' => 'id','type' => 'INT','primary' => true,'autoIncrement' => true],
  ['name' => 'email','type' => 'VARCHAR(255)','nullable' => false],
  ['name' => 'active','type' => 'BOOLEAN','default' => 1],
], [
  'if_not_exists' => true,
  'constraints' => [
    'unique' => [ ['name' => 'uq_users_email','columns' => ['email']] ],
  ],
  'indexes' => [ ['name' => 'idx_users_active','columns' => ['active']] ],
]);
```
**SQL Equivalente (MySQL / similar):**
```sql
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  active BOOLEAN DEFAULT 1,
  CONSTRAINT uq_users_email UNIQUE (email)
);
CREATE INDEX idx_users_active ON users(active);
```

## Alteraciones (`schemaAlter`)
Estructura general del array `$changes`:
```php
$changes = [
  'add' => [ ['name' => 'last_login','type' => 'DATETIME','nullable' => true] ],
  'addIndex' => [ ['name' => 'idx_users_last_login','columns' => ['last_login']] ],
  'rename' => [ ['from' => 'active','to' => 'is_active'] ],
  'modify' => [ ['name' => 'email','type' => 'VARCHAR(320)','nullable' => false] ],
  'drop' => ['legacy_flag'],
  'addForeign' => [ [
     'name' => 'fk_users_role','columns' => ['role_id'],
     'refTable' => 'roles','refColumns' => ['id'],
     'onDelete' => 'cascade','onUpdate' => 'cascade'
  ] ],
  'dropForeign' => ['fk_users_old'],
  'dropIndex' => ['idx_users_active']
];
$orm->schemaAlter('users', $changes);
```
**SQL Equivalente aproximado (según driver puede dividirse en múltiples sentencias):**
```sql
ALTER TABLE users ADD COLUMN last_login DATETIME NULL;
CREATE INDEX idx_users_last_login ON users(last_login);
ALTER TABLE users RENAME COLUMN active TO is_active;         -- PostgreSQL / SQLite; MySQL 8+ soporta RENAME COLUMN
ALTER TABLE users MODIFY COLUMN email VARCHAR(320) NOT NULL; -- MySQL
-- PostgreSQL: ALTER TABLE users ALTER COLUMN email TYPE VARCHAR(320); ALTER TABLE users ALTER COLUMN email SET NOT NULL;
ALTER TABLE users DROP COLUMN legacy_flag;
ALTER TABLE users ADD CONSTRAINT fk_users_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE users DROP FOREIGN KEY fk_users_old;             -- MySQL (PostgreSQL: DROP CONSTRAINT fk_users_old)
DROP INDEX idx_users_active ON users;                        -- PostgreSQL: DROP INDEX idx_users_active;
```

## Renombrar Tabla
```php
$orm->schemaRename('users_tmp','users');
```
Internamente usa `RENAME TABLE` (MySQL) o `ALTER TABLE ... RENAME TO` (PostgreSQL/SQLite).
**SQL Equivalente:**
```sql
RENAME TABLE users_tmp TO users;                 -- MySQL
ALTER TABLE users_tmp RENAME TO users;           -- PostgreSQL / SQLite
```

## Eliminar Tabla
```php
$orm->schemaDrop('temp_cache'); // IF EXISTS por defecto
```
**SQL Equivalente:**
```sql
DROP TABLE IF EXISTS temp_cache;
```

## Inspección de Columnas
```php
$cols = $orm->schema('columns','users');
foreach ($cols as $c) {
  echo $c['name'] . " (" . ($c['type'] ?? '?') . ")\n";
}
```
**SQL subyacente (varía por driver):**
```sql
-- MySQL
SHOW COLUMNS FROM users;
-- PostgreSQL
SELECT column_name, data_type, is_nullable FROM information_schema.columns WHERE table_name = 'users';
-- SQLite
PRAGMA table_info('users');
```

## Auto-Creación Implícita (Modelos)
Si freeze está desactivado y asignas un atributo inexistente antes de `store()`, el ORM puede:
1. Detectar tabla faltante y crear base `id`.
2. Inferir tipo y emitir `ALTER TABLE ADD COLUMN`.

Esto ocurre dentro de `VersaModel` (métodos privados `createBaseTableIfMissing` y `ensureColumnsExist`). Para entornos controlados se recomienda migraciones explícitas.
**SQL Equivalente (creación implícita + alter incremental):**
```sql
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT);
ALTER TABLE users ADD COLUMN extra_field VARCHAR(255) NULL;
```

## Buenas Prácticas
- Usa `if_not_exists` para evitar errores repetidos en tests.
- Agrupa cambios relacionados en un solo `schemaAlter`.
- Evita `modify` y `drop` críticos en caliente: preparar ventana de mantenimiento.
- Congela (`freeze`) en producción para impedir alteraciones accidentales.

## Checklist DDL API
- [ ] Freeze desactivado antes de crear/alterar
- [ ] Definiciones de columnas completas (tipo, nulabilidad, default)
- [ ] Uniques e índices con nombres consistentes
- [ ] Migración inversa (rollback) planificada
- [ ] Re-aplica tests de integridad tras cambios

## ➡️ Próximos Pasos
- Estrategia operacional: [DDL / Freeze / Migraciones](ddl-freeze-migraciones.md)
- Verificar impacto de cambios: [Métricas](observabilidad/metricas.md)
- Alinear tipos y casting: [Tipado y Validación Avanzada](tipado-validacion-avanzado.md)
