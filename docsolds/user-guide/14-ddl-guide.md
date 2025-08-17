# Guía de DDL y Esquema

Esta guía describe la API de DDL de VersaORM y la introspección de índices para flujos de migraciones agnósticos del driver.

## Crear tablas: `schemaCreate(table, columns, options)`

- columns: [{ name, type, nullable?, default?, primary?, autoIncrement? }]
- options:
  - primary_key: string|string[]
  - if_not_exists: bool
  - engine, charset, collation (MySQL)
  - constraints:
    - unique: [{ name, columns[] }]
    - foreign: [{ name, columns[], refTable, refColumns[], onDelete?, onUpdate? }]
  - indexes: [{ name, columns[], unique?, using?, where?, concurrently?, if_not_exists? }]

Notas:
- PK se puede definir por columna (primary: true) o a nivel de tabla (primary_key).
- `columns[]` en índices acepta strings o `{ raw: 'expresión' }` para expresiones (por ejemplo, JSONB/GIN/funciones).

### Ejemplo SQL vs VersaORM-PHP

SQL puro (MySQL):

```sql
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(191) NOT NULL,
  name VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY users_email_unique (email)
) ENGINE=InnoDB;
```

PHP (VersaORM-PHP):

```php
$orm->schemaCreate('users', [
  ['name'=>'id','type'=>'INT','primary'=>true,'autoIncrement'=>true,'nullable'=>false],
  ['name'=>'email','type'=>'VARCHAR(191)','nullable'=>false],
  ['name'=>'name','type'=>'VARCHAR(255)','nullable'=>false],
  ['name'=>'created_at','type'=>'TIMESTAMP','default'=>'CURRENT_TIMESTAMP'],
], [
  'engine' => 'InnoDB',
  'constraints' => [ 'unique' => [ ['name'=>'users_email_unique','columns'=>['email']] ] ],
]);
```

## Modificar tablas: `schemaAlter(table, changes)`

- changes:
  - add: columns[] (mismo formato que en create)
  - rename: [{ from, to }]
  - drop: [colName, ...]
  - modify: [{ name, type, nullable?, default? }]
  - addIndex: [indexDef, ...]
  - dropIndex: [indexName, ...]
  - addForeign: [foreignDef, ...]
  - dropForeign: [fkName, ...]

### Ejemplo SQL vs VersaORM-PHP

Renombrar, modificar y eliminar columnas (PostgreSQL):

```sql
-- SQL
ALTER TABLE users RENAME COLUMN name TO full_name;
ALTER TABLE users ALTER COLUMN full_name TYPE VARCHAR(300);
ALTER TABLE users ALTER COLUMN full_name SET NOT NULL;
ALTER TABLE users ALTER COLUMN full_name SET DEFAULT '';
ALTER TABLE users DROP COLUMN legacy;
```

```php
// VersaORM-PHP
$orm->schemaAlter('users', [
  'rename' => [ ['from'=>'name','to'=>'full_name'] ],
  'modify' => [ ['name'=>'full_name','type'=>'VARCHAR(300)','nullable'=>false,'default'=>''] ],
  'drop' => ['legacy'],
]);
```

Índice con expresión y parcial (PostgreSQL):

```sql
-- SQL
CREATE INDEX idx_users_email_lower ON users USING GIN (lower(email)) WHERE status = 'active';
```

```php
// VersaORM-PHP
$orm->schemaAlter('users', [
  'addIndex' => [ [
    'name' => 'idx_users_email_lower',
    'using' => 'GIN',
    'columns' => [ ['raw'=>'lower("email")'] ],
    'where' => "status = 'active'",
  ] ]
]);
```

## Eliminar/Renombrar tablas

- `schemaDrop(table, ifExists=true)`
- `schemaRename(from, to)`

## Introspección de esquema: `schema('tables'|'columns'|'indexes', table?)`

- `tables`: lista de nombres.
- `columns`: metadatos por columna (nombre, tipo, nullable, default, etc.).
- `indexes`: lista de índices por tabla (nombre, columna, unique). En SQLite no se listan columnas del índice (limitación de PRAGMA simple).

## Buenas prácticas y seguridad
- Activa freeze-mode en producción; habilítalo sólo durante migraciones controladas.
- Valida nombres de tablas/columnas externos: evita concatenar strings inseguros en `raw`.
- Prefiere `constraints` en schemaCreate para UNIQUE/FK portables.
- Usa `where` en índices parciales sólo cuando el dialecto lo soporta (PostgreSQL).
- Evita defaults no portables; usa funciones nativas (CURRENT_TIMESTAMP, NOW()) sin comillas.

## Ejemplos extra

// CTE y luego crear índice sobre vista materializada (PostgreSQL)
-- SQL
CREATE MATERIALIZED VIEW mv_active_users AS SELECT * FROM users WHERE active = true;
CREATE INDEX idx_mv_users_email ON mv_active_users (email);

// VersaORM-PHP
$orm->exec('CREATE MATERIALIZED VIEW mv_active_users AS SELECT * FROM users WHERE active = true');
$orm->schemaAlter('mv_active_users', [ 'addIndex' => [ ['name'=>'idx_mv_users_email','columns'=>['email']] ] ]);
