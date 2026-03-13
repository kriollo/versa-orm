# INSERT, UPDATE, DELETE - Operaciones de Modificación

Esta página cubre todas las operaciones de modificación de datos y sus equivalencias en VersaORM.

## INSERT - Insertar Datos

### Insertar un registro

```sql
-- SQL
INSERT INTO users (name, email, active) VALUES ('Juan Pérez', 'juan@email.com', 1);
```

```php
// VersaORM con VersaModel
$user = VersaModel::dispense('users');
$user->name = 'Juan Pérez';
$user->email = 'juan@email.com';
$user->active = 1;
$id = $user->store();

// O usando Query Builder
$id = $orm->table('users')->insert([
    'name' => 'Juan Pérez',
    'email' => 'juan@email.com',
    'active' => 1
]);
```

**Devuelve:** ID del registro insertado (entero).

### Insertar múltiples registros

```sql
-- SQL
INSERT INTO users (name, email, active) VALUES
('Ana García', 'ana@email.com', 1),
('Carlos López', 'carlos@email.com', 0),
('María Rodríguez', 'maria@email.com', 1);
```

```php
// VersaORM
$users = [
    ['name' => 'Ana García', 'email' => 'ana@email.com', 'active' => 1],
    ['name' => 'Carlos López', 'email' => 'carlos@email.com', 'active' => 0],
    ['name' => 'María Rodríguez', 'email' => 'maria@email.com', 'active' => 1]
];

$insertedIds = $orm->table('users')->insertMany($users);
```

**Devuelve:** Array con los IDs de los registros insertados.

### INSERT con SELECT (copiar datos)

```sql
-- SQL
INSERT INTO users_backup (name, email, created_at)
SELECT name, email, created_at FROM users WHERE active = 0;
```

```php
// VersaORM
$inactiveUsers = $orm->table('users')
    ->select(['name', 'email', 'created_at'])
    ->where('active', '=', 0)
    ->getAll();

$orm->table('users_backup')->insertMany($inactiveUsers);
```

## UPDATE - Actualizar Datos

### Actualizar un registro específico

```sql
-- SQL
UPDATE users SET name = 'Juan Carlos Pérez', active = 1 WHERE id = 5;
```

```php
// VersaORM con VersaModel
$user = VersaModel::load('users', 5);
if ($user) {
    $user->name = 'Juan Carlos Pérez';
    $user->active = 1;
    $user->store();
}

// O usando Query Builder
$affected = $orm->table('users')
    ->where('id', '=', 5)
    ->update([
        'name' => 'Juan Carlos Pérez',
        'active' => 1
    ]);
```

**Devuelve:** Número de registros afectados (entero).

### Actualizar múltiples registros

```sql
-- SQL
UPDATE users SET active = 0 WHERE last_login < '2023-01-01';
```

```php
// VersaORM
$affected = $orm->table('users')
    ->where('last_login', '<', '2023-01-01')
    ->update(['active' => 0]);
```

### Actualizar con cálculos

```sql
-- SQL
UPDATE users SET login_count = login_count + 1 WHERE id = 5;
```

```php
// VersaORM
$orm->table('users')
    ->where('id', '=', 5)
    ->update([
        'login_count' => $orm->raw('login_count + 1')
    ]);
```

### Actualizar con JOIN

```sql
-- SQL
UPDATE users u
JOIN posts p ON u.id = p.user_id
SET u.post_count = u.post_count + 1
WHERE p.published = 1;
```

```php
// VersaORM
$orm->table('users as u')
    ->join('posts as p', 'u.id', '=', 'p.user_id')
    ->where('p.published', '=', 1)
    ->update([
        'u.post_count' => $orm->raw('u.post_count + 1')
    ]);
```

## DELETE - Eliminar Datos

### Eliminar un registro específico

```sql
-- SQL
DELETE FROM users WHERE id = 5;
```

```php
// VersaORM con VersaModel
$user = VersaModel::load('users', 5);
if ($user) {
    $user->trash();
}

// O usando Query Builder
$deleted = $orm->table('users')
    ->where('id', '=', 5)
    ->delete();
```

**Devuelve:** Número de registros eliminados (entero).

### Eliminar múltiples registros

```sql
-- SQL
DELETE FROM users WHERE active = 0 AND last_login < '2022-01-01';
```

```php
// VersaORM
$deleted = $orm->table('users')
    ->where('active', '=', 0)
    ->where('last_login', '<', '2022-01-01')
    ->delete();
```

### Eliminar con JOIN

```sql
-- SQL
DELETE u FROM users u
LEFT JOIN posts p ON u.id = p.user_id
WHERE p.id IS NULL;
```

```php
// VersaORM
$orm->table('users as u')
    ->leftJoin('posts as p', 'u.id', '=', 'p.user_id')
    ->whereNull('p.id')
    ->delete();
```

### Eliminar todos los registros (TRUNCATE equivalente)

```sql
-- SQL
TRUNCATE TABLE temp_data;
-- O
DELETE FROM temp_data;
```

```php
// VersaORM
$orm->table('temp_data')->delete(); // Sin WHERE elimina todo
```

## UPSERT - Insertar o Actualizar

### INSERT ... ON DUPLICATE KEY UPDATE (MySQL)

```sql
-- SQL (MySQL)
INSERT INTO users (id, name, email, login_count)
VALUES (1, 'Juan Pérez', 'juan@email.com', 1)
ON DUPLICATE KEY UPDATE
    name = VALUES(name),
    login_count = login_count + 1;
```

```php
// VersaORM
$orm->table('users')->upsert([
    'id' => 1,
    'name' => 'Juan Pérez',
    'email' => 'juan@email.com',
    'login_count' => 1
], [
    'name' => 'Juan Pérez',
    'login_count' => $orm->raw('login_count + 1')
]);
```

### INSERT ... ON CONFLICT (PostgreSQL)

```sql
-- SQL (PostgreSQL)
INSERT INTO users (email, name, active)
VALUES ('juan@email.com', 'Juan Pérez', 1)
ON CONFLICT (email)
DO UPDATE SET
    name = EXCLUDED.name,
    updated_at = NOW();
```

```php
// VersaORM
$orm->table('users')->upsert([
    'email' => 'juan@email.com',
    'name' => 'Juan Pérez',
    'active' => 1
], [
    'name' => 'Juan Pérez',
    'updated_at' => $orm->raw('NOW()')
], ['email']); // Columna de conflicto
```

## REPLACE - Reemplazar Datos

### REPLACE INTO (MySQL)

```sql
-- SQL (MySQL)
REPLACE INTO users (id, name, email, active)
VALUES (1, 'Juan Carlos', 'juan@email.com', 1);
```

```php
// VersaORM
$orm->table('users')->replace([
    'id' => 1,
    'name' => 'Juan Carlos',
    'email' => 'juan@email.com',
    'active' => 1
]);
```

## Operaciones en Lote (Batch)

### Actualizar múltiples registros con diferentes valores

```php
// VersaORM - Actualización en lote
$updates = [
    ['id' => 1, 'name' => 'Juan Actualizado'],
    ['id' => 2, 'name' => 'Ana Actualizada'],
    ['id' => 3, 'name' => 'Carlos Actualizado']
];

$orm->table('users')->updateMany($updates, 'id');
```

### Eliminar múltiples registros por IDs

```sql
-- SQL
DELETE FROM users WHERE id IN (1, 2, 3, 4, 5);
```

```php
// VersaORM
$orm->table('users')
    ->whereIn('id', [1, 2, 3, 4, 5])
    ->delete();

// O usando deleteMany
$orm->table('users')->deleteMany([1, 2, 3, 4, 5]);
```

## Transacciones

### Transacción básica

```sql
-- SQL
START TRANSACTION;
INSERT INTO users (name, email) VALUES ('Test User', 'test@email.com');
UPDATE posts SET user_id = LAST_INSERT_ID() WHERE id = 1;
COMMIT;
```

```php
// VersaORM
$orm->beginTransaction();
try {
    $userId = $orm->table('users')->insert([
        'name' => 'Test User',
        'email' => 'test@email.com'
    ]);

    $orm->table('posts')
        ->where('id', '=', 1)
        ->update(['user_id' => $userId]);

    $orm->commit();
} catch (Exception $e) {
    $orm->rollback();
    throw $e;
}
```

## Validación y Manejo de Errores

### Verificar si un registro existe antes de actualizar

```php
// VersaORM
$user = VersaModel::load('users', 5);
if (!$user) {
    throw new Exception('Usuario no encontrado');
}

$user->name = 'Nuevo Nombre';
$user->store();
```

### Manejar errores de duplicados

```php
// VersaORM
try {
    $orm->table('users')->insert([
        'email' => 'duplicado@email.com',
        'name' => 'Usuario'
    ]);
} catch (VersaORMException $e) {
    if ($e->getCode() === 23000) { // Duplicate entry
        echo "El email ya existe";
    }
}
```

## Mejores Prácticas

1. **Usa transacciones**: Para operaciones que afectan múltiples tablas
2. **Valida antes de modificar**: Verifica que los registros existan
3. **Usa UPSERT**: Para evitar errores de duplicados
4. **Limita DELETE**: Siempre usa WHERE en DELETE para evitar eliminar todo
5. **Batch operations**: Usa `insertMany`, `updateMany` para mejor rendimiento

## Errores Comunes

- **DELETE sin WHERE**: Elimina todos los registros de la tabla
- **No manejar duplicados**: Puede causar errores en INSERT
- **Transacciones sin rollback**: Pueden dejar la BD en estado inconsistente
- **No validar datos**: Puede causar errores de integridad

## Navegación

- [← SELECT](select.md)
- [JOINs y Subconsultas →](joins-subqueries.md)