# SELECT - Consultas de Selección

Esta página cubre todas las variantes de SELECT en SQL y sus equivalencias en VersaORM.

## SELECT Básico

### Seleccionar todas las columnas

```sql
-- SQL
SELECT * FROM users;
```

```php
// VersaORM
$users = $orm->table('users')->getAll();
```

**Devuelve:** Array de arrays asociativos con todas las columnas.

### Seleccionar columnas específicas

```sql
-- SQL
SELECT name, email FROM users;
```

```php
// VersaORM
$users = $orm->table('users')
    ->select(['name', 'email'])
    ->getAll();
```

**Devuelve:** Array de arrays asociativos solo con las columnas especificadas.

## WHERE - Condiciones

### Condición simple

```sql
-- SQL
SELECT * FROM users WHERE active = 1;
```

```php
// VersaORM
$users = $orm->table('users')
    ->where('active', '=', 1)
    ->getAll();
```

### Múltiples condiciones AND

```sql
-- SQL
SELECT * FROM users WHERE active = 1 AND age >= 18;
```

```php
// VersaORM
$users = $orm->table('users')
    ->where('active', '=', 1)
    ->where('age', '>=', 18)
    ->getAll();
```

### Condiciones OR

```sql
-- SQL
SELECT * FROM users WHERE role = 'admin' OR role = 'moderator';
```

```php
// VersaORM
$users = $orm->table('users')
    ->where('role', '=', 'admin')
    ->orWhere('role', '=', 'moderator')
    ->getAll();
```

### IN y NOT IN

```sql
-- SQL
SELECT * FROM users WHERE id IN (1, 2, 3, 4);
```

```php
// VersaORM
$users = $orm->table('users')
    ->whereIn('id', [1, 2, 3, 4])
    ->getAll();
```

```sql
-- SQL
SELECT * FROM users WHERE status NOT IN ('banned', 'suspended');
```

```php
// VersaORM
$users = $orm->table('users')
    ->whereNotIn('status', ['banned', 'suspended'])
    ->getAll();
```

### BETWEEN

```sql
-- SQL
SELECT * FROM users WHERE age BETWEEN 18 AND 65;
```

```php
// VersaORM
$users = $orm->table('users')
    ->whereBetween('age', [18, 65])
    ->getAll();
```

### LIKE - Búsqueda de patrones

```sql
-- SQL
SELECT * FROM users WHERE name LIKE 'John%';
```

```php
// VersaORM
$users = $orm->table('users')
    ->where('name', 'LIKE', 'John%')
    ->getAll();
```

### IS NULL y IS NOT NULL

```sql
-- SQL
SELECT * FROM users WHERE deleted_at IS NULL;
```

```php
// VersaORM
$users = $orm->table('users')
    ->whereNull('deleted_at')
    ->getAll();
```

```sql
-- SQL
SELECT * FROM users WHERE email IS NOT NULL;
```

```php
// VersaORM
$users = $orm->table('users')
    ->whereNotNull('email')
    ->getAll();
```

## ORDER BY - Ordenamiento

### Ordenamiento simple

```sql
-- SQL
SELECT * FROM users ORDER BY name;
```

```php
// VersaORM
$users = $orm->table('users')
    ->orderBy('name')
    ->getAll();
```

### Ordenamiento descendente

```sql
-- SQL
SELECT * FROM users ORDER BY created_at DESC;
```

```php
// VersaORM
$users = $orm->table('users')
    ->orderBy('created_at', 'DESC')
    ->getAll();
```

### Múltiples criterios de ordenamiento

```sql
-- SQL
SELECT * FROM users ORDER BY role ASC, name DESC;
```

```php
// VersaORM
$users = $orm->table('users')
    ->orderBy('role', 'ASC')
    ->orderBy('name', 'DESC')
    ->getAll();
```

## LIMIT y OFFSET - Paginación

### Limitar resultados

```sql
-- SQL
SELECT * FROM users LIMIT 10;
```

```php
// VersaORM
$users = $orm->table('users')
    ->limit(10)
    ->getAll();
```

### Paginación con OFFSET

```sql
-- SQL
SELECT * FROM users LIMIT 10 OFFSET 20;
```

```php
// VersaORM
$users = $orm->table('users')
    ->limit(10)
    ->offset(20)
    ->getAll();
```

## DISTINCT - Valores únicos

```sql
-- SQL
SELECT DISTINCT role FROM users;
```

```php
// VersaORM
$roles = $orm->table('users')
    ->select(['role'])
    ->distinct()
    ->getAll();
```

## Subconsultas en WHERE

### Subconsulta con EXISTS

```sql
-- SQL
SELECT * FROM users u
WHERE EXISTS (
    SELECT 1 FROM posts p WHERE p.user_id = u.id
);
```

```php
// VersaORM
$users = $orm->table('users')
    ->whereExists(function($query) {
        $query->table('posts')
              ->select(['1'])
              ->whereRaw('posts.user_id = users.id');
    })
    ->getAll();
```

### Subconsulta con IN

```sql
-- SQL
SELECT * FROM users
WHERE id IN (
    SELECT user_id FROM posts WHERE published = 1
);
```

```php
// VersaORM
$users = $orm->table('users')
    ->whereIn('id', function($query) {
        $query->table('posts')
              ->select(['user_id'])
              ->where('published', '=', 1);
    })
    ->getAll();
```

## Consultas con Alias

### Alias de tabla

```sql
-- SQL
SELECT u.name, u.email FROM users u WHERE u.active = 1;
```

```php
// VersaORM
$users = $orm->table('users as u')
    ->select(['u.name', 'u.email'])
    ->where('u.active', '=', 1)
    ->getAll();
```

### Alias de columna

```sql
-- SQL
SELECT name AS full_name, email AS contact_email FROM users;
```

```php
// VersaORM
$users = $orm->table('users')
    ->select([
        'name AS full_name',
        'email AS contact_email'
    ])
    ->getAll();
```

## CASE WHEN - Lógica condicional

```sql
-- SQL
SELECT name,
       CASE
           WHEN age < 18 THEN 'Minor'
           WHEN age >= 65 THEN 'Senior'
           ELSE 'Adult'
       END AS age_group
FROM users;
```

```php
// VersaORM
$users = $orm->table('users')
    ->select([
        'name',
        $orm->raw("CASE
                     WHEN age < 18 THEN 'Minor'
                     WHEN age >= 65 THEN 'Senior'
                     ELSE 'Adult'
                   END AS age_group")
    ])
    ->getAll();
```

## Obtener un solo registro

### Primer registro

```sql
-- SQL
SELECT * FROM users WHERE active = 1 LIMIT 1;
```

```php
// VersaORM
$user = $orm->table('users')
    ->where('active', '=', 1)
    ->first();
```

**Devuelve:** Array asociativo del primer registro o `null` si no existe.

### Por ID específico

```sql
-- SQL
SELECT * FROM users WHERE id = 5;
```

```php
// VersaORM
$user = $orm->table('users')
    ->where('id', '=', 5)
    ->first();

// O usando VersaModel
$user = VersaModel::load('users', 5);
```

**Devuelve:** Array asociativo o objeto VersaModel según el método usado.

## Contar registros

```sql
-- SQL
SELECT COUNT(*) as total FROM users WHERE active = 1;
```

```php
// VersaORM
$total = $orm->table('users')
    ->where('active', '=', 1)
    ->count();
```

**Devuelve:** Número entero con el total de registros.

## Mejores Prácticas

1. **Usa select() específico**: Evita `SELECT *` en producción especificando solo las columnas necesarias
2. **Combina condiciones**: Encadena múltiples `where()` para condiciones AND
3. **Usa índices**: Asegúrate de que las columnas en WHERE tengan índices
4. **Limita resultados**: Siempre usa `limit()` en consultas que pueden devolver muchos registros

## Errores Comunes

- **No usar paréntesis en OR**: Las condiciones OR complejas pueden necesitar agrupación con `whereRaw()`
- **Olvidar DISTINCT**: Puede causar duplicados en JOINs
- **No validar NULL**: Siempre considera valores NULL en condiciones

## Navegación

- [← README de Referencia SQL](README.md)
- [INSERT, UPDATE, DELETE →](insert-update-delete.md)
