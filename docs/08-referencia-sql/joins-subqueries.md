# JOINs y Subconsultas

Esta página cubre consultas complejas con múltiples tablas, JOINs y subconsultas en VersaORM.

## INNER JOIN - UniInterna

### JOIN básico

```sql
-- SQL
SELECT u.name, p.title
FROM users u
INNER JOIN posts p ON u.id = p.user_id;
```

```php
// VersaORM
$results = $orm->table('users as u')
    ->join('posts as p', 'u.id', '=', 'p.user_id')
    ->select(['u.name', 'p.title'])
    ->getAll();
```

**Devuelve:** Array de arrays asociativos con las columnas de ambas tablas.

### JOIN con condiciones adicionales

```sql
-- SQL
SELECT u.name, p.title
FROM users u
INNER JOIN posts p ON u.id = p.user_id AND p.published = 1
WHERE u.active = 1;
```

```php
// VersaORM
$results = $orm->table('users as u')
    ->join('posts as p', function($join) {
        $join->on('u.id', '=', 'p.user_id')
             ->where('p.published', '=', 1);
    })
    ->where('u.active', '=', 1)
    ->select(['u.name', 'p.title'])
    ->getAll();
```

## LEFT JOIN - Unión Izquierda

### LEFT JOIN básico

```sql
-- SQL
SELECT u.name, COUNT(p.id) as post_count
FROM users u
LEFT JOIN posts p ON u.id = p.user_id
GROUP BY u.id, u.name;
```

```php
// VersaORM
$results = $orm->table('users as u')
    ->leftJoin('posts as p', 'u.id', '=', 'p.user_id')
    ->select([
        'u.name',
        $orm->raw('COUNT(p.id) as post_count')
    ])
    ->groupBy(['u.id', 'u.name'])
    ->getAll();
```

### Encontrar registros sin relación

```sql
-- SQL
SELECT u.name
FROM users u
LEFT JOIN posts p ON u.id = p.user_id
WHERE p.id IS NULL;
```

```php
// VersaORM
$usersWithoutPosts = $orm->table('users as u')
    ->leftJoin('posts as p', 'u.id', '=', 'p.user_id')
    ->whereNull('p.id')
    ->select(['u.name'])
    ->getAll();
```

## RIGHT JOIN - Unión Derecha

```sql
-- SQL
SELECT u.name, p.title
FROM users u
RIGHT JOIN posts p ON u.id = p.user_id;
```

```php
// VersaORM
$results = $orm->table('users as u')
    ->rightJoin('posts as p', 'u.id', '=', 'p.user_id')
    ->select(['u.name', 'p.title'])
    ->getAll();
```

## FULL OUTER JOIN - Unión Completa

```sql
-- SQL (PostgreSQL)
SELECT u.name, p.title
FROM users u
FULL OUTER JOIN posts p ON u.id = p.user_id;
```

```php
// VersaORM (simulado con UNION)
$leftJoin = $orm->table('users as u')
    ->leftJoin('posts as p', 'u.id', '=', 'p.user_id')
    ->select(['u.name', 'p.title']);

$rightJoin = $orm->table('users as u')
    ->rightJoin('posts as p', 'u.id', '=', 'p.user_id')
    ->select(['u.name', 'p.title']);

$results = $orm->union($leftJoin, $rightJoin)->getAll();
```

## Múltiples JOINs

### JOIN con tres tablas

```sql
-- SQL
SELECT u.name, p.title, c.name as category_name
FROM users u
INNER JOIN posts p ON u.id = p.user_id
INNER JOIN categories c ON p.category_id = c.id
WHERE u.active = 1;
```

```php
// VersaORM
$results = $orm->table('users as u')
    ->join('posts as p', 'u.id', '=', 'p.user_id')
    ->join('categories as c', 'p.category_id', '=', 'c.id')
    ->where('u.active', '=', 1)
    ->select(['u.name', 'p.title', 'c.name as category_name'])
    ->getAll();
```

### JOIN con tabla de relación muchos-a-muchos

```sql
-- SQL
SELECT u.name, t.name as tag_name
FROM users u
INNER JOIN posts p ON u.id = p.user_id
INNER JOIN post_tags pt ON p.id = pt.post_id
INNER JOIN tags t ON pt.tag_id = t.id
WHERE p.published = 1;
```

```php
// VersaORM
$results = $orm->table('users as u')
    ->join('posts as p', 'u.id', '=', 'p.user_id')
    ->join('post_tags as pt', 'p.id', '=', 'pt.post_id')
    ->join('tags as t', 'pt.tag_id', '=', 't.id')
    ->where('p.published', '=', 1)
    ->select(['u.name', 't.name as tag_name'])
    ->getAll();
```

## Subconsultas en SELECT

### Subconsulta escalar

```sql
-- SQL
SELECT u.name,
       (SELECT COUNT(*) FROM posts p WHERE p.user_id = u.id) as post_count
FROM users u;
```

```php
// VersaORM
$results = $orm->table('users as u')
    ->select([
        'u.name',
        $orm->subquery(
            $orm->table('posts as p')
                ->select([$orm->raw('COUNT(*)')])
                ->whereRaw('p.user_id = u.id'),
            'post_count'
        )
    ])
    ->getAll();
```

### Subconsulta con múltiples columnas

```sql
-- SQL
SELECT u.name,
       (SELECT p.title FROM posts p WHERE p.user_id = u.id ORDER BY p.created_at DESC LIMIT 1) as latest_post
FROM users u;
```

```php
// VersaORM
$results = $orm->table('users as u')
    ->select([
        'u.name',
        $orm->subquery(
            $orm->table('posts as p')
                ->select(['p.title'])
                ->whereRaw('p.user_id = u.id')
                ->orderBy('p.created_at', 'DESC')
                ->limit(1),
            'latest_post'
        )
    ])
    ->getAll();
```

## Subconsultas en WHERE

### EXISTS

```sql
-- SQL
SELECT * FROM users u
WHERE EXISTS (
    SELECT 1 FROM posts p
    WHERE p.user_id = u.id AND p.published = 1
);
```

```php
// VersaORM
$results = $orm->table('users as u')
    ->whereExists(function($query) {
        $query->table('posts as p')
              ->select(['1'])
              ->whereRaw('p.user_id = u.id')
              ->where('p.published', '=', 1);
    })
    ->getAll();
```

### NOT EXISTS

```sql
-- SQL
SELECT * FROM users u
WHERE NOT EXISTS (
    SELECT 1 FROM posts p WHERE p.user_id = u.id
);
```

```php
// VersaORM
$results = $orm->table('users as u')
    ->whereNotExists(function($query) {
        $query->table('posts as p')
              ->select(['1'])
              ->whereRaw('p.user_id = u.id');
    })
    ->getAll();
```

### IN con subconsulta

```sql
-- SQL
SELECT * FROM users
WHERE id IN (
    SELECT user_id FROM posts WHERE published = 1
);
```

```php
// VersaORM
$results = $orm->table('users')
    ->whereIn('id', function($query) {
        $query->table('posts')
              ->select(['user_id'])
              ->where('published', '=', 1);
    })
    ->getAll();
```

### Comparación con subconsulta

```sql
-- SQL
SELECT * FROM posts
WHERE created_at > (
    SELECT AVG(created_at) FROM posts
);
```

```php
// VersaORM
$results = $orm->table('posts')
    ->where('created_at', '>', function($query) {
        $query->table('posts')
              ->select([$orm->raw('AVG(created_at)')]);
    })
    ->getAll();
```

## Subconsultas en FROM

### Subconsulta como tabla derivada

```sql
-- SQL
SELECT avg_posts.user_id, avg_posts.post_count
FROM (
    SELECT user_id, COUNT(*) as post_count
    FROM posts
    GROUP BY user_id
    HAVING COUNT(*) > 5
) as avg_posts;
```

```php
// VersaORM
$subquery = $orm->table('posts')
    ->select(['user_id', $orm->raw('COUNT(*) as post_count')])
    ->groupBy('user_id')
    ->having($orm->raw('COUNT(*)'), '>', 5);

$results = $orm->table($orm->raw("({$subquery->toSql()}) as avg_posts"))
    ->select(['avg_posts.user_id', 'avg_posts.post_count'])
    ->getAll();
```

## UNION - Unir Consultas

### UNION básico

```sql
-- SQL
SELECT name, 'user' as type FROM users WHERE active = 1
UNION
SELECT title, 'post' as type FROM posts WHERE published = 1;
```

```php
// VersaORM
$users = $orm->table('users')
    ->select(['name', $orm->raw("'user' as type")])
    ->where('active', '=', 1);

$posts = $orm->table('posts')
    ->select(['title as name', $orm->raw("'post' as type")])
    ->where('published', '=', 1);

$results = $orm->union($users, $posts)->getAll();
```

### UNION ALL (incluir duplicados)

```sql
-- SQL
SELECT email FROM users
UNION ALL
SELECT email FROM subscribers;
```

```php
// VersaORM
$users = $orm->table('users')->select(['email']);
$subscribers = $orm->table('subscribers')->select(['email']);

$results = $orm->unionAll($users, $subscribers)->getAll();
```

## Common Table Expressions (CTEs)

### WITH básico (PostgreSQL)

```sql
-- SQL (PostgreSQL)
WITH user_stats AS (
    SELECT user_id, COUNT(*) as post_count
    FROM posts
    GROUP BY user_id
)
SELECT u.name, us.post_count
FROM users u
JOIN user_stats us ON u.id = us.user_id
WHERE us.post_count > 10;
```

```php
// VersaORM (usando subconsulta)
$userStats = $orm->table('posts')
    ->select(['user_id', $orm->raw('COUNT(*) as post_count')])
    ->groupBy('user_id');

$results = $orm->table('users as u')
    ->joinSub($userStats, 'us', 'u.id', '=', 'us.user_id')
    ->where('us.post_count', '>', 10)
    ->select(['u.name', 'us.post_count'])
    ->getAll();
```

## Consultas Correlacionadas

### Subconsulta correlacionada

```sql
-- SQL
SELECT u.name,
       (SELECT COUNT(*) FROM posts p WHERE p.user_id = u.id) as post_count
FROM users u
WHERE (SELECT COUNT(*) FROM posts p WHERE p.user_id = u.id) > 5;
```

```php
// VersaORM
$results = $orm->table('users as u')
    ->select([
        'u.name',
        $orm->subquery(
            $orm->table('posts as p')
                ->select([$orm->raw('COUNT(*)')])
                ->whereRaw('p.user_id = u.id'),
            'post_count'
        )
    ])
    ->whereExists(function($query) {
        $query->table('posts as p')
              ->select([$orm->raw('COUNT(*)')])
              ->whereRaw('p.user_id = u.id')
              ->havingRaw('COUNT(*) > 5');
    })
    ->getAll();
```

## Window Functions (Funciones de Ventana)

### ROW_NUMBER()

```sql
-- SQL (PostgreSQL/MySQL 8.0+)
SELECT name, email,
       ROW_NUMBER() OVER (ORDER BY created_at) as row_num
FROM users;
```

```php
// VersaORM
$results = $orm->table('users')
    ->select([
        'name',
        'email',
        $orm->raw('ROW_NUMBER() OVER (ORDER BY created_at) as row_num')
    ])
    ->getAll();
```

### RANK() con PARTITION BY

```sql
-- SQL
SELECT name, department,
       RANK() OVER (PARTITION BY department ORDER BY salary DESC) as rank_in_dept
FROM employees;
```

```php
// VersaORM
$results = $orm->table('employees')
    ->select([
        'name',
        'department',
        $orm->raw('RANK() OVER (PARTITION BY department ORDER BY salary DESC) as rank_in_dept')
    ])
    ->getAll();
```

## Mejores Prácticas

1. **Usa alias**: Siempre usa alias para tablas en JOINs complejos
2. **Índices en JOINs**: Asegúrate de que las columnas de JOIN tengan índices
3. **Limita subconsultas**: Las subconsultas pueden ser lentas, considera JOINs
4. **EXISTS vs IN**: Usa EXISTS para mejor rendimiento en subconsultas
5. **Evita SELECT ***: En JOINs, especifica las columnas necesarias

## Errores Comunes

- **Ambigüedad de columnas**: No especificar tabla en columnas con mismo nombre
- **Cartesian product**: JOIN sin condición ON
- **Subconsultas lentas**: No optimizar subconsultas correlacionadas
- **NULL en JOINs**: No considerar valores NULL en condiciones de JOIN

## Navegación

- [← INSERT, UPDATE, DELETE](insert-update-delete.md)
- [Funciones de Agregación →](funciones-agregacion.md)
