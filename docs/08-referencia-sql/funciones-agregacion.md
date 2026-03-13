# Funciones de Agregación

Esta página cubre todas las funciones de agregación SQL y sus equivalencias en VersaORM.

## Funciones Básicas de Agregación

### COUNT - Contar Registros

```sql
-- SQL
SELECT COUNT(*) FROM users;
```

```php
// VersaORM
$total = $orm->table('users')->count();
```
ve:** Número entero con el total de registros.

```sql
-- SQL
SELECT COUNT(email) FROM users;
```

```php
// VersaORM
$emailCount = $orm->table('users')->count('email');
```

### COUNT DISTINCT - Contar Valores Únicos

```sql
-- SQL
SELECT COUNT(DISTINCT role) FROM users;
```

```php
// VersaORM
$uniqueRoles = $orm->table('users')
    ->select([$orm->raw('COUNT(DISTINCT role) as unique_roles')])
    ->first()['unique_roles'];
```

### SUM - Sumar Valores

```sql
-- SQL
SELECT SUM(amount) FROM orders;
```

```php
// VersaORM
$totalAmount = $orm->table('orders')->sum('amount');
```

**Devuelve:** Número (entero o decimal) con la suma total.

### AVG - Promedio

```sql
-- SQL
SELECT AVG(age) FROM users;
```

```php
// VersaORM
$averageAge = $orm->table('users')->avg('age');
```

**Devuelve:** Número decimal con el promedio.

### MIN y MAX - Valores Mínimo y Máximo

```sql
-- SQL
SELECT MIN(created_at), MAX(created_at) FROM posts;
```

```php
// VersaORM
$minDate = $orm->table('posts')->min('created_at');
$maxDate = $orm->table('posts')->max('created_at');

// O en una sola consulta
$result = $orm->table('posts')
    ->select([
        $orm->raw('MIN(created_at) as min_date'),
        $orm->raw('MAX(created_at) as max_date')
    ])
    ->first();
```

## GROUP BY - Agrupar Resultados

### Agrupación básica

```sql
-- SQL
SELECT role, COUNT(*) as user_count
FROM users
GROUP BY role;
```

```php
// VersaORM
$roleStats = $orm->table('users')
    ->select(['role', $orm->raw('COUNT(*) as user_count')])
    ->groupBy('role')
    ->getAll();
```

### Múltiples columnas de agrupación

```sql
-- SQL
SELECT role, active, COUNT(*) as count
FROM users
GROUP BY role, active;
```

```php
// VersaORM
$stats = $orm->table('users')
    ->select([
        'role',
        'active',
        $orm->raw('COUNT(*) as count')
    ])
    ->groupBy(['role', 'active'])
    ->getAll();
```

### Agrupación con múltiples funciones

```sql
-- SQL
SELECT user_id,
       COUNT(*) as post_count,
       AVG(views) as avg_views,
       SUM(likes) as total_likes
FROM posts
GROUP BY user_id;
```

```php
// VersaORM
$userStats = $orm->table('posts')
    ->select([
        'user_id',
        $orm->raw('COUNT(*) as post_count'),
        $orm->raw('AVG(views) as avg_views'),
        $orm->raw('SUM(likes) as total_likes')
    ])
    ->groupBy('user_id')
    ->getAll();
```

## HAVING - Filtrar Grupos

### HAVING básico

```sql
-- SQL
SELECT role, COUNT(*) as user_count
FROM users
GROUP BY role
HAVING COUNT(*) > 5;
```

```php
// VersaORM
$popularRoles = $orm->table('users')
    ->select(['role', $orm->raw('COUNT(*) as user_count')])
    ->groupBy('role')
    ->having($orm->raw('COUNT(*)'), '>', 5)
    ->getAll();
```

### HAVING con múltiples condiciones

```sql
-- SQL
SELECT user_id, COUNT(*) as post_count, AVG(views) as avg_views
FROM posts
GROUP BY user_id
HAVING COUNT(*) >= 10 AND AVG(views) > 1000;
```

```php
// VersaORM
$activeUsers = $orm->table('posts')
    ->select([
        'user_id',
        $orm->raw('COUNT(*) as post_count'),
        $orm->raw('AVG(views) as avg_views')
    ])
    ->groupBy('user_id')
    ->having($orm->raw('COUNT(*)'), '>=', 10)
    ->having($orm->raw('AVG(views)'), '>', 1000)
    ->getAll();
```

## Funciones de Fecha y Tiempo

### Agrupar por fecha

```sql
-- SQL
SELECT DATE(created_at) as date, COUNT(*) as posts_per_day
FROM posts
GROUP BY DATE(created_at)
ORDER BY date;
```

```php
// VersaORM
$dailyStats = $orm->table('posts')
    ->select([
        $orm->raw('DATE(created_at) as date'),
        $orm->raw('COUNT(*) as posts_per_day')
    ])
    ->groupBy($orm->raw('DATE(created_at)'))
    ->orderBy('date')
    ->getAll();
```

### Agrupar por mes y año

```sql
-- SQL
SELECT YEAR(created_at) as year,
       MONTH(created_at) as month,
       COUNT(*) as count
FROM posts
GROUP BY YEAR(created_at), MONTH(created_at)
ORDER BY year, month;
```

```php
// VersaORM
$monthlyStats = $orm->table('posts')
    ->select([
        $orm->raw('YEAR(created_at) as year'),
        $orm->raw('MONTH(created_at) as month'),
        $orm->raw('COUNT(*) as count')
    ])
    ->groupBy([$orm->raw('YEAR(created_at)'), $orm->raw('MONTH(created_at)')])
    ->orderBy('year')
    ->orderBy('month')
    ->getAll();
```

### Funciones de fecha específicas por motor

```sql
-- SQL (MySQL)
SELECT DAYNAME(created_at) as day_name, COUNT(*) as count
FROM posts
GROUP BY DAYNAME(created_at);
```

```php
// VersaORM
$dayStats = $orm->table('posts')
    ->select([
        $orm->raw('DAYNAME(created_at) as day_name'),
        $orm->raw('COUNT(*) as count')
    ])
    ->groupBy($orm->raw('DAYNAME(created_at)'))
    ->getAll();
```

## Funciones de String

### Concatenación y agrupación

```sql
-- SQL
SELECT CONCAT(first_name, ' ', last_name) as full_name, COUNT(*) as count
FROM users
GROUP BY CONCAT(first_name, ' ', last_name);
```

```php
// VersaORM
$nameStats = $orm->table('users')
    ->select([
        $orm->raw("CONCAT(first_name, ' ', last_name) as full_name"),
        $orm->raw('COUNT(*) as count')
    ])
    ->groupBy($orm->raw("CONCAT(first_name, ' ', last_name)"))
    ->getAll();
```

### Funciones de string con agregación

```sql
-- SQL
SELECT LEFT(email, LOCATE('@', email) - 1) as domain_prefix,
       COUNT(*) as count
FROM users
GROUP BY LEFT(email, LOCATE('@', email) - 1);
```

```php
// VersaORM
$domainStats = $orm->table('users')
    ->select([
        $orm->raw("LEFT(email, LOCATE('@', email) - 1) as domain_prefix"),
        $orm->raw('COUNT(*) as count')
    ])
    ->groupBy($orm->raw("LEFT(email, LOCATE('@', email) - 1)"))
    ->getAll();
```

## Funciones Matemáticas

### Operaciones matemáticas con agregación

```sql
-- SQL
SELECT category_id,
       ROUND(AVG(price), 2) as avg_price,
       CEIL(AVG(price)) as avg_price_ceil,
       FLOOR(AVG(price)) as avg_price_floor
FROM products
GROUP BY category_id;
```

```php
// VersaORM
$priceStats = $orm->table('products')
    ->select([
        'category_id',
        $orm->raw('ROUND(AVG(price), 2) as avg_price'),
        $orm->raw('CEIL(AVG(price)) as avg_price_ceil'),
        $orm->raw('FLOOR(AVG(price)) as avg_price_floor')
    ])
    ->groupBy('category_id')
    ->getAll();
```

### Cálculos estadísticos

```sql
-- SQL (PostgreSQL)
SELECT category_id,
       STDDEV(price) as price_stddev,
       VARIANCE(price) as price_variance
FROM products
GROUP BY category_id;
```

```php
// VersaORM
$statisticalData = $orm->table('products')
    ->select([
        'category_id',
        $orm->raw('STDDEV(price) as price_stddev'),
        $orm->raw('VARIANCE(price) as price_variance')
    ])
    ->groupBy('category_id')
    ->getAll();
```

## Funciones Condicionales

### CASE WHEN con agregación

```sql
-- SQL
SELECT
    SUM(CASE WHEN status = 'completed' THEN amount ELSE 0 END) as completed_total,
    SUM(CASE WHEN status = 'pending' THEN amount ELSE 0 END) as pending_total,
    COUNT(CASE WHEN status = 'cancelled' THEN 1 END) as cancelled_count
FROM orders;
```

```php
// VersaORM
$orderStats = $orm->table('orders')
    ->select([
        $orm->raw("SUM(CASE WHEN status = 'completed' THEN amount ELSE 0 END) as completed_total"),
        $orm->raw("SUM(CASE WHEN status = 'pending' THEN amount ELSE 0 END) as pending_total"),
        $orm->raw("COUNT(CASE WHEN status = 'cancelled' THEN 1 END) as cancelled_count")
    ])
    ->first();
```

### IF/IIF con agregación (MySQL)

```sql
-- SQL (MySQL)
SELECT user_id,
       SUM(IF(published = 1, 1, 0)) as published_count,
       SUM(IF(published = 0, 1, 0)) as draft_count
FROM posts
GROUP BY user_id;
```

```php
// VersaORM
$postStats = $orm->table('posts')
    ->select([
        'user_id',
        $orm->raw('SUM(IF(published = 1, 1, 0)) as published_count'),
        $orm->raw('SUM(IF(published = 0, 1, 0)) as draft_count')
    ])
    ->groupBy('user_id')
    ->getAll();
```

## Agregaciones con JOINs

### Agregación con INNER JOIN

```sql
-- SQL
SELECT u.name, COUNT(p.id) as post_count, AVG(p.views) as avg_views
FROM users u
INNER JOIN posts p ON u.id = p.user_id
GROUP BY u.id, u.name;
```

```php
// VersaORM
$userPostStats = $orm->table('users as u')
    ->join('posts as p', 'u.id', '=', 'p.user_id')
    ->select([
        'u.name',
        $orm->raw('COUNT(p.id) as post_count'),
        $orm->raw('AVG(p.views) as avg_views')
    ])
    ->groupBy(['u.id', 'u.name'])
    ->getAll();
```

### Agregación con LEFT JOIN

```sql
-- SQL
SELECT u.name, COALESCE(COUNT(p.id), 0) as post_count
FROM users u
LEFT JOIN posts p ON u.id = p.user_id
GROUP BY u.id, u.name;
```

```php
// VersaORM
$allUserStats = $orm->table('users as u')
    ->leftJoin('posts as p', 'u.id', '=', 'p.user_id')
    ->select([
        'u.name',
        $orm->raw('COALESCE(COUNT(p.id), 0) as post_count')
    ])
    ->groupBy(['u.id', 'u.name'])
    ->getAll();
```

## Subconsultas con Agregación

### Subconsulta en SELECT con agregación

```sql
-- SQL
SELECT u.name,
       (SELECT COUNT(*) FROM posts p WHERE p.user_id = u.id) as post_count,
       (SELECT MAX(p.created_at) FROM posts p WHERE p.user_id = u.id) as last_post
FROM users u;
```

```php
// VersaORM
$userDetails = $orm->table('users as u')
    ->select([
        'u.name',
        $orm->subquery(
            $orm->table('posts as p')
                ->select([$orm->raw('COUNT(*)')])
                ->whereRaw('p.user_id = u.id'),
            'post_count'
        ),
        $orm->subquery(
            $orm->table('posts as p')
                ->select([$orm->raw('MAX(p.created_at)')])
                ->whereRaw('p.user_id = u.id'),
            'last_post'
        )
    ])
    ->getAll();
```

## Window Functions Avanzadas

### Funciones de ranking

```sql
-- SQL (PostgreSQL/MySQL 8.0+)
SELECT name, salary, department,
       RANK() OVER (PARTITION BY department ORDER BY salary DESC) as salary_rank,
       DENSE_RANK() OVER (PARTITION BY department ORDER BY salary DESC) as dense_rank,
       ROW_NUMBER() OVER (PARTITION BY department ORDER BY salary DESC) as row_num
FROM employees;
```

```php
// VersaORM
$employeeRanks = $orm->table('employees')
    ->select([
        'name',
        'salary',
        'department',
        $orm->raw('RANK() OVER (PARTITION BY department ORDER BY salary DESC) as salary_rank'),
        $orm->raw('DENSE_RANK() OVER (PARTITION BY department ORDER BY salary DESC) as dense_rank'),
        $orm->raw('ROW_NUMBER() OVER (PARTITION BY department ORDER BY salary DESC) as row_num')
    ])
    ->getAll();
```

### Funciones de agregación como ventana

```sql
-- SQL
SELECT name, salary,
       SUM(salary) OVER (ORDER BY salary) as running_total,
       AVG(salary) OVER (ORDER BY salary ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) as moving_avg
FROM employees;
```

```php
// VersaORM
$salaryAnalysis = $orm->table('employees')
    ->select([
        'name',
        'salary',
        $orm->raw('SUM(salary) OVER (ORDER BY salary) as running_total'),
        $orm->raw('AVG(salary) OVER (ORDER BY salary ROWS BETWEEN 2 PRECEDING AND CURRENT ROW) as moving_avg')
    ])
    ->getAll();
```

## Funciones Específicas por Motor de BD

### MySQL específicas

```sql
-- SQL (MySQL)
SELECT GROUP_CONCAT(name ORDER BY name SEPARATOR ', ') as all_names
FROM users
WHERE active = 1;
```

```php
// VersaORM
$nameList = $orm->table('users')
    ->where('active', '=', 1)
    ->select([$orm->raw("GROUP_CONCAT(name ORDER BY name SEPARATOR ', ') as all_names")])
    ->first()['all_names'];
```

### PostgreSQL específicas

```sql
-- SQL (PostgreSQL)
SELECT STRING_AGG(name, ', ' ORDER BY name) as all_names,
       ARRAY_AGG(id ORDER BY name) as all_ids
FROM users
WHERE active = true;
```

```php
// VersaORM
$aggregatedData = $orm->table('users')
    ->where('active', '=', true)
    ->select([
        $orm->raw("STRING_AGG(name, ', ' ORDER BY name) as all_names"),
        $orm->raw("ARRAY_AGG(id ORDER BY name) as all_ids")
    ])
    ->first();
```

## Mejores Prácticas

1. **Usa índices**: Las columnas en GROUP BY deben tener índices
2. **Limita resultados**: Usa LIMIT en agregaciones que pueden devolver muchos grupos
3. **Considera rendimiento**: Las funciones de ventana pueden ser costosas
4. **Valida NULL**: Las funciones de agregación ignoran valores NULL
5. **Usa HAVING correctamente**: Para filtrar grupos, no registros individuales

## Errores Comunes

- **SELECT sin GROUP BY**: Incluir columnas no agregadas sin agrupar
- **HAVING vs WHERE**: Usar HAVING para filtros que deberían ir en WHERE
- **NULL en agregaciones**: No considerar que NULL se ignora en funciones
- **Rendimiento**: No optimizar consultas con muchas agregaciones

## Navegación

- [← JOINs y Subconsultas](joins-subqueries.md)
- [README de Referencia SQL](README.md)
