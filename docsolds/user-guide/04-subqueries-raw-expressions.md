# Subconsultas y Expresiones Raw

VersaORM ofrece soporte completo para subconsultas y expresiones SQL raw, permitiendo consultas complejas manteniendo la seguridad contra inyección SQL.

## Expresiones Raw

### selectRaw()

Permite utilizar expresiones SQL raw en la cláusula SELECT:

```php
// Expresiones básicas con funciones SQL
$users = $orm->table('users')
    ->selectRaw('COUNT(*) as total_users')
    ->selectRaw('UPPER(name) as upper_name')
    ->selectRaw('YEAR(created_at) as registration_year')
    ->get();

// Con parámetros bindados para seguridad
$users = $orm->table('users')
    ->selectRaw('CASE WHEN age >= ? THEN "adult" ELSE "minor" END as age_group', [18])
    ->get();
```

### orderByRaw()

Ordena usando expresiones SQL personalizadas:

```php
// Ordenamiento condicional
$users = $orm->table('users')
    ->orderByRaw('CASE WHEN status = ? THEN 1 ELSE 2 END', ['premium'])
    ->orderByRaw('name ASC')
    ->get();

// Ordenamiento por múltiples criterios
$posts = $orm->table('posts')
    ->orderByRaw('FIELD(status, ?, ?, ?)', ['featured', 'published', 'draft'])
    ->get();
```

### groupByRaw()

Agrupa usando expresiones complejas:

```php
// Agrupación por fechas
$stats = $orm->table('orders')
    ->selectRaw('YEAR(created_at) as year, MONTH(created_at) as month, SUM(amount) as total')
    ->groupByRaw('YEAR(created_at), MONTH(created_at)')
    ->get();

// Agrupación condicional
$users = $orm->table('users')
    ->selectRaw('COUNT(*) as count')
    ->groupByRaw('CASE WHEN age >= 18 THEN "adult" ELSE "minor" END')
    ->get();
```

### whereRaw()

Condiciones WHERE con expresiones personalizadas:

```php
// Condiciones complejas
$users = $orm->table('users')
    ->whereRaw('age > ? AND status = ?', [18, 'active'])
    ->whereRaw('created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)', [30])
    ->get();
```

## Subconsultas

### selectSubQuery()

Incluye subconsultas en el SELECT:

```php
// Contar posts por usuario
$users = $orm->table('users')
    ->select(['id', 'name', 'email'])
    ->selectSubQuery(function ($query) {
        $query->from('posts')
              ->selectRaw('COUNT(*)')
              ->whereRaw('user_id = users.id');
    }, 'posts_count')
    ->get();

// Usando QueryBuilder existente
$postsQuery = $orm->table('posts')
    ->selectRaw('COUNT(*)')
    ->where('status', '=', 'published');

$users = $orm->table('users')
    ->selectSubQuery($postsQuery, 'published_posts_count')
    ->get();
```

### whereSubQuery()

Subconsultas en condiciones WHERE:

```php
// WHERE con subconsulta IN
$activeUsers = $orm->table('users')
    ->whereSubQuery('id', 'IN', function ($query) {
        $query->from('posts')
              ->select(['user_id'])
              ->where('status', '=', 'published')
              ->where('created_at', '>=', '2024-01-01');
    })
    ->get();

// WHERE con operadores de comparación
$topUsers = $orm->table('users')
    ->whereSubQuery('id', '=', function ($query) {
        $query->from('posts')
              ->selectRaw('user_id')
              ->groupBy(['user_id'])
              ->orderByRaw('COUNT(*) DESC')
              ->limit(1);
    })
    ->get();
```

### whereExists() y whereNotExists()

Verificar existencia de registros relacionados:

```php
// Usuarios que tienen posts
$usersWithPosts = $orm->table('users')
    ->whereExists(function ($query) {
        $query->from('posts')
              ->whereRaw('user_id = users.id')
              ->where('status', '=', 'published');
    })
    ->get();

// Usuarios sin posts
$usersWithoutPosts = $orm->table('users')
    ->whereNotExists(function ($query) {
        $query->from('posts')
              ->whereRaw('user_id = users.id');
    })
    ->get();

// Usuarios no baneados
$activeUsers = $orm->table('users')
    ->whereNotExists(function ($query) {
        $query->from('banned_users')
              ->whereRaw('user_id = users.id')
              ->where('active', '=', true);
    })
    ->get();
```

## Ejemplos Avanzados

### Consulta Compleja con Múltiples Subconsultas

```php
$report = $orm->table('users')
    ->select(['id', 'name', 'email', 'created_at'])
    
    // Contar posts publicados
    ->selectSubQuery(function ($query) {
        $query->from('posts')
              ->selectRaw('COUNT(*)')
              ->whereRaw('user_id = users.id')
              ->where('status', '=', 'published');
    }, 'published_posts')
    
    // Contar comentarios recibidos
    ->selectSubQuery(function ($query) {
        $query->from('comments')
              ->join('posts', 'posts.id', '=', 'comments.post_id')
              ->selectRaw('COUNT(*)')
              ->whereRaw('posts.user_id = users.id');
    }, 'comments_received')
    
    // Solo usuarios activos con posts
    ->whereExists(function ($query) {
        $query->from('posts')
              ->whereRaw('user_id = users.id')
              ->where('status', '=', 'published');
    })
    
    // Ordenar por actividad
    ->orderByRaw('
        (
            SELECT COUNT(*) FROM posts 
            WHERE user_id = users.id 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        ) DESC
    ')
    
    ->limit(50)
    ->get();
```

### Estadísticas con Agrupación y Subconsultas

```php
$monthlyStats = $orm->table('users')
    ->selectRaw('
        YEAR(created_at) as year,
        MONTH(created_at) as month,
        COUNT(*) as new_users
    ')
    ->selectSubQuery(function ($query) {
        $query->from('posts')
              ->selectRaw('COUNT(*)')
              ->whereRaw('YEAR(posts.created_at) = YEAR(users.created_at)')
              ->whereRaw('MONTH(posts.created_at) = MONTH(users.created_at)');
    }, 'posts_created')
    
    ->groupByRaw('YEAR(created_at), MONTH(created_at)')
    ->orderByRaw('year DESC, month DESC')
    ->get();
```

## Validación de Seguridad

VersaORM incluye validaciones automáticas contra inyección SQL:

### Patrones Detectados y Bloqueados

```php
// ❌ Estos ejemplos fallarán con VersaORMException

// Comentarios SQL
$orm->table('users')->selectRaw('name -- DROP TABLE users');

// Comandos peligrosos
$orm->table('users')->whereRaw('1=1; DROP TABLE users; --');

// Ataques UNION
$orm->table('users')->selectRaw('name UNION SELECT password FROM admin');

// Funciones peligrosas
$orm->table('users')->selectRaw('LOAD_FILE("/etc/passwd")');

// Paréntesis desbalanceados
$orm->table('users')->selectRaw('COUNT((incomplete');

// Expresiones demasiado largas (>500 caracteres)
$orm->table('users')->selectRaw(str_repeat('a', 501));
```

### Funciones SQL Permitidas

```php
// ✅ Estas funciones están en la lista blanca

$allowedFunctions = [
    'COUNT', 'SUM', 'AVG', 'MAX', 'MIN',
    'UPPER', 'LOWER', 'LENGTH', 'SUBSTRING', 'CONCAT',
    'COALESCE', 'IFNULL', 'NULLIF',
    'ABS', 'ROUND', 'CEIL', 'FLOOR',
    'NOW', 'CURDATE', 'CURTIME', 'DATE',
    'YEAR', 'MONTH', 'DAY', 'HOUR', 'MINUTE', 'SECOND',
    'TRIM', 'LTRIM', 'RTRIM', 'REPLACE',
    'DISTINCT'
];

// Ejemplos seguros
$orm->table('users')->selectRaw('COUNT(*) as total');
$orm->table('users')->selectRaw('UPPER(name) as upper_name');
$orm->table('orders')->selectRaw('SUM(amount) as total_amount');
```

## Mejores Prácticas

### 1. Usar Parámetros Bindados

```php
// ✅ Correcto - usa parámetros bindados
$users = $orm->table('users')
    ->whereRaw('age > ? AND status = ?', [18, 'active'])
    ->get();

// ❌ Incorrecto - concatenación directa
$age = 18;
$users = $orm->table('users')
    ->whereRaw("age > {$age}")  // Vulnerable a inyección
    ->get();
```

### 2. Validar Entradas de Usuario

```php
// ✅ Validar antes de usar en raw expressions
$validStatuses = ['active', 'inactive', 'pending'];
$userStatus = $_GET['status'] ?? 'active';

if (!in_array($userStatus, $validStatuses)) {
    throw new InvalidArgumentException('Invalid status');
}

$users = $orm->table('users')
    ->whereRaw('status = ?', [$userStatus])
    ->get();
```

### 3. Preferir Métodos Estándar Cuando Sea Posible

```php
// ✅ Usar métodos estándar cuando sea suficiente
$users = $orm->table('users')
    ->where('age', '>', 18)
    ->where('status', '=', 'active')
    ->orderBy('name', 'asc')
    ->get();

// Solo usar raw cuando sea necesario para lógica compleja
$users = $orm->table('users')
    ->whereRaw('DATEDIFF(NOW(), last_login) > ?', [30])
    ->get();
```

### 4. Documentar Expresiones Complejas

```php
// ✅ Documentar la lógica de expresiones complejas
$users = $orm->table('users')
    // Calcular puntuación de actividad basada en posts y comentarios recientes
    ->selectRaw('
        (
            (SELECT COUNT(*) FROM posts WHERE user_id = users.id AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)) * 2 +
            (SELECT COUNT(*) FROM comments WHERE user_id = users.id AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY))
        ) as activity_score
    ')
    ->orderByRaw('activity_score DESC')
    ->get();
```

## Compatibilidad con Bases de Datos

Las expresiones raw y subconsultas son compatibles con:

- ✅ **MySQL 5.7+**: Soporte completo
- ✅ **PostgreSQL 10+**: Soporte completo  
- ✅ **SQLite 3.25+**: Soporte completo
- ✅ **SQL Server 2017+**: Soporte completo

> **Nota**: Algunas funciones específicas pueden variar entre motores de base de datos. Consulte la documentación de su motor específico para funciones avanzadas.
