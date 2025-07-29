# QueryBuilder Class

La clase `QueryBuilder` proporciona una interfaz fluida para construir consultas SQL complejas de manera programática, similar a Laravel Eloquent.

## Tabla de Contenidos

- [Constructor](#constructor)
- [Selección de Columnas](#selección-de-columnas)
- [Cláusulas WHERE](#cláusulas-where)
- [Cláusulas JOIN](#cláusulas-join)
- [Agrupación y Ordenamiento](#agrupación-y-ordenamiento)
- [Límites y Paginación](#límites-y-paginación)
- [Ejecución de Consultas](#ejecución-de-consultas)
- [Operaciones CRUD](#operaciones-crud)
- [Métodos de Utilidad](#métodos-de-utilidad)

---

## Constructor

### `__construct($orm, string $table)`

Crea una nueva instancia de QueryBuilder.

**Parámetros:**
- `$orm` (VersaORM): Instancia del ORM
- `$table` (string): Nombre de la tabla

**Ejemplo:**
```php
$qb = new QueryBuilder($orm, 'users');
// O usar el método helper de VersaORM
$qb = $orm->table('users');
```

---

## Selección de Columnas

### `select(?array $columns = ['*']): self`

Especifica las columnas a seleccionar.

**Parámetros:**
- `$columns` (array|null, opcional): Array de columnas (por defecto ['*'])

**Retorna:** La misma instancia (fluent interface)

**Ejemplos:**
```php
// Seleccionar todas las columnas
$users = $orm->table('users')->select()->findAll();

// Seleccionar columnas específicas
$users = $orm->table('users')
    ->select(['id', 'name', 'email'])
    ->findAll();

// Seleccionar con alias
$users = $orm->table('users')
    ->select(['u.id', 'u.name as full_name', 'u.email'])
    ->findAll();
```

---

## Cláusulas WHERE

### `where(?string $column, ?string $operator, $value): self`

Añade una cláusula WHERE con operador AND.

**Parámetros:**
- `$column` (string|null): Nombre de la columna
- `$operator` (string|null): Operador de comparación (=, >, <, >=, <=, !=, LIKE)
- `$value` (mixed): Valor a comparar

**Ejemplos:**
```php
// Comparación simple
$users = $orm->table('users')
    ->where('status', '=', 'active')
    ->findAll();

// Múltiples condiciones AND
$users = $orm->table('users')
    ->where('status', '=', 'active')
    ->where('age', '>=', 18)
    ->where('city', '=', 'Madrid')
    ->findAll();

// Diferentes operadores
$products = $orm->table('products')
    ->where('price', '>', 100)
    ->where('name', 'LIKE', '%laptop%')
    ->where('stock', '!=', 0)
    ->findAll();
```

### `orWhere(string $column, string $operator, $value): self`

Añade una cláusula WHERE con operador OR.

**Parámetros:**
- `$column` (string): Nombre de la columna
- `$operator` (string): Operador de comparación
- `$value` (mixed): Valor a comparar

**Ejemplo:**
```php
// Buscar usuarios activos o premium
$users = $orm->table('users')
    ->where('status', '=', 'active')
    ->orWhere('type', '=', 'premium')
    ->findAll();

// Combinación compleja
$products = $orm->table('products')
    ->where('category', '=', 'electronics')
    ->where('price', '<', 500)
    ->orWhere('featured', '=', 1)
    ->findAll();
```

### `whereIn(string $column, array $values): self`

Añade una cláusula WHERE IN.

**Parámetros:**
- `$column` (string): Nombre de la columna
- `$values` (array): Array de valores

**Ejemplo:**
```php
// Buscar usuarios por IDs específicos
$users = $orm->table('users')
    ->whereIn('id', [1, 2, 3, 5, 8])
    ->findAll();

// Buscar productos por categorías
$products = $orm->table('products')
    ->whereIn('category', ['electronics', 'books', 'clothing'])
    ->findAll();
```

### `whereNotIn(string $column, array $values): self`

Añade una cláusula WHERE NOT IN.

**Parámetros:**
- `$column` (string): Nombre de la columna
- `$values` (array): Array de valores a excluir

**Ejemplo:**
```php
// Excluir usuarios específicos
$users = $orm->table('users')
    ->whereNotIn('id', [1, 2, 3])
    ->where('status', '=', 'active')
    ->findAll();
```

### `whereNull(string $column): self`

Añade una cláusula WHERE IS NULL.

**Parámetros:**
- `$column` (string): Nombre de la columna

**Ejemplo:**
```php
// Buscar usuarios sin email
$users = $orm->table('users')
    ->whereNull('email')
    ->findAll();

// Buscar productos sin descripción
$products = $orm->table('products')
    ->whereNull('description')
    ->where('status', '=', 'published')
    ->findAll();
```

### `whereNotNull(string $column): self`

Añade una cláusula WHERE IS NOT NULL.

**Parámetros:**
- `$column` (string): Nombre de la columna

**Ejemplo:**
```php
// Buscar usuarios con email válido
$users = $orm->table('users')
    ->whereNotNull('email')
    ->where('email_verified', '=', 1)
    ->findAll();
```

### `whereBetween(string $column, $min, $max): self`

Añade una cláusula WHERE BETWEEN.

**Parámetros:**
- `$column` (string): Nombre de la columna
- `$min` (mixed): Valor mínimo
- `$max` (mixed): Valor máximo

**Ejemplos:**
```php
// Buscar productos en rango de precio
$products = $orm->table('products')
    ->whereBetween('price', 100, 500)
    ->findAll();

// Buscar usuarios por rango de edad
$users = $orm->table('users')
    ->whereBetween('age', 25, 35)
    ->where('status', '=', 'active')
    ->findAll();

// Buscar registros por fecha
$orders = $orm->table('orders')
    ->whereBetween('created_at', '2024-01-01', '2024-12-31')
    ->findAll();
```

### `whereRaw(string $sql, array $bindings = []): self`

Añade una cláusula WHERE con SQL raw.

**Parámetros:**
- `$sql` (string): Condición SQL raw
- `$bindings` (array, opcional): Valores para prepared statements

**Ejemplos:**
```php
// Condición SQL personalizada
$users = $orm->table('users')
    ->whereRaw('YEAR(created_at) = ?', [2024])
    ->findAll();

// Función de base de datos
$products = $orm->table('products')
    ->whereRaw('LOWER(name) LIKE ?', ['%laptop%'])
    ->findAll();

// Subconsulta
$users = $orm->table('users')
    ->whereRaw('id IN (SELECT user_id FROM orders WHERE total > ?)', [1000])
    ->findAll();
```

---

## Cláusulas JOIN

### `join(string $table, string $firstCol, string $operator, string $secondCol): self`

Añade un INNER JOIN.

**Parámetros:**
- `$table` (string): Tabla a unir
- `$firstCol` (string): Primera columna
- `$operator` (string): Operador de comparación
- `$secondCol` (string): Segunda columna

**Ejemplo:**
```php
// Usuarios con sus perfiles
$usersWithProfiles = $orm->table('users')
    ->join('profiles', 'users.id', '=', 'profiles.user_id')
    ->select(['users.*', 'profiles.bio', 'profiles.avatar'])
    ->findAll();
```

### `leftJoin(string $table, string $firstCol, string $operator, string $secondCol): self`

Añade un LEFT JOIN.

**Parámetros:**
- `$table` (string): Tabla a unir
- `$firstCol` (string): Primera columna
- `$operator` (string): Operador de comparación
- `$secondCol` (string): Segunda columna

**Ejemplo:**
```php
// Usuarios con sus perfiles (incluyendo usuarios sin perfil)
$usersWithProfiles = $orm->table('users')
    ->leftJoin('profiles', 'users.id', '=', 'profiles.user_id')
    ->select(['users.*', 'profiles.bio'])
    ->findAll();
```

### `rightJoin(string $table, string $firstCol, string $operator, string $secondCol): self`

Añade un RIGHT JOIN.

**Parámetros:**
- `$table` (string): Tabla a unir
- `$firstCol` (string): Primera columna
- `$operator` (string): Operador de comparación
- `$secondCol` (string): Segunda columna

**Ejemplo:**
```php
// Todos los perfiles con sus usuarios (incluyendo perfiles huérfanos)
$profilesWithUsers = $orm->table('users')
    ->rightJoin('profiles', 'users.id', '=', 'profiles.user_id')
    ->select(['users.name', 'profiles.*'])
    ->findAll();
```

---

## Agrupación y Ordenamiento

### `orderBy(string $column, string $direction = 'asc'): self`

Ordena los resultados.

**Parámetros:**
- `$column` (string): Columna por la cual ordenar
- `$direction` (string, opcional): Dirección del ordenamiento ('asc' o 'desc')

**Ejemplos:**
```php
// Ordenar por nombre ascendente
$users = $orm->table('users')
    ->orderBy('name', 'asc')
    ->findAll();

// Ordenar por fecha descendente
$posts = $orm->table('posts')
    ->orderBy('created_at', 'desc')
    ->findAll();

// Múltiples ordenamientos (requiere múltiples llamadas)
$users = $orm->table('users')
    ->orderBy('last_name', 'asc')
    ->orderBy('first_name', 'asc')
    ->findAll();
```

### `groupBy($columns): self`

Agrupa los resultados.

**Parámetros:**
- `$columns` (array|string): Columnas para agrupar

**Nota:** Método implementado pero requiere funcionalidad adicional en el backend

### `having(string $column, string $operator, $value): self`

Añade una cláusula HAVING.

**Parámetros:**
- `$column` (string): Nombre de la columna
- `$operator` (string): Operador de comparación
- `$value` (mixed): Valor a comparar

**Ejemplo:**
```php
// Buscar categorías con más de 10 productos
$categories = $orm->table('products')
    ->select(['category', 'COUNT(*) as total'])
    ->groupBy('category')
    ->having('total', '>', 10)
    ->getAll();
```

---

## Límites y Paginación

### `limit(int $count): self`

Limita el número de resultados.

**Parámetros:**
- `$count` (int): Número máximo de registros

**Ejemplo:**
```php
// Obtener los primeros 10 usuarios
$users = $orm->table('users')
    ->limit(10)
    ->findAll();

// Top 5 productos más caros
$products = $orm->table('products')
    ->orderBy('price', 'desc')
    ->limit(5)
    ->findAll();
```

### `offset(int $count): self`

Especifica el punto de inicio para la paginación.

**Parámetros:**
- `$count` (int): Número de registros a saltar

**Ejemplo:**
```php
// Paginación: página 2 con 10 registros por página
$users = $orm->table('users')
    ->limit(10)
    ->offset(10)
    ->findAll();

// Paginación manual
$page = 3;
$perPage = 15;
$offset = ($page - 1) * $perPage;

$users = $orm->table('users')
    ->limit($perPage)
    ->offset($offset)
    ->findAll();
```

---

## Ejecución de Consultas

### `findAll(): Model[]`

Ejecuta la consulta SELECT y devuelve un array de modelos.

**Retorna:** Array de instancias de Model

**Ejemplo:**
```php
$users = $orm->table('users')
    ->where('status', '=', 'active')
    ->orderBy('name')
    ->findAll();

foreach ($users as $user) {
    echo $user->name . " - " . $user->email . "\n";
}
```

### `getAll(): array`

Ejecuta la consulta SELECT y devuelve un array de arrays.

**Retorna:** Array de arrays con los datos

**Ejemplo:**
```php
$userData = $orm->table('users')
    ->select(['id', 'name', 'email'])
    ->where('status', '=', 'active')
    ->getAll();

foreach ($userData as $user) {
    echo $user['name'] . " - " . $user['email'] . "\n";
}
```

### `findOne(): ?Model`

Obtiene el primer resultado como modelo.

**Retorna:** Instancia de Model o null

**Ejemplo:**
```php
$user = $orm->table('users')
    ->where('email', '=', 'juan@ejemplo.com')
    ->findOne();

if ($user) {
    echo "Usuario encontrado: " . $user->name;
} else {
    echo "Usuario no encontrado";
}
```

### `first(): ?Model`

Alias de findOne() - obtiene el primer resultado.

**Retorna:** Instancia de Model o null

**Ejemplo:**
```php
$latestPost = $orm->table('posts')
    ->orderBy('created_at', 'desc')
    ->first();
```

### `find($id, string $pk = 'id'): ?Model`

Busca un registro por su clave primaria.

**Parámetros:**
- `$id` (mixed): Valor del ID
- `$pk` (string, opcional): Nombre de la clave primaria

**Ejemplo:**
```php
// Buscar por ID
$user = $orm->table('users')->find(1);

// Buscar por clave primaria personalizada
$product = $orm->table('products')->find('SKU123', 'sku');
```

### `count(): int`

Cuenta los registros que coinciden con la consulta.

**Retorna:** Número de registros (int)

**Ejemplos:**
```php
// Contar todos los usuarios activos
$activeUsers = $orm->table('users')
    ->where('status', '=', 'active')
    ->count();

// Contar productos por categoría
$electronicsCount = $orm->table('products')
    ->where('category', '=', 'electronics')
    ->where('stock', '>', 0)
    ->count();
```

### `exists(): bool`

Verifica si existen registros que coincidan con la consulta.

**Retorna:** true si existen registros

**Ejemplo:**
```php
// Verificar si existe un email
$emailExists = $orm->table('users')
    ->where('email', '=', 'test@ejemplo.com')
    ->exists();

if ($emailExists) {
    echo "El email ya está registrado";
}
```

---

## Operaciones CRUD

### `insert(array $data): self`

Inserta un nuevo registro.

**Parámetros:**
- `$data` (array): Datos a insertar

**Ejemplo:**
```php
// Insertar un usuario
$orm->table('users')->insert([
    'name' => 'Carlos Ruiz',
    'email' => 'carlos@ejemplo.com',
    'status' => 'active'
]);

// Insertar múltiples campos
$orm->table('products')->insert([
    'name' => 'Laptop Gaming',
    'price' => 1299.99,
    'category' => 'electronics',
    'stock' => 5,
    'featured' => true
]);
```

### `insertGetId(array $data): mixed`

Inserta un registro y devuelve el ID autoincremental.

**Parámetros:**
- `$data` (array): Datos a insertar

**Retorna:** El ID del registro insertado

**Ejemplo:**
```php
$userId = $orm->table('users')->insertGetId([
    'name' => 'Ana García',
    'email' => 'ana@ejemplo.com',
    'status' => 'active'
]);

echo "Usuario creado con ID: " . $userId;

// Usar el ID para crear registros relacionados
$orm->table('profiles')->insert([
    'user_id' => $userId,
    'bio' => 'Desarrolladora Full Stack',
    'website' => 'https://ana-garcia.dev'
]);
```

### `update(array $data): self`

Actualiza registros que coincidan con las condiciones WHERE.

**Parámetros:**
- `$data` (array): Datos a actualizar

**Ejemplos:**
```php
// Actualizar un usuario específico
$orm->table('users')
    ->where('id', '=', 1)
    ->update([
        'name' => 'Juan Pérez Actualizado',
        'last_login' => date('Y-m-d H:i:s')
    ]);

// Actualizar múltiples usuarios
$orm->table('users')
    ->where('status', '=', 'pending')
    ->where('created_at', '<', '2024-01-01')
    ->update([
        'status' => 'inactive'
    ]);

// Actualizar con incremento
$orm->table('products')
    ->where('id', '=', 1)
    ->update([
        'views' => 'views + 1'  // Nota: esto requiere soporte en el backend
    ]);
```

### `delete(): self`

Elimina registros que coincidan con las condiciones WHERE.

**Ejemplos:**
```php
// Eliminar un usuario específico
$orm->table('users')
    ->where('id', '=', 1)
    ->delete();

// Eliminar usuarios inactivos antiguos
$orm->table('users')
    ->where('status', '=', 'inactive')
    ->where('last_login', '<', '2023-01-01')
    ->delete();

// Eliminar con múltiples condiciones
$orm->table('sessions')
    ->where('expires_at', '<', time())
    ->orWhere('user_id', 'IS NULL', null)
    ->delete();
```

---

## Métodos de Utilidad

### `dispense(): Model`

Crea un nuevo modelo vacío para la tabla.

**Retorna:** Nueva instancia de Model

**Ejemplo:**
```php
$user = $orm->table('users')->dispense();
$user->name = 'Nuevo Usuario';
$user->email = 'nuevo@ejemplo.com';
$user->store();
```

---

## Ejemplos Avanzados

### Consulta Compleja con JOIN y Filtros

```php
$ordersWithCustomers = $orm->table('orders')
    ->select([
        'orders.*',
        'customers.name as customer_name',
        'customers.email as customer_email'
    ])
    ->join('customers', 'orders.customer_id', '=', 'customers.id')
    ->where('orders.status', '=', 'completed')
    ->where('orders.total', '>', 100)
    ->whereBetween('orders.created_at', '2024-01-01', '2024-12-31')
    ->orderBy('orders.created_at', 'desc')
    ->limit(50)
    ->findAll();
```

### Paginación Completa

```php
function getUsersPaginated($page = 1, $perPage = 10) {
    global $orm;
    
    $offset = ($page - 1) * $perPage;
    
    // Obtener datos
    $users = $orm->table('users')
        ->where('status', '=', 'active')
        ->orderBy('name', 'asc')
        ->limit($perPage)
        ->offset($offset)
        ->findAll();
    
    // Obtener total para paginación
    $total = $orm->table('users')
        ->where('status', '=', 'active')
        ->count();
    
    return [
        'data' => Model::exportAll($users),
        'current_page' => $page,
        'per_page' => $perPage,
        'total' => $total,
        'last_page' => ceil($total / $perPage)
    ];
}
```

### Búsqueda Avanzada

```php
function searchProducts($filters) {
    global $orm;
    
    $query = $orm->table('products');
    
    // Filtro por nombre
    if (!empty($filters['name'])) {
        $query->where('name', 'LIKE', '%' . $filters['name'] . '%');
    }
    
    // Filtro por categorías
    if (!empty($filters['categories'])) {
        $query->whereIn('category', $filters['categories']);
    }
    
    // Filtro por rango de precio
    if (!empty($filters['min_price'])) {
        $query->where('price', '>=', $filters['min_price']);
    }
    if (!empty($filters['min_price'])) {
        $query->where('price', '<=', $filters['max_price']);
    }
    
    // Filtro por disponibilidad
    if ($filters['in_stock'] ?? false) {
        $query->where('stock', '>', 0);
    }
    
    // Ordenamiento
    $sortBy = $filters['sort_by'] ?? 'name';
    $sortDir = $filters['sort_dir'] ?? 'asc';
    $query->orderBy($sortBy, $sortDir);
    
    return $query->findAll();
}
```

### Estadísticas con GROUP BY

```php
// Obtener estadísticas de ventas por mes
$monthlySales = $orm->table('orders')
    ->select([
        'YEAR(created_at) as year',
        'MONTH(created_at) as month',
        'COUNT(*) as total_orders',
        'SUM(total) as total_revenue',
        'AVG(total) as avg_order_value'
    ])
    ->where('status', '=', 'completed')
    ->groupBy(['YEAR(created_at)', 'MONTH(created_at)'])
    ->orderBy('year', 'desc')
    ->orderBy('month', 'desc')
    ->getAll();
```

---

## Consideraciones de Rendimiento

1. **Usar LIMIT**: Siempre limitar resultados en consultas grandes
2. **Índices**: Asegurar que las columnas WHERE tengan índices
3. **SELECT específico**: Evitar SELECT * cuando sea posible
4. **JOIN eficientes**: Usar JOINs apropiados según la relación
5. **Paginación**: Implementar paginación para datasets grandes

---

## Patrones Comunes

1. **Chain Method**: Encadenar métodos para construir consultas complejas
2. **Repository Pattern**: Encapsular lógica de consultas en repositorios
3. **Query Scopes**: Crear métodos reutilizables para filtros comunes
4. **Lazy Loading**: Cargar datos relacionados solo cuando es necesario

---

Esta documentación cubre todas las funcionalidades de la clase QueryBuilder. Para ejemplos más específicos y casos de uso avanzados, consulta la sección de ejemplos en la documentación.
