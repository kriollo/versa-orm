# Ejemplos Básicos de VersaORM

Esta guía proporciona ejemplos prácticos de las operaciones más comunes con VersaORM.

## Tabla de Contenidos

- [Configuración Inicial](#configuración-inicial)
- [Creación de Registros](#creación-de-registros)
- [Lectura de Datos](#lectura-de-datos)
- [Actualización de Registros](#actualización-de-registros)
- [Eliminación de Registros](#eliminación-de-registros)
- [Query Builder Básico](#query-builder-básico)
- [Consultas SQL Raw](#consultas-sql-raw)

---

## Configuración Inicial

```php
<?php
require_once 'vendor/autoload.php';

use VersaORM\VersaORM;
use VersaORM\Model;

// Configuración de la base de datos
$config = [
    'driver' => 'mysql',
    'host' => 'localhost',
    'port' => 3306,
    'database' => 'tienda_online',
    'username' => 'usuario',
    'password' => 'contraseña'
];

// Crear instancia del ORM
$orm = new VersaORM($config);

// Configurar ORM global para modelos estáticos (opcional)
Model::setORM($orm);
```

---

## Creación de Registros

### Método 1: Usando el patrón RedBean

```php
// Crear un nuevo usuario
$user = $orm->dispense('users');
$user->name = 'Juan Pérez';
$user->email = 'juan@ejemplo.com';
$user->age = 30;
$user->status = 'active';
$orm->store($user);

echo "Usuario creado con ID: " . $user->id;
```

### Método 2: Usando instancias de Model

```php
// Crear usuario con Model
$user = new Model('users', $orm);
$user->name = 'María García';
$user->email = 'maria@ejemplo.com';
$user->age = 28;
$user->status = 'active';
$user->store();

echo "Usuario creado con ID: " . $user->id;
```

### Método 3: Usando QueryBuilder

```php
// Insertar usando QueryBuilder
$userId = $orm->table('users')->insertGetId([
    'name' => 'Carlos Ruiz',
    'email' => 'carlos@ejemplo.com',
    'age' => 35,
    'status' => 'active'
]);

echo "Usuario creado con ID: " . $userId;
```

### Creación de múltiples registros

```php
// Crear varios productos
$products = [
    ['name' => 'Laptop HP', 'price' => 800.00, 'category' => 'electronics'],
    ['name' => 'Mouse Logitech', 'price' => 25.50, 'category' => 'electronics'],
    ['name' => 'Libro PHP', 'price' => 45.00, 'category' => 'books']
];

foreach ($products as $productData) {
    $product = $orm->dispense('products');
    foreach ($productData as $key => $value) {
        $product->$key = $value;
    }
    $orm->store($product);
    echo "Producto '{$product->name}' creado con ID: {$product->id}\n";
}
```

---

## Lectura de Datos

### Buscar por ID

```php
// Buscar usuario por ID
$user = $orm->findOne('users', 1);
if ($user) {
    echo "Usuario encontrado: " . $user->name;
} else {
    echo "Usuario no encontrado";
}

// Usando Model estático
$user = Model::load('users', 1);
if ($user) {
    echo "Email: " . $user->email;
}
```

### Buscar todos los registros

```php
// Obtener todos los usuarios
$users = $orm->findAll('users');
foreach ($users as $user) {
    echo "Usuario: {$user->name} - {$user->email}\n";
}

// Obtener solo usuarios activos
$activeUsers = $orm->findAll('users', 'status = ?', ['active']);
foreach ($activeUsers as $user) {
    echo "Usuario activo: {$user->name}\n";
}
```

### Contar registros

```php
// Contar total de usuarios
$totalUsers = $orm->count('users');
echo "Total de usuarios: " . $totalUsers;

// Contar usuarios activos
$activeUsers = $orm->count('users', 'status = ?', ['active']);
echo "Usuarios activos: " . $activeUsers;
```

### Obtener un solo valor

```php
// Obtener el nombre de un usuario
$userName = $orm->getCell('SELECT name FROM users WHERE id = ?', [1]);
echo "Nombre del usuario: " . $userName;

// Obtener el precio promedio de productos
$avgPrice = $orm->getCell('SELECT AVG(price) FROM products');
echo "Precio promedio: $" . number_format($avgPrice, 2);
```

---

## Actualización de Registros

### Método 1: Cargar y modificar

```php
// Cargar usuario y modificar
$user = $orm->findOne('users', 1);
if ($user) {
    $user->name = 'Juan Pérez Actualizado';
    $user->last_login = date('Y-m-d H:i:s');
    $orm->store($user);
    echo "Usuario actualizado";
}
```

### Método 2: Usando QueryBuilder

```php
// Actualizar múltiples usuarios
$orm->table('users')
    ->where('status', '=', 'pending')
    ->update([
        'status' => 'active',
        'activated_at' => date('Y-m-d H:i:s')
    ]);

echo "Usuarios activados";
```

### Actualización condicional

```php
// Actualizar precio de productos en oferta
$orm->table('products')
    ->where('category', '=', 'electronics')
    ->where('stock', '>', 10)
    ->update([
        'price' => 'price * 0.9' // Aplicar 10% descuento
    ]);
```

---

## Eliminación de Registros

### Eliminar por modelo

```php
// Cargar y eliminar usuario
$user = $orm->findOne('users', 1);
if ($user) {
    $orm->trash($user);
    echo "Usuario eliminado";
}

// O usando el método del modelo
$user = Model::load('users', 1);
if ($user) {
    $user->trash();
    echo "Usuario eliminado";
}
```

### Eliminar usando QueryBuilder

```php
// Eliminar usuarios inactivos antiguos
$orm->table('users')
    ->where('status', '=', 'inactive')
    ->where('last_login', '<', '2023-01-01')
    ->delete();

echo "Usuarios inactivos eliminados";
```

### Eliminación en lote

```php
// Eliminar productos sin stock
$orm->table('products')
    ->where('stock', '=', 0)
    ->where('created_at', '<', '2023-01-01')
    ->delete();

// Eliminar usando SQL raw
$deletedCount = $orm->exec('DELETE FROM logs WHERE created_at < ?', ['2024-01-01']);
echo "Registros eliminados: " . $deletedCount;
```

---

## Query Builder Básico

### Consultas simples

```php
// Usuarios activos ordenados por nombre
$users = $orm->table('users')
    ->where('status', '=', 'active')
    ->orderBy('name', 'asc')
    ->findAll();

// Productos en rango de precio
$products = $orm->table('products')
    ->whereBetween('price', 50, 200)
    ->where('stock', '>', 0)
    ->limit(10)
    ->findAll();
```

### Consultas con múltiples condiciones

```php
// Búsqueda avanzada de productos
$products = $orm->table('products')
    ->where('category', '=', 'electronics')
    ->where(function($query) {
        $query->where('name', 'LIKE', '%laptop%')
              ->orWhere('name', 'LIKE', '%computer%');
    })
    ->whereBetween('price', 300, 1500)
    ->whereNotNull('description')
    ->orderBy('price', 'desc')
    ->limit(20)
    ->findAll();
```

### Paginación

```php
// Paginación simple
$page = 2;
$perPage = 10;
$offset = ($page - 1) * $perPage;

$users = $orm->table('users')
    ->where('status', '=', 'active')
    ->orderBy('created_at', 'desc')
    ->limit($perPage)
    ->offset($offset)
    ->findAll();

// Obtener total para paginación
$total = $orm->table('users')
    ->where('status', '=', 'active')
    ->count();

$totalPages = ceil($total / $perPage);
echo "Página {$page} de {$totalPages}";
```

---

## Consultas SQL Raw

### Consultas de selección complejas

```php
// Estadísticas de usuarios por mes
$stats = $orm->exec('
    SELECT 
        YEAR(created_at) as year,
        MONTH(created_at) as month,
        COUNT(*) as total_users,
        COUNT(CASE WHEN status = "active" THEN 1 END) as active_users
    FROM users 
    WHERE created_at >= ? 
    GROUP BY YEAR(created_at), MONTH(created_at)
    ORDER BY year DESC, month DESC
', ['2024-01-01']);

foreach ($stats as $stat) {
    echo "Año {$stat['year']}, Mes {$stat['month']}: {$stat['total_users']} usuarios ({$stat['active_users']} activos)\n";
}
```

### Consultas con JOINs

```php
// Usuarios con sus pedidos
$usersWithOrders = $orm->exec('
    SELECT 
        u.id,
        u.name,
        u.email,
        COUNT(o.id) as total_orders,
        SUM(o.total) as total_spent
    FROM users u
    LEFT JOIN orders o ON u.id = o.user_id
    WHERE u.status = ?
    GROUP BY u.id, u.name, u.email
    HAVING total_orders > 0
    ORDER BY total_spent DESC
    LIMIT 10
', ['active']);

foreach ($usersWithOrders as $user) {
    echo "Usuario: {$user['name']} - Pedidos: {$user['total_orders']} - Gastado: $" . number_format($user['total_spent'], 2) . "\n";
}
```

### Operaciones en lote

```php
// Actualización masiva con SQL
$affected = $orm->exec('
    UPDATE products 
    SET price = price * 1.1 
    WHERE category = ? AND stock > ?
', ['electronics', 5]);

echo "Productos actualizados: " . $affected;

// Inserción múltiple
$orm->exec('
    INSERT INTO product_tags (product_id, tag) 
    VALUES (?, ?), (?, ?), (?, ?)
', [1, 'nuevo', 1, 'oferta', 2, 'destacado']);
```

---

## Ejemplo Completo: Sistema de Blog Simple

```php
<?php
// Configuración
$orm = new VersaORM($config);

// Crear un nuevo post
function createPost($orm, $title, $content, $authorId) {
    $post = $orm->dispense('posts');
    $post->title = $title;
    $post->content = $content;
    $post->author_id = $authorId;
    $post->status = 'published';
    $post->created_at = date('Y-m-d H:i:s');
    $orm->store($post);
    
    return $post;
}

// Obtener posts recientes
function getRecentPosts($orm, $limit = 5) {
    return $orm->table('posts')
        ->where('status', '=', 'published')
        ->orderBy('created_at', 'desc')
        ->limit($limit)
        ->findAll();
}

// Buscar posts por título
function searchPosts($orm, $keyword) {
    return $orm->table('posts')
        ->where('title', 'LIKE', "%{$keyword}%")
        ->orWhere('content', 'LIKE', "%{$keyword}%")
        ->where('status', '=', 'published')
        ->orderBy('created_at', 'desc')
        ->findAll();
}

// Obtener posts con información del autor
function getPostsWithAuthors($orm) {
    return $orm->exec('
        SELECT 
            p.id,
            p.title,
            p.created_at,
            u.name as author_name,
            u.email as author_email
        FROM posts p
        JOIN users u ON p.author_id = u.id
        WHERE p.status = ?
        ORDER BY p.created_at DESC
    ', ['published']);
}

// Uso del sistema
try {
    // Crear un post
    $post = createPost($orm, 'Mi Primer Post', 'Este es el contenido del post...', 1);
    echo "Post creado con ID: {$post->id}\n";
    
    // Obtener posts recientes
    $recentPosts = getRecentPosts($orm);
    echo "Posts recientes:\n";
    foreach ($recentPosts as $post) {
        echo "- {$post->title} ({$post->created_at})\n";
    }
    
    // Buscar posts
    $searchResults = searchPosts($orm, 'primer');
    echo "Resultados de búsqueda:\n";
    foreach ($searchResults as $post) {
        echo "- {$post->title}\n";
    }
    
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}
```

---

## Consejos y Mejores Prácticas

### 1. Validación de datos

```php
function createUser($orm, $data) {
    // Validar datos antes de crear
    if (empty($data['name']) || empty($data['email'])) {
        throw new InvalidArgumentException('Nombre y email son requeridos');
    }
    
    if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
        throw new InvalidArgumentException('Email no válido');
    }
    
    // Verificar email único
    $existingUser = $orm->table('users')
        ->where('email', '=', $data['email'])
        ->exists();
    
    if ($existingUser) {
        throw new InvalidArgumentException('El email ya está registrado');
    }
    
    // Crear usuario
    $user = $orm->dispense('users');
    $user->name = $data['name'];
    $user->email = $data['email'];
    $user->created_at = date('Y-m-d H:i:s');
    $orm->store($user);
    
    return $user;
}
```

### 2. Manejo de errores

```php
function getUserById($orm, $id) {
    try {
        $user = $orm->findOne('users', $id);
        if (!$user) {
            throw new Exception("Usuario con ID {$id} no encontrado");
        }
        return $user;
    } catch (Exception $e) {
        error_log("Error al obtener usuario: " . $e->getMessage());
        return null;
    }
}
```

### 3. Uso de transacciones simuladas

```php
function transferUser($orm, $userId, $newStatus) {
    try {
        // Simular transaccón con múltiples operaciones
        $orm->exec('START TRANSACTION');
        
        // Actualizar usuario
        $user = $orm->findOne('users', $userId);
        $user->status = $newStatus;
        $user->updated_at = date('Y-m-d H:i:s');
        $orm->store($user);
        
        // Registrar cambio en log
        $log = $orm->dispense('user_logs');
        $log->user_id = $userId;
        $log->action = 'status_changed';
        $log->new_value = $newStatus;
        $log->created_at = date('Y-m-d H:i:s');
        $orm->store($log);
        
        $orm->exec('COMMIT');
        return true;
        
    } catch (Exception $e) {
        $orm->exec('ROLLBACK');
        error_log("Error en transferencia: " . $e->getMessage());
        return false;
    }
}
```

---

Estos ejemplos básicos cubren las operaciones más comunes que realizarás con VersaORM. Para casos más avanzados, consulta la documentación de ejemplos avanzados y las guías específicas de cada componente.
