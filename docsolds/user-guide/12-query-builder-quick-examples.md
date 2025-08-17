# 🚀 Query Builder - Ejemplos Rápidos

Esta guía contiene **ejemplos listos para usar** del Query Builder de VersaORM. Perfecta para referencia rápida y copy-paste.

## 📖 Índice de Ejemplos

1. [🔍 Búsquedas Básicas](#-búsquedas-básicas)
2. [📊 Filtrado Avanzado](#-filtrado-avanzado)  
3. [🔗 Joins y Relaciones](#-joins-y-relaciones)
4. [📈 Agregaciones y Estadísticas](#-agregaciones-y-estadísticas)
5. [✏️ Operaciones de Escritura](#️-operaciones-de-escritura)
6. [🎯 Casos Específicos](#-casos-específicos)
7. [⚡ Optimizaciones con Lazy Mode](#-optimizaciones-con-lazy-mode)

---

## 🔍 Búsquedas Básicas

### Obtener Todos los Registros
```php
$users = $orm->table('users')->getAll();
$users = $orm->table('users')->findAll(); // Como objetos
```

### Buscar por ID
```php
$user = $orm->table('users')->where('id', '=', 1)->firstArray();
$user = $orm->table('users')->where('id', '=', 1)->findOne(); // Como objeto
```

### Buscar con Múltiples Condiciones
```php
$activeAdults = $orm->table('users')
    ->where('status', '=', 'active')
    ->where('age', '>=', 18)
    ->getAll();
```

### Búsqueda LIKE (Texto)
```php
$users = $orm->table('users')
    ->where('name', 'LIKE', '%juan%')
    ->orWhere('email', 'LIKE', '%juan%')
    ->getAll();
```

### Buscar con IN
```php
$admins = $orm->table('users')
    ->whereIn('role', ['admin', 'super_admin', 'moderator'])
    ->getAll();
```

---

## 📊 Filtrado Avanzado

### Rangos de Fecha
```php
$recentOrders = $orm->table('orders')
    ->whereBetween('created_at', '2024-01-01', '2024-01-31')
    ->where('status', '!=', 'cancelled')
    ->orderBy('created_at', 'desc')
    ->getAll();
```

### Filtros Condicionales
```php
$products = $orm->table('products')
    ->where('status', '=', 'published');

if ($categoryId) {
    $products->where('category_id', '=', $categoryId);
}

if ($minPrice > 0) {
    $products->where('price', '>=', $minPrice);
}

$results = $products->getAll();
```

### Filtros con Valores NULL
```php
$incompleteProfiles = $orm->table('users')
    ->whereNull('avatar')
    ->whereNotNull('email')
    ->getAll();
```

---

## 🔗 Joins y Relaciones

### Inner Join Básico
```php
$usersWithPosts = $orm->table('users')
    ->select(['users.name', 'posts.title', 'posts.created_at'])
    ->join('posts', 'users.id', '=', 'posts.user_id')
    ->getAll();
```

### Left Join con Condiciones
```php
$usersAndProfiles = $orm->table('users')
    ->select(['users.*', 'profiles.bio', 'profiles.avatar'])
    ->leftJoin('profiles', 'users.id', '=', 'profiles.user_id')
    ->where('users.status', '=', 'active')
    ->getAll();
```

### Join Múltiple
```php
$orderDetails = $orm->table('orders')
    ->select([
        'orders.*',
        'users.name as customer_name',
        'users.email as customer_email',
        'products.name as product_name'
    ])
    ->join('users', 'orders.user_id', '=', 'users.id')
    ->join('order_items', 'orders.id', '=', 'order_items.order_id')
    ->join('products', 'order_items.product_id', '=', 'products.id')
    ->where('orders.status', '=', 'completed')
    ->getAll();
```

---

## 📈 Agregaciones y Estadísticas

### Conteos Básicos
```php
$totalUsers = $orm->table('users')->count();
$activeUsers = $orm->table('users')->where('status', '=', 'active')->count();
```

### Estadísticas del Usuario
```php
$userStats = $orm->table('users')
    ->select([
        'COUNT(*) as total_users',
        'COUNT(CASE WHEN status = "active" THEN 1 END) as active_users',
        'COUNT(CASE WHEN created_at >= CURDATE() THEN 1 END) as today_registrations'
    ])
    ->firstArray();
```

### Reportes por Agrupación
```php
$salesByMonth = $orm->table('orders')
    ->select([
        'DATE_FORMAT(created_at, "%Y-%m") as month',
        'COUNT(*) as order_count',
        'SUM(total) as revenue',
        'AVG(total) as avg_order_value'
    ])
    ->where('status', '=', 'completed')
    ->groupBy('month')
    ->orderBy('month', 'desc')
    ->getAll();
```

### Top N Consultas
```php
$topCustomers = $orm->table('users')
    ->select([
        'users.name',
        'users.email',
        'COUNT(orders.id) as order_count',
        'SUM(orders.total) as total_spent'
    ])
    ->join('orders', 'users.id', '=', 'orders.user_id')
    ->where('orders.status', '=', 'completed')
    ->groupBy(['users.id', 'users.name', 'users.email'])
    ->orderBy('total_spent', 'desc')
    ->limit(10)
    ->getAll();
```

---

## ✏️ Operaciones de Escritura

### Insertar Registro
```php
$newUserId = $orm->table('users')->insertGetId([
    'name' => 'Juan Pérez',
    'email' => 'juan@example.com',
    'status' => 'active'
]);
```

### Actualización Condicional
```php
$updatedRows = $orm->table('users')
    ->where('last_login', '<', date('Y-m-d', strtotime('-90 days')))
    ->update(['status' => 'inactive']);
```

### Eliminar con Condiciones
```php
$deletedRows = $orm->table('logs')
    ->where('level', '=', 'debug')
    ->where('created_at', '<', date('Y-m-d', strtotime('-7 days')))
    ->delete();
```

### Upsert (Insert o Update)
```php
$orm->table('user_settings')->upsert([
    'user_id' => 123,
    'setting_name' => 'theme',
    'setting_value' => 'dark'
], ['user_id', 'setting_name']); // Claves únicas
```

---

## 🎯 Casos Específicos

### Paginación Simple
```php
$page = 1;
$perPage = 15;

$users = $orm->table('users')
    ->where('status', '=', 'active')
    ->orderBy('created_at', 'desc')
    ->limit($perPage)
    ->offset(($page - 1) * $perPage)
    ->getAll();

$totalCount = $orm->table('users')
    ->where('status', '=', 'active')
    ->count();
```

### Búsqueda con Scoring/Relevancia
```php
$searchTerm = 'desarrollador';
$results = $orm->table('users')
    ->select([
        '*',
        'CASE 
            WHEN name LIKE "%' . $searchTerm . '%" THEN 3
            WHEN email LIKE "%' . $searchTerm . '%" THEN 2  
            WHEN bio LIKE "%' . $searchTerm . '%" THEN 1
            ELSE 0 
         END as relevance_score'
    ])
    ->whereRaw('(name LIKE ? OR email LIKE ? OR bio LIKE ?)', [
        "%{$searchTerm}%", "%{$searchTerm}%", "%{$searchTerm}%"
    ])
    ->orderBy('relevance_score', 'desc')
    ->orderBy('created_at', 'desc')
    ->getAll();
```

### Subconsultas con EXISTS
```php
$authorsWithRecentPosts = $orm->table('users')
    ->whereRaw('EXISTS (
        SELECT 1 FROM posts 
        WHERE posts.user_id = users.id 
        AND posts.created_at >= ? 
        AND posts.status = "published"
    )', [date('Y-m-d', strtotime('-30 days'))])
    ->orderBy('name')
    ->getAll();
```

### Duplicados y Limpieza
```php
// Encontrar emails duplicados
$duplicateEmails = $orm->table('users')
    ->select(['email', 'COUNT(*) as count'])
    ->groupBy('email')
    ->having('count', '>', 1)
    ->getAll();

// Mantener solo el registro más reciente de cada email
$orm->table('users')
    ->whereRaw('id NOT IN (
        SELECT MAX(id) FROM users GROUP BY email
    )')
    ->delete();
```

---

## ⚡ Optimizaciones con Lazy Mode

### Consulta Compleja Optimizada
```php
$complexData = $orm->table('orders')
    ->lazy() // 🚀 Activa optimización automática
    ->select([
        'orders.*',
        'users.name as customer_name',
        'COUNT(order_items.id) as item_count',
        'SUM(order_items.price * order_items.quantity) as total_amount'
    ])
    ->join('users', 'orders.user_id', '=', 'users.id')
    ->join('order_items', 'orders.id', '=', 'order_items.order_id')
    ->where('orders.created_at', '>=', date('Y-m-d', strtotime('-30 days')))
    ->where('orders.status', '=', 'completed')
    ->groupBy(['orders.id'])
    ->having('item_count', '>', 1)
    ->orderBy('total_amount', 'desc')
    ->collect(); // ✅ Ejecuta con optimizaciones
```

### Dashboard con Múltiples Métricas
```php
$dashboard = $orm->table('orders')
    ->lazy()
    ->select([
        'DATE(created_at) as date',
        'COUNT(*) as daily_orders',
        'SUM(total) as daily_revenue',
        'AVG(total) as avg_order_value',
        'COUNT(DISTINCT user_id) as unique_customers'
    ])
    ->where('created_at', '>=', date('Y-m-d', strtotime('-30 days')))
    ->where('status', '=', 'completed')
    ->groupBy('date')
    ->orderBy('date', 'desc')
    ->collect();
```

---

## 💡 Tips de Rendimiento

### ✅ Buenas Prácticas
```php
// Seleccionar solo columnas necesarias
$lightUsers = $orm->table('users')
    ->select(['id', 'name', 'email']) // No traer columnas innecesarias
    ->where('status', '=', 'active')
    ->getAll();

// Usar índices eficientemente
$indexedQuery = $orm->table('orders')
    ->where('user_id', '=', $userId)     // Índice en user_id
    ->where('status', '=', 'completed')  // Índice en status  
    ->orderBy('created_at', 'desc')      // Índice en created_at
    ->limit(10)
    ->getAll();
```

### ❌ Evitar
```php
// MAL: SQL injection vulnerable
$badQuery = $orm->table('users')
    ->whereRaw("name = '{$userInput}'"); // ¡PELIGROSO!

// BIEN: Siempre usar parámetros
$goodQuery = $orm->table('users')
    ->whereRaw('name = ?', [$userInput]);

// MAL: Traer todo cuando solo necesitas algunos campos
$wasteful = $orm->table('users')->getAll(); // Trae todas las columnas

// BIEN: Solo lo que necesitas
$efficient = $orm->table('users')
    ->select(['id', 'name'])
    ->getAll();
```

---

## 🔗 Enlaces Relacionados

- **[Guía Completa del Query Builder](02-query-builder.md)** - Documentación detallada
- **[Modo Lazy y Optimizaciones](10-lazy-mode-query-planner.md)** - Rendimiento avanzado
- **[Operaciones Batch](03-batch-operations.md)** - Operaciones masivas eficientes

---

> **💡 Tip:** Estos ejemplos están listos para copy-paste. Solo reemplaza los nombres de tablas y columnas por los de tu aplicación. Para consultas complejas, siempre considera usar el **Modo Lazy** para obtener optimizaciones automáticas.
