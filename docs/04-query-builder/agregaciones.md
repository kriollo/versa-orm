# Agregaciones - COUNT, SUM, AVG, GROUP BY, HAVING

Las funciones de agregación te permiten realizar cálculos sobre conjuntos de do contar registros, sumar valores, calcular promedios y agrupar resultados.

## Conceptos Clave

- **COUNT**: Cuenta el número de registros
- **SUM**: Suma valores numéricos
- **AVG**: Calcula el promedio de valores
- **MIN/MAX**: Encuentra valores mínimos y máximos
- **GROUP BY**: Agrupa registros por columnas específicas
- **HAVING**: Filtra grupos después de la agregación

## Función COUNT - Contar registros

### COUNT básico

```php
// Contar todos los usuarios
$totalUsuarios = $orm->table('users')->count();
echo "Total de usuarios: $totalUsuarios\n";

// Contar usuarios activos
$usuariosActivos = $orm->table('users')
    ->where('active', '=', true)
    ->count();
echo "Usuarios activos: $usuariosActivos\n";

// Contar posts publicados
$postsPublicados = $orm->table('posts')
    ->where('published', '=', true)
    ->count();
echo "Posts publicados: $postsPublicados\n";
```

**SQL Equivalente:**
```sql
SELECT COUNT(*) FROM users;
SELECT COUNT(*) FROM users WHERE active = 1;
SELECT COUNT(*) FROM posts WHERE published = 1;
```

**Devuelve:** Entero con el número de registros

### COUNT con condiciones complejas

```php
// Contar posts de un usuario específico
$postsDelUsuario = $orm->table('posts')
    ->where('user_id', '=', 5)
    ->where('published', '=', true)
    ->count();

// Contar usuarios registrados este año
$usuariosEsteAno = $orm->table('users')
    ->where('created_at', '>=', '2024-01-01')
    ->count();

echo "Posts del usuario 5: $postsDelUsuario\n";
echo "Usuarios registrados en 2024: $usuariosEsteAno\n";
```

## Función SUM - Sumar valores

### SUM básico

```php
// Suma total de ventas
$totalVentas = $orm->table('orders')
    ->sum('total_amount');
echo "Total de ventas: $" . number_format($totalVentas, 2) . "\n";

// Suma de puntos de todos los usuarios
$totalPuntos = $orm->table('users')
    ->sum('points');
echo "Total de puntos: $totalPuntos\n";
```

**SQL Equivalente:**
```sql
SELECT SUM(total_amount) FROM orders;
SELECT SUM(points) FROM users;
```

**Devuelve:** Número (float) con la suma total

### SUM con condiciones

```php
// Ventas del mes actual
$ventasDelMes = $orm->table('orders')
    ->where('created_at', '>=', date('Y-m-01'))
    ->where('status', '=', 'completed')
    ->sum('total_amount');

// Puntos de usuarios activos
$puntosActivos = $orm->table('users')
    ->where('active', '=', true)
    ->sum('points');

echo "Ventas del mes: $" . number_format($ventasDelMes, 2) . "\n";
echo "Puntos de usuarios activos: $puntosActivos\n";
```

## Función AVG - Calcular promedios

### AVG básico

```php
// Edad promedio de usuarios
$edadPromedio = $orm->table('users')
    ->avg('age');
echo "Edad promedio: " . round($edadPromedio, 1) . " años\n";

// Precio promedio de productos
$precioPromedio = $orm->table('products')
    ->avg('price');
echo "Precio promedio: $" . number_format($precioPromedio, 2) . "\n";
```

**SQL Equivalente:**
```sql
SELECT AVG(age) FROM users;
SELECT AVG(price) FROM products;
```

**Devuelve:** Número (float) con el promedio

### AVG con filtros

```php
// Promedio de calificaciones de productos activos
$calificacionPromedio = $orm->table('products')
    ->where('active', '=', true)
    ->where('rating', '>', 0)
    ->avg('rating');

// Promedio de ventas mensuales
$ventaPromedio = $orm->table('orders')
    ->where('status', '=', 'completed')
    ->where('created_at', '>=', date('Y-01-01'))
    ->avg('total_amount');

echo "Calificación promedio: " . round($calificacionPromedio, 2) . "/5\n";
echo "Venta promedio: $" . number_format($ventaPromedio, 2) . "\n";
```

## Funciones MIN y MAX

### MIN y MAX básicos

```php
// Producto más barato y más caro
$precioMinimo = $orm->table('products')->min('price');
$precioMaximo = $orm->table('products')->max('price');

// Usuario más joven y más viejo
$edadMinima = $orm->table('users')->min('age');
$edadMaxima = $orm->table('users')->max('age');

echo "Precio mínimo: $" . number_format($precioMinimo, 2) . "\n";
echo "Precio máximo: $" . number_format($precioMaximo, 2) . "\n";
echo "Edad mínima: $edadMinima años\n";
echo "Edad máxima: $edadMaxima años\n";
```

**SQL Equivalente:**
```sql
SELECT MIN(price) FROM products;
SELECT MAX(price) FROM products;
SELECT MIN(age) FROM users;
SELECT MAX(age) FROM users;
```

### Encontrar registros con valores MIN/MAX

```php
// Producto más caro
$productoMasCaro = $orm->table('products')
    ->where('price', '=', $orm->table('products')->max('price'))
    ->firstArray();

// Usuario más joven
$usuarioMasJoven = $orm->table('users')
    ->where('age', '=', $orm->table('users')->min('age'))
    ->firstArray();

if ($productoMasCaro) {
    echo "Producto más caro: {$productoMasCaro['name']} - $" .
         number_format($productoMasCaro['price'], 2) . "\n";
}
```

## GROUP BY - Agrupar resultados

### GROUP BY básico

```php
// Contar posts por usuario
$postsPorUsuario = $orm->table('posts')
    ->join('users', 'posts.user_id', '=', 'users.id')
    ->select(['users.name', 'users.email'])
    ->selectRaw('COUNT(posts.id) as total_posts')
    ->groupBy(['users.id', 'users.name', 'users.email'])
    ->orderBy('total_posts', 'DESC')
    ->getAll();

echo "Posts por usuario:\n";
foreach ($postsPorUsuario as $usuario) {
    echo "- {$usuario['name']}: {$usuario['total_posts']} posts\n";
}
```

**SQL Equivalente:**
```sql
SELECT users.name, users.email, COUNT(posts.id) as total_posts
FROM posts
INNER JOIN users ON posts.user_id = users.id
GROUP BY users.id, users.name, users.email
ORDER BY total_posts DESC;
```

### GROUP BY con múltiples agregaciones

```php
// Estadísticas por categoría de producto
$estadisticasCategorias = $orm->table('products')
    ->select(['category'])
    ->selectRaw('COUNT(*) as total_productos')
    ->selectRaw('AVG(price) as precio_promedio')
    ->selectRaw('MIN(price) as precio_minimo')
    ->selectRaw('MAX(price) as precio_maximo')
    ->selectRaw('SUM(stock) as stock_total')
    ->groupBy('category')
    ->orderBy('total_productos', 'DESC')
    ->getAll();

echo "Estadísticas por categoría:\n";
foreach ($estadisticasCategorias as $cat) {
    echo "Categoría: {$cat['category']}\n";
    echo "- Productos: {$cat['total_productos']}\n";
    echo "- Precio promedio: $" . number_format($cat['precio_promedio'], 2) . "\n";
    echo "- Rango de precios: $" . number_format($cat['precio_minimo'], 2) .
         " - $" . number_format($cat['precio_maximo'], 2) . "\n";
    echo "- Stock total: {$cat['stock_total']}\n\n";
}
```

### GROUP BY por fechas

```php
// Posts por mes
$postsPorMes = $orm->table('posts')
    ->selectRaw('YEAR(created_at) as año')
    ->selectRaw('MONTH(created_at) as mes')
    ->selectRaw('COUNT(*) as total_posts')
    ->where('published', '=', true)
    ->groupByRaw('YEAR(created_at), MONTH(created_at)')
    ->orderByRaw('YEAR(created_at) DESC, MONTH(created_at) DESC')
    ->getAll();

echo "Posts por mes:\n";
foreach ($postsPorMes as $mes) {
    $nombreMes = date('F', mktime(0, 0, 0, $mes['mes'], 1));
    echo "- {$nombreMes} {$mes['año']}: {$mes['total_posts']} posts\n";
}
```

**SQL Equivalente:**
```sql
SELECT YEAR(created_at) as año, MONTH(created_at) as mes, COUNT(*) as total_posts
FROM posts
WHERE published = 1
GROUP BY YEAR(created_at), MONTH(created_at)
ORDER BY YEAR(created_at) DESC, MONTH(created_at) DESC;
```

## HAVING - Filtrar grupos

### HAVING básico

```php
// Usuarios con más de 5 posts
$usuariosActivos = $orm->table('users')
    ->join('posts', 'users.id', '=', 'posts.user_id')
    ->select(['users.name', 'users.email'])
    ->selectRaw('COUNT(posts.id) as total_posts')
    ->groupBy(['users.id', 'users.name', 'users.email'])
    ->having('total_posts', '>', 5)
    ->orderBy('total_posts', 'DESC')
    ->getAll();

echo "Usuarios con más de 5 posts:\n";
foreach ($usuariosActivos as $usuario) {
    echo "- {$usuario['name']}: {$usuario['total_posts']} posts\n";
}
```

**SQL Equivalente:**
```sql
SELECT users.name, users.email, COUNT(posts.id) as total_posts
FROM users
INNER JOIN posts ON users.id = posts.user_id
GROUP BY users.id, users.name, users.email
HAVING total_posts > 5
ORDER BY total_posts DESC;
```

### HAVING con múltiples condiciones

```php
// Categorías con más de 10 productos y precio promedio mayor a $50
$categoriasPopulares = $orm->table('products')
    ->select(['category'])
    ->selectRaw('COUNT(*) as total_productos')
    ->selectRaw('AVG(price) as precio_promedio')
    ->groupBy('category')
    ->having('total_productos', '>', 10)
    ->having('precio_promedio', '>', 50)
    ->orderBy('precio_promedio', 'DESC')
    ->getAll();

echo "Categorías populares y caras:\n";
foreach ($categoriasPopulares as $cat) {
    echo "- {$cat['category']}: {$cat['total_productos']} productos, " .
         "promedio $" . number_format($cat['precio_promedio'], 2) . "\n";
}
```

### HAVING con rangos

```php
// Usuarios con actividad moderada (entre 3 y 15 posts)
$usuariosModerados = $orm->table('users')
    ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
    ->select(['users.name', 'users.email'])
    ->selectRaw('COUNT(posts.id) as total_posts')
    ->groupBy(['users.id', 'users.name', 'users.email'])
    ->havingBetween('total_posts', [3, 15])
    ->orderBy('total_posts', 'DESC')
    ->getAll();
```

## Agregaciones complejas con subconsultas

### Comparar con promedios

```php
// Productos con precio mayor al promedio
$precioPromedio = $orm->table('products')->avg('price');

$productosCaros = $orm->table('products')
    ->where('price', '>', $precioPromedio)
    ->orderBy('price', 'DESC')
    ->getAll();

echo "Precio promedio: $" . number_format($precioPromedio, 2) . "\n";
echo "Productos más caros que el promedio:\n";
foreach ($productosCaros as $producto) {
    echo "- {$producto['name']}: $" . number_format($producto['price'], 2) . "\n";
}
```

### Top N por categoría

```php
// Los 2 productos más caros de cada categoría
$topProductos = $orm->table('products as p1')
    ->select(['p1.name', 'p1.category', 'p1.price'])
    ->whereRaw('(
        SELECT COUNT(*)
        FROM products as p2
        WHERE p2.category = p1.category
        AND p2.price > p1.price
    ) < 2')
    ->orderBy('p1.category')
    ->orderBy('p1.price', 'DESC')
    ->getAll();

$categoriaActual = '';
foreach ($topProductos as $producto) {
    if ($producto['category'] !== $categoriaActual) {
        $categoriaActual = $producto['category'];
        echo "\n=== {$categoriaActual} ===\n";
    }
    echo "- {$producto['name']}: $" . number_format($producto['price'], 2) . "\n";
}
```

## Ejemplo práctico completo

```php
<?php
require_once 'config/database.php';

try {
    echo "=== Agregaciones y Estadísticas ===\n\n";

    // 1. Estadísticas básicas
    echo "1. Estadísticas generales:\n";
    $totalUsuarios = $orm->table('users')->count();
    $usuariosActivos = $orm->table('users')->where('active', '=', true)->count();
    $totalPosts = $orm->table('posts')->count();
    $postsPublicados = $orm->table('posts')->where('published', '=', true)->count();

    echo "- Total usuarios: $totalUsuarios (Activos: $usuariosActivos)\n";
    echo "- Total posts: $totalPosts (Publicados: $postsPublicados)\n";

    // 2. Promedios y rangos
    echo "\n2. Análisis de datos:\n";
    if ($orm->table('users')->where('age', '>', 0)->count() > 0) {
        $edadPromedio = $orm->table('users')->where('age', '>', 0)->avg('age');
        $edadMinima = $orm->table('users')->where('age', '>', 0)->min('age');
        $edadMaxima = $orm->table('users')->where('age', '>', 0)->max('age');

        echo "- Edad promedio: " . round($edadPromedio, 1) . " años\n";
        echo "- Rango de edades: $edadMinima - $edadMaxima años\n";
    }

    // 3. Agrupación por usuario
    echo "\n3. Top 5 usuarios más activos:\n";
    $topUsuarios = $orm->table('users')
        ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
        ->select(['users.name', 'users.email'])
        ->selectRaw('COUNT(posts.id) as total_posts')
        ->groupBy(['users.id', 'users.name', 'users.email'])
        ->orderBy('total_posts', 'DESC')
        ->limit(5)
        ->getAll();

    foreach ($topUsuarios as $i => $usuario) {
        $posicion = $i + 1;
        echo "$posicion. {$usuario['name']}: {$usuario['total_posts']} posts\n";
    }

    // 4. Análisis temporal
    echo "\n4. Posts por mes (últimos 6 meses):\n";
    $postsPorMes = $orm->table('posts')
        ->selectRaw('YEAR(created_at) as año')
        ->selectRaw('MONTH(created_at) as mes')
        ->selectRaw('MONTHNAME(created_at) as nombre_mes')
        ->selectRaw('COUNT(*) as total_posts')
        ->where('created_at', '>=', date('Y-m-d', strtotime('-6 months')))
        ->groupByRaw('YEAR(created_at), MONTH(created_at)')
        ->orderByRaw('YEAR(created_at) DESC, MONTH(created_at) DESC')
        ->getAll();

    foreach ($postsPorMes as $mes) {
        echo "- {$mes['nombre_mes']} {$mes['año']}: {$mes['total_posts']} posts\n";
    }

    // 5. Usuarios con actividad moderada
    echo "\n5. Usuarios con actividad moderada (3-10 posts):\n";
    $usuariosModerados = $orm->table('users')
        ->join('posts', 'users.id', '=', 'posts.user_id')
        ->select(['users.name'])
        ->selectRaw('COUNT(posts.id) as total_posts')
        ->groupBy(['users.id', 'users.name'])
        ->havingBetween('total_posts', [3, 10])
        ->orderBy('total_posts', 'DESC')
        ->getAll();

    if (empty($usuariosModerados)) {
        echo "- No hay usuarios en este rango\n";
    } else {
        foreach ($usuariosModerados as $usuario) {
            echo "- {$usuario['name']}: {$usuario['total_posts']} posts\n";
        }
    }

    // 6. Resumen de rendimiento
    echo "\n6. Métricas de rendimiento:\n";
    $promedioPostsPorUsuario = $orm->table('posts')
        ->join('users', 'posts.user_id', '=', 'users.id')
        ->selectRaw('COUNT(posts.id) / COUNT(DISTINCT users.id) as promedio')
        ->firstArray();

    if ($promedioPostsPorUsuario) {
        echo "- Promedio de posts por usuario: " .
             round($promedioPostsPorUsuario['promedio'], 2) . "\n";
    }

    $usuariosConPosts = $orm->table('users')
        ->join('posts', 'users.id', '=', 'posts.user_id')
        ->distinct()
        ->count('users.id');

    $porcentajeActivos = ($usuariosConPosts / $totalUsuarios) * 100;
    echo "- Usuarios que han publicado: $usuariosConPosts de $totalUsuarios " .
         "(" . round($porcentajeActivos, 1) . "%)\n";

} catch (VersaORMException $e) {
    echo "Error en la consulta: " . $e->getMessage() . "\n";
}
```

## Mejores prácticas

### ✅ Recomendado

```php
// Usar índices en columnas de GROUP BY
// CREATE INDEX idx_posts_user_id ON posts(user_id);

// Combinar múltiples agregaciones en una consulta
$stats = $orm->table('orders')
    ->selectRaw('COUNT(*) as total, SUM(amount) as sum, AVG(amount) as avg')
    ->firstArray();

// Usar HAVING para filtrar grupos, WHERE para filtrar registros
$query->where('active', '=', true)      // Filtrar antes de agrupar
      ->groupBy('category')
      ->having('total', '>', 10);        // Filtrar después de agrupar
```

### ❌ Evitar

```php
// No usar agregaciones sin GROUP BY en columnas no agregadas
$orm->table('posts')
    ->select(['user_id', 'COUNT(*)']) // Error: user_id debe estar en GROUP BY
    ->getAll();

// No usar WHERE con funciones agregadas (usar HAVING)
$orm->table('posts')
    ->where('COUNT(*)', '>', 5) // Error: usar HAVING
    ->groupBy('user_id');

// No hacer múltiples consultas cuando puedes usar una con agregación
$total = $orm->table('orders')->count();
$sum = $orm->table('orders')->sum('amount'); // Ineficiente

// Mejor:
$stats = $orm->table('orders')
    ->selectRaw('COUNT(*) as total, SUM(amount) as sum')
    ->firstArray();
```

## Errores comunes

### Error: Columna no agregada en SELECT
```php
// Error: name no está en GROUP BY ni es una función agregada
$orm->table('users')
    ->select(['name', 'COUNT(*)'])
    ->groupBy('department'); // Error

// Solución: incluir en GROUP BY o usar función agregada
$orm->table('users')
    ->select(['name'])
    ->selectRaw('COUNT(*) as total')
    ->groupBy(['department', 'name']); // Correcto
```

### Error: Usar WHERE con funciones agregadas
```php
// Error: WHERE no puede usar funciones agregadas
$orm->table('posts')
    ->where('COUNT(*)', '>', 5)
    ->groupBy('user_id'); // Error

// Solución: usar HAVING
$orm->table('posts')
    ->groupBy('user_id')
    ->having('COUNT(*)', '>', 5); // Correcto
```

### Error: GROUP BY incompleto
```php
// Error: todas las columnas no agregadas deben estar en GROUP BY
$orm->table('users')
    ->select(['name', 'email', 'COUNT(*)'])
    ->groupBy('name'); // Error: falta email

// Solución: incluir todas las columnas
$orm->table('users')
    ->select(['name', 'email', 'COUNT(*)'])
    ->groupBy(['name', 'email']); // Correcto
```

## Siguiente paso

¡Felicidades! Has completado la sección del Query Builder. Ahora puedes continuar con [Tipos de Relaciones](../05-relaciones/tipos-relaciones.md) para aprender sobre las relaciones entre modelos.

## Navegación

- **Anterior**: [Ordenamiento y Paginación](ordenamiento-paginacion.md)
- **Siguiente**: [Tipos de Relaciones](../05-relaciones/tipos-relaciones.md)
- **Índice**: [Documentación Principal](../README.md)
