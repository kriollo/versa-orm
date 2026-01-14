# JOINs - Combinando Datos de Múltiples Tablas

Los JOINs te permiten combinar datos de múltiples tablas relacionadas en una sola consulta. VersaORM soporta todosos de JOIN estándar de SQL.

## Conceptos Clave

- **INNER JOIN**: Solo registros que coinciden en ambas tablas
- **LEFT JOIN**: Todos los registros de la tabla izquierda + coincidencias de la derecha
- **RIGHT JOIN**: Todos los registros de la tabla derecha + coincidencias de la izquierda
- **Alias de tablas**: Nombres cortos para facilitar las referencias
- **Condiciones de JOIN**: Cómo se relacionan las tablas

## Estructura de datos de ejemplo

Para estos ejemplos, usaremos estas tablas relacionadas:

```sql
-- Tabla users
CREATE TABLE users (
    id INT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100)
);

-- Tabla posts
CREATE TABLE posts (
    id INT PRIMARY KEY,
    title VARCHAR(200),
    content TEXT,
    user_id INT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Tabla categories
CREATE TABLE categories (
    id INT PRIMARY KEY,
    name VARCHAR(50)
);

-- Tabla post_categories (muchos a muchos)
CREATE TABLE post_categories (
    post_id INT,
    category_id INT,
    PRIMARY KEY (post_id, category_id)
);
```

## INNER JOIN - Solo coincidencias

### Ejemplo básico

```php
// Posts con información del autor
$postsConAutor = $orm->table('posts')
    ->join('users', 'posts.user_id', '=', 'users.id')
    ->select(['posts.*', 'users.name as author_name', 'users.email as author_email'])
    ->getAll();

foreach ($postsConAutor as $post) {
    echo "Post: {$post['title']}\n";
    echo "Autor: {$post['author_name']} ({$post['author_email']})\n\n";
}
```

**SQL Equivalente:**
```sql
SELECT posts.*, users.name as author_name, users.email as author_email
FROM posts
INNER JOIN users ON posts.user_id = users.id;
```

**Devuelve:** Array de arrays asociativos con datos combinados de ambas tablas

### Ejemplo con filtros

```php
// Posts publicados con información del autor
$postsPublicados = $orm->table('posts')
    ->join('users', 'posts.user_id', '=', 'users.id')
    ->where('posts.published', '=', true)
    ->where('users.active', '=', true)
    ->select(['posts.title', 'posts.created_at', 'users.name as author'])
    ->orderBy('posts.created_at', 'DESC')
    ->getAll();
```

**SQL Equivalente:**
```sql
SELECT posts.title, posts.created_at, users.name as author
FROM posts
INNER JOIN users ON posts.user_id = users.id
WHERE posts.published = 1 AND users.active = 1
ORDER BY posts.created_at DESC;
```

## LEFT JOIN - Incluir todos los registros de la izquierda

### Ejemplo básico

```php
// Todos los usuarios con sus posts (incluso si no tienen posts)
$usuariosConPosts = $orm->table('users')
    ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
    ->select(['users.name', 'users.email', 'posts.title', 'posts.created_at'])
    ->orderBy('users.name')
    ->getAll();

foreach ($usuariosConPosts as $registro) {
    $post = $registro['title'] ? $registro['title'] : 'Sin posts';
    echo "Usuario: {$registro['name']} - Post: $post\n";
}
```

**SQL Equivalente:**
```sql
SELECT users.name, users.email, posts.title, posts.created_at
FROM users
LEFT JOIN posts ON users.id = posts.user_id
ORDER BY users.name;
```

### Encontrar registros sin relación

```php
// Usuarios que NO tienen posts
$usuariosSinPosts = $orm->table('users')
    ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
    ->whereNull('posts.id')
    ->select(['users.id', 'users.name', 'users.email'])
    ->getAll();

echo "Usuarios sin posts:\n";
foreach ($usuariosSinPosts as $usuario) {
    echo "- {$usuario['name']} ({$usuario['email']})\n";
}
```

**SQL Equivalente:**
```sql
SELECT users.id, users.name, users.email
FROM users
LEFT JOIN posts ON users.id = posts.user_id
WHERE posts.id IS NULL;
```

## RIGHT JOIN - Incluir todos los registros de la derecha

### Ejemplo básico

```php
// Todos los posts con información del usuario (incluso posts huérfanos)
$postsConUsuarios = $orm->table('posts')
    ->rightJoin('users', 'posts.user_id', '=', 'users.id')
    ->select(['posts.title', 'posts.created_at', 'users.name', 'users.email'])
    ->orderBy('users.name')
    ->getAll();
```

**SQL Equivalente:**
```sql
SELECT posts.title, posts.created_at, users.name, users.email
FROM posts
RIGHT JOIN users ON posts.user_id = users.id
ORDER BY users.name;
```

## JOINs múltiples

### Ejemplo con tres tablas

```php
// Posts con autor y categoría
$postsCompletos = $orm->table('posts')
    ->join('users', 'posts.user_id', '=', 'users.id')
    ->join('post_categories', 'posts.id', '=', 'post_categories.post_id')
    ->join('categories', 'post_categories.category_id', '=', 'categories.id')
    ->select([
        'posts.title',
        'posts.content',
        'posts.created_at',
        'users.name as author',
        'categories.name as category'
    ])
    ->where('posts.published', '=', true)
    ->orderBy('posts.created_at', 'DESC')
    ->getAll();

foreach ($postsCompletos as $post) {
    echo "Título: {$post['title']}\n";
    echo "Autor: {$post['author']}\n";
    echo "Categoría: {$post['category']}\n";
    echo "Fecha: {$post['created_at']}\n\n";
}
```

**SQL Equivalente:**
```sql
SELECT posts.title, posts.content, posts.created_at,
       users.name as author, categories.name as category
FROM posts
INNER JOIN users ON posts.user_id = users.id
INNER JOIN post_categories ON posts.id = post_categories.post_id
INNER JOIN categories ON post_categories.category_id = categories.id
WHERE posts.published = 1
ORDER BY posts.created_at DESC;
```

## Usando alias de tablas

### Ejemplo con alias

```php
// Usar alias para simplificar la consulta
$posts = $orm->table('posts as p')
    ->join('users as u', 'p.user_id', '=', 'u.id')
    ->join('post_categories as pc', 'p.id', '=', 'pc.post_id')
    ->join('categories as c', 'pc.category_id', '=', 'c.id')
    ->select([
        'p.title',
        'p.created_at',
        'u.name as author',
        'c.name as category'
    ])
    ->where('p.published', '=', true)
    ->getAll();
```

**SQL Equivalente:**
```sql
SELECT p.title, p.created_at, u.name as author, c.name as category
FROM posts as p
INNER JOIN users as u ON p.user_id = u.id
INNER JOIN post_categories as pc ON p.id = pc.post_id
INNER JOIN categories as c ON pc.category_id = c.id
WHERE p.published = 1;
```

## JOINs con condiciones adicionales

### JOIN con múltiples condiciones

```php
// Posts con autores activos y verificados
$posts = $orm->table('posts')
    ->join('users', function($join) {
        $join->on('posts.user_id', '=', 'users.id')
             ->where('users.active', '=', true)
             ->where('users.verified', '=', true);
    })
    ->select(['posts.title', 'users.name as author'])
    ->getAll();
```

**SQL Equivalente:**
```sql
SELECT posts.title, users.name as author
FROM posts
INNER JOIN users ON posts.user_id = users.id
                AND users.active = 1
                AND users.verified = 1;
```

## Agregaciones con JOINs

### Contar registros relacionados

```php
// Usuarios con el número de posts que han escrito
$usuariosConConteo = $orm->table('users')
    ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
    ->select(['users.name', 'users.email'])
    ->selectRaw('COUNT(posts.id) as total_posts')
    ->groupBy(['users.id', 'users.name', 'users.email'])
    ->orderBy('total_posts', 'DESC')
    ->getAll();

foreach ($usuariosConConteo as $usuario) {
    echo "{$usuario['name']}: {$usuario['total_posts']} posts\n";
}
```

**SQL Equivalente:**
```sql
SELECT users.name, users.email, COUNT(posts.id) as total_posts
FROM users
LEFT JOIN posts ON users.id = posts.user_id
GROUP BY users.id, users.name, users.email
ORDER BY total_posts DESC;
```

### Filtrar por agregaciones

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

## Ejemplo práctico completo

```php
<?php
require_once 'config/database.php';

try {
    echo "=== JOINs - Combinando Tablas ===\n\n";

    // 1. INNER JOIN básico
    echo "1. Posts con información del autor:\n";
    $postsConAutor = $orm->table('posts')
        ->join('users', 'posts.user_id', '=', 'users.id')
        ->select(['posts.title', 'users.name as author', 'posts.created_at'])
        ->where('posts.published', '=', true)
        ->orderBy('posts.created_at', 'DESC')
        ->limit(5)
        ->getAll();

    foreach ($postsConAutor as $post) {
        echo "- {$post['title']} por {$post['author']} ({$post['created_at']})\n";
    }

    // 2. LEFT JOIN para encontrar usuarios sin posts
    echo "\n2. Usuarios sin posts:\n";
    $usuariosSinPosts = $orm->table('users')
        ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
        ->whereNull('posts.id')
        ->select(['users.name', 'users.email'])
        ->getAll();

    if (empty($usuariosSinPosts)) {
        echo "- Todos los usuarios tienen al menos un post\n";
    } else {
        foreach ($usuariosSinPosts as $usuario) {
            echo "- {$usuario['name']} ({$usuario['email']})\n";
        }
    }

    // 3. JOIN múltiple con agregación
    echo "\n3. Estadísticas de usuarios:\n";
    $estadisticas = $orm->table('users')
        ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
        ->select(['users.name', 'users.email'])
        ->selectRaw('COUNT(posts.id) as total_posts')
        ->selectRaw('MAX(posts.created_at) as ultimo_post')
        ->groupBy(['users.id', 'users.name', 'users.email'])
        ->orderBy('total_posts', 'DESC')
        ->getAll();

    foreach ($estadisticas as $stat) {
        $ultimoPost = $stat['ultimo_post'] ? $stat['ultimo_post'] : 'Nunca';
        echo "- {$stat['name']}: {$stat['total_posts']} posts (Último: $ultimoPost)\n";
    }

    // 4. JOIN complejo con múltiples tablas
    echo "\n4. Posts con toda la información:\n";
    $postsCompletos = $orm->table('posts as p')
        ->join('users as u', 'p.user_id', '=', 'u.id')
        ->leftJoin('post_categories as pc', 'p.id', '=', 'pc.post_id')
        ->leftJoin('categories as c', 'pc.category_id', '=', 'c.id')
        ->select([
            'p.title',
            'u.name as author',
            'c.name as category',
            'p.created_at'
        ])
        ->where('p.published', '=', true)
        ->orderBy('p.created_at', 'DESC')
        ->limit(3)
        ->getAll();

    foreach ($postsCompletos as $post) {
        $categoria = $post['category'] ? $post['category'] : 'Sin categoría';
        echo "- {$post['title']}\n";
        echo "  Autor: {$post['author']}\n";
        echo "  Categoría: $categoria\n";
        echo "  Fecha: {$post['created_at']}\n\n";
    }

} catch (VersaORMException $e) {
    echo "Error en la consulta: " . $e->getMessage() . "\n";
}
```

## Mejores prácticas

### ✅ Recomendado

```php
// Usar alias para tablas con nombres largos
$orm->table('very_long_table_name as vlt')
    ->join('another_long_name as aln', 'vlt.id', '=', 'aln.foreign_id');

// Especificar columnas explícitamente para evitar conflictos
->select(['users.name', 'posts.title', 'posts.created_at'])

// Usar LEFT JOIN cuando necesites todos los registros de la tabla principal
$orm->table('users')->leftJoin('posts', 'users.id', '=', 'posts.user_id')
```

### ❌ Evitar

```php
// No usar SELECT * con JOINs (puede causar conflictos de nombres)
$orm->table('posts')->join('users', '...')->getAll(); // Evitar

// No hacer JOINs innecesarios
$orm->table('posts')
    ->join('users', '...')
    ->join('categories', '...') // Si no usas datos de categories

// No olvidar condiciones WHERE en JOINs complejos
$orm->table('posts')->join('users', '...')->getAll(); // Puede ser muy lento
```

## Errores comunes

### Error: Columnas ambiguas
```php
// Error: 'id' existe en ambas tablas
$orm->table('posts')
    ->join('users', 'posts.user_id', '=', 'users.id')
    ->where('id', '=', 1) // ¿posts.id o users.id?
    ->getAll();

// Solución: especificar la tabla
->where('posts.id', '=', 1)
```

### Error: JOIN sin condición
```php
// Error: falta la condición ON
$orm->table('posts')->join('users')->getAll();

// Solución: siempre especificar la condición
->join('users', 'posts.user_id', '=', 'users.id')
```

### Error: Usar INNER JOIN cuando necesitas LEFT JOIN
```php
// Problema: solo muestra usuarios que tienen posts
$orm->table('users')->join('posts', 'users.id', '=', 'posts.user_id');

// Solución: usar LEFT JOIN para incluir usuarios sin posts
->leftJoin('posts', 'users.id', '=', 'posts.user_id')
```

## JOINs RAW - SQL Personalizado

Para casos complejos donde necesitas control total sobre la cláusula JOIN, puedes usar los métodos `*JoinRaw()`.

### ¿Cuándo usar JOINs RAW?

- Subconsultas complejas en el JOIN
- Múltiples condiciones con lógica compleja
- Funciones SQL específicas del motor
- Optimizaciones avanzadas

⚠️ **ADVERTENCIA**: Los JOINs RAW permiten SQL arbitrario. Siempre usa **bindings parametrizados** para valores dinámicos y evita concatenar datos del usuario directamente en el SQL.

### joinRaw() - JOIN genérico con SQL crudo

```php
// JOIN con subconsulta y condiciones complejas
$campanasConConteo = $orm->table('campanas')
    ->select([
        'campanas.id',
        'campanas.nombre',
        'video_counts.video_count'
    ])
    ->joinRaw(
        'INNER JOIN (SELECT campana_id, COUNT(*) as video_count FROM videos GROUP BY campana_id) as video_counts ON video_counts.campana_id = campanas.id'
    )
    ->getAll();
```

### leftJoinRaw() - LEFT JOIN con SQL crudo

```php
// Ejemplo real: campañas con imágenes y conteo de videos
$qb = $orm->table('anima_campanas')->lazy();

$qb->select([
    'anima_campanas.id',
    'anima_campanas.nombre',
    'versa_users.name as nombre_usuario',
    'anima_campana_images.image_path as imagen_default',
    'video_counts.video_count'
])->selectRaw('COUNT(*) OVER() AS total_count');

// JOIN normal
$qb->join('versa_users', 'versa_users.id', '=', 'anima_campanas.id_user');

// LEFT JOIN con condición RAW
$qb->leftJoin('anima_campana_images', 'anima_campana_images.id_campana', '=', 'anima_campanas.id')
   ->onRaw('anima_campana_images.is_default = TRUE');

// LEFT JOIN RAW con subconsulta
$qb->leftJoinRaw(
    '(SELECT id_campana, COUNT(*) as video_count FROM anima_videos GROUP BY id_campana) as video_counts ON video_counts.id_campana = anima_campanas.id'
);

$result = $qb->collect();
```

### rightJoinRaw() - RIGHT JOIN con SQL crudo

```php
// RIGHT JOIN con tabla derivada
$result = $orm->table('productos')
    ->select(['productos.nombre', 'categorias.categoria', 'stats.total_vendido'])
    ->rightJoinRaw(
        '(SELECT categoria_id, SUM(cantidad) as total_vendido FROM ventas GROUP BY categoria_id) as stats ON stats.categoria_id = productos.categoria_id'
    )
    ->getAll();
```

### innerJoinRaw() - INNER JOIN con SQL crudo

```php
// INNER JOIN con condiciones complejas
$productosActivos = $orm->table('productos')
    ->select(['productos.*', 'stock.cantidad'])
    ->innerJoinRaw(
        'inventario stock ON stock.producto_id = productos.id AND stock.cantidad > 0 AND stock.activo = TRUE'
    )
    ->getAll();
```

### Usando bindings parametrizados (IMPORTANTE)

Siempre usa bindings para valores dinámicos:

```php
$minVideos = 2;
$estado = 'activo';

$result = $orm->table('campanas')
    ->select(['campanas.nombre', 'video_counts.video_count'])
    ->joinRaw(
        'INNER JOIN (SELECT campana_id, COUNT(*) as video_count FROM videos GROUP BY campana_id HAVING COUNT(*) >= ?) as video_counts ON video_counts.campana_id = campanas.id',
        [$minVideos]  // ← Bindings seguros
    )
    ->where('campanas.estado', '=', $estado)
    ->getAll();
```

### Combinando JOINs normales y RAW

Puedes mezclar JOINs estándar con JOINs RAW en la misma consulta:

```php
$resultado = $orm->table('users')
    ->select([
        'users.name',
        'posts.title',
        'stats.comment_count'
    ])
    ->join('posts', 'posts.user_id', '=', 'users.id')  // JOIN normal
    ->leftJoinRaw(                                       // JOIN RAW
        '(SELECT post_id, COUNT(*) as comment_count FROM comments GROUP BY post_id) as stats ON stats.post_id = posts.id'
    )
    ->where('users.active', '=', true)
    ->getAll();
```

### Características importantes

1. **Prefijos automáticos**: `leftJoinRaw()`, `rightJoinRaw()` e `innerJoinRaw()` agregan automáticamente el prefijo si no está presente:

```php
// Estas dos formas son equivalentes:
->leftJoinRaw('tabla ON condicion')
->leftJoinRaw('LEFT JOIN tabla ON condicion')
```

2. **Validación de seguridad**: VersaORM valida automáticamente expresiones RAW para prevenir patrones peligrosos (DDL, múltiples sentencias, etc.)

3. **Bindings seguros**: Los bindings se procesan mediante prepared statements de PDO, protegiéndote contra inyección SQL

### Errores comunes

```php
// ❌ NUNCA concatenes valores directamente
$valor = $_POST['status'];  // Peligroso!
->joinRaw("tabla ON campo = '$valor'")

// ✅ SIEMPRE usa bindings
$valor = $_POST['status'];
->joinRaw('tabla ON campo = ?', [$valor])

// ❌ No olvides la cláusula ON
->joinRaw('(SELECT ...) as alias')  // Error: falta ON

// ✅ Incluye siempre la condición ON
->joinRaw('(SELECT ...) as alias ON alias.id = tabla.id')
```

## Siguiente paso

Ahora que dominas los JOINs, aprende sobre [Ordenamiento y Paginación](ordenamiento-paginacion.md) para organizar y limitar tus resultados.

## Navegación

- **Anterior**: [Filtros WHERE](filtros-where.md)
- **Siguiente**: [Ordenamiento y Paginación](ordenamiento-paginacion.md)
- **Índice**: [Documentación Principal](../README.md)
