# Ordenamiento y Paginación

El ordenamiento y la paginación son fundamentales para crear interfaces de usuario eficientes y organizar grandes conjuntos dtos de manera manejable.

## Conceptos Clave

- **ORDER BY**: Ordena resultados por una o más columnas
- **LIMIT**: Limita el número de resultados
- **OFFSET**: Omite un número específico de registros
- **Paginación**: Divide resultados en páginas manejables
- **Ordenamiento múltiple**: Combina varios criterios de ordenamiento

## Ordenamiento básico

### Ordenamiento ascendente (ASC)

```php
// Usuarios ordenados por nombre (A-Z)
$usuarios = $orm->table('users')
    ->orderBy('name', 'ASC')
    ->getAll();

// También puedes omitir 'ASC' (es el valor por defecto)
$usuarios = $orm->table('users')
    ->orderBy('name')
    ->getAll();

foreach ($usuarios as $usuario) {
    echo "- {$usuario['name']}\n";
}
```

**SQL Equivalente:**
```sql
SELECT * FROM users ORDER BY name ASC;
```

### Ordenamiento descendente (DESC)

```php
// Posts más recientes primero
$postsRecientes = $orm->table('posts')
    ->orderBy('created_at', 'DESC')
    ->getAll();

// Usuarios por edad (mayor a menor)
$usuariosPorEdad = $orm->table('users')
    ->orderBy('age', 'DESC')
    ->getAll();
```

**SQL Equivalente:**
```sql
SELECT * FROM posts ORDER BY created_at DESC;
SELECT * FROM users ORDER BY age DESC;
```

## Ordenamiento múltiple

### Múltiples criterios

```php
// Ordenar por categoría y luego por fecha
$posts = $orm->table('posts')
    ->orderBy('category', 'ASC')
    ->orderBy('created_at', 'DESC')
    ->getAll();

// Usuarios por estado activo y luego por nombre
$usuarios = $orm->table('users')
    ->orderBy('active', 'DESC')  // Activos primero
    ->orderBy('name', 'ASC')     // Luego alfabéticamente
    ->getAll();
```

**SQL Equivalente:**
```sql
SELECT * FROM posts ORDER BY category ASC, created_at DESC;
SELECT * FROM users ORDER BY active DESC, name ASC;
```

### Ejemplo práctico con múltiples criterios

```php
// Lista de empleados: primero por departamento, luego por salario (mayor a menor), luego por nombre
$empleados = $orm->table('employees')
    ->orderBy('department', 'ASC')
    ->orderBy('salary', 'DESC')
    ->orderBy('name', 'ASC')
    ->getAll();

$departamentoActual = '';
foreach ($empleados as $empleado) {
    if ($empleado['department'] !== $departamentoActual) {
        $departamentoActual = $empleado['department'];
        echo "\n=== {$departamentoActual} ===\n";
    }
    echo "- {$empleado['name']} (${$empleado['salary']})\n";
}
```

## Limitando resultados con LIMIT

### Límite básico

```php
// Los 10 posts más recientes
$postsRecientes = $orm->table('posts')
    ->orderBy('created_at', 'DESC')
    ->limit(10)
    ->getAll();

echo "Los 10 posts más recientes:\n";
foreach ($postsRecientes as $post) {
    echo "- {$post['title']} ({$post['created_at']})\n";
}
```

**SQL Equivalente:**
```sql
SELECT * FROM posts ORDER BY created_at DESC LIMIT 10;
```

### Top N con condiciones

```php
// Los 5 usuarios más activos (con más posts)
$usuariosActivos = $orm->table('users')
    ->join('posts', 'users.id', '=', 'posts.user_id')
    ->select(['users.name', 'users.email'])
    ->selectRaw('COUNT(posts.id) as total_posts')
    ->groupBy(['users.id', 'users.name', 'users.email'])
    ->orderBy('total_posts', 'DESC')
    ->limit(5)
    ->getAll();

echo "Top 5 usuarios más activos:\n";
foreach ($usuariosActivos as $i => $usuario) {
    $posicion = $i + 1;
    echo "$posicion. {$usuario['name']}: {$usuario['total_posts']} posts\n";
}
```

**SQL Equivalente:**
```sql
SELECT users.name, users.email, COUNT(posts.id) as total_posts
FROM users
INNER JOIN posts ON users.id = posts.user_id
GROUP BY users.id, users.name, users.email
ORDER BY total_posts DESC
LIMIT 5;
```

## Paginación con OFFSET

### Paginación básica

```php
function obtenerPagina($pagina = 1, $porPagina = 10) {
    global $orm;

    $offset = ($pagina - 1) * $porPagina;

    $posts = $orm->table('posts')
        ->where('published', '=', true)
        ->orderBy('created_at', 'DESC')
        ->limit($porPagina)
        ->offset($offset)
        ->getAll();

    return $posts;
}

// Obtener la primera página (posts 1-10)
$pagina1 = obtenerPagina(1, 10);

// Obtener la segunda página (posts 11-20)
$pagina2 = obtenerPagina(2, 10);

// Obtener la tercera página (posts 21-30)
$pagina3 = obtenerPagina(3, 10);
```

**SQL Equivalente:**
```sql
-- Página 1
SELECT * FROM posts WHERE published = 1 ORDER BY created_at DESC LIMIT 10 OFFSET 0;

-- Página 2
SELECT * FROM posts WHERE published = 1 ORDER BY created_at DESC LIMIT 10 OFFSET 10;

-- Página 3
SELECT * FROM posts WHERE published = 1 ORDER BY created_at DESC LIMIT 10 OFFSET 20;
```

### Sistema de paginación completo

```php
class Paginador {
    private $orm;
    private $tabla;
    private $porPagina;

    public function __construct($orm, $tabla, $porPagina = 10) {
        $this->orm = $orm;
        $this->tabla = $tabla;
        $this->porPagina = $porPagina;
    }

    public function paginar($pagina = 1, $condiciones = []) {
        $query = $this->orm->table($this->tabla);

        // Aplicar condiciones
        foreach ($condiciones as $campo => $valor) {
            $query->where($campo, '=', $valor);
        }

        // Contar total de registros
        $total = $query->count();

        // Calcular paginación
        $totalPaginas = ceil($total / $this->porPagina);
        $offset = ($pagina - 1) * $this->porPagina;

        // Obtener registros de la página actual
        $registros = $query->limit($this->porPagina)
                          ->offset($offset)
                          ->orderBy('created_at', 'DESC')
                          ->getAll();

        return [
            'datos' => $registros,
            'paginacion' => [
                'pagina_actual' => $pagina,
                'por_pagina' => $this->porPagina,
                'total_registros' => $total,
                'total_paginas' => $totalPaginas,
                'tiene_anterior' => $pagina > 1,
                'tiene_siguiente' => $pagina < $totalPaginas
            ]
        ];
    }
}

// Uso del paginador
$paginador = new Paginador($orm, 'posts', 5);
$resultado = $paginador->paginar(2, ['published' => true]);

echo "Página {$resultado['paginacion']['pagina_actual']} de {$resultado['paginacion']['total_paginas']}\n";
echo "Total de registros: {$resultado['paginacion']['total_registros']}\n\n";

foreach ($resultado['datos'] as $post) {
    echo "- {$post['title']}\n";
}

if ($resultado['paginacion']['tiene_anterior']) {
    echo "\n← Página anterior disponible\n";
}
if ($resultado['paginacion']['tiene_siguiente']) {
    echo "→ Página siguiente disponible\n";
}
```

## Ordenamiento con JOINs

### Ordenar por columnas de tablas relacionadas

```php
// Posts ordenados por nombre del autor
$posts = $orm->table('posts')
    ->join('users', 'posts.user_id', '=', 'users.id')
    ->select(['posts.title', 'posts.created_at', 'users.name as author'])
    ->orderBy('users.name', 'ASC')
    ->orderBy('posts.created_at', 'DESC')
    ->getAll();

foreach ($posts as $post) {
    echo "- {$post['title']} por {$post['author']} ({$post['created_at']})\n";
}
```

**SQL Equivalente:**
```sql
SELECT posts.title, posts.created_at, users.name as author
FROM posts
INNER JOIN users ON posts.user_id = users.id
ORDER BY users.name ASC, posts.created_at DESC;
```

### Paginación con JOINs

```php
// Paginación de posts con información del autor
function obtenerPostsConAutor($pagina = 1, $porPagina = 5) {
    global $orm;

    $offset = ($pagina - 1) * $porPagina;

    // Contar total
    $total = $orm->table('posts')
        ->join('users', 'posts.user_id', '=', 'users.id')
        ->where('posts.published', '=', true)
        ->count();

    // Obtener registros
    $posts = $orm->table('posts')
        ->join('users', 'posts.user_id', '=', 'users.id')
        ->select(['posts.title', 'posts.created_at', 'users.name as author'])
        ->where('posts.published', '=', true)
        ->orderBy('posts.created_at', 'DESC')
        ->limit($porPagina)
        ->offset($offset)
        ->getAll();

    return [
        'posts' => $posts,
        'total' => $total,
        'pagina' => $pagina,
        'total_paginas' => ceil($total / $porPagina)
    ];
}

$resultado = obtenerPostsConAutor(1, 3);
echo "Posts (Página {$resultado['pagina']} de {$resultado['total_paginas']}):\n";
foreach ($resultado['posts'] as $post) {
    echo "- {$post['title']} por {$post['author']}\n";
}
```

## Ordenamiento por expresiones calculadas

### Ordenar por campos calculados

```php
// Usuarios ordenados por edad calculada desde fecha de nacimiento
$usuarios = $orm->table('users')
    ->selectRaw('*, YEAR(CURDATE()) - YEAR(birth_date) as edad')
    ->orderByRaw('YEAR(CURDATE()) - YEAR(birth_date) DESC')
    ->getAll();

// Productos ordenados por descuento porcentual
$productos = $orm->table('products')
    ->selectRaw('*, ((original_price - sale_price) / original_price * 100) as descuento')
    ->orderByRaw('((original_price - sale_price) / original_price * 100) DESC')
    ->getAll();
```

**SQL Equivalente:**
```sql
SELECT *, YEAR(CURDATE()) - YEAR(birth_date) as edad
FROM users
ORDER BY YEAR(CURDATE()) - YEAR(birth_date) DESC;
```

## Ejemplo práctico completo

```php
<?php
require_once 'config/database.php';

try {
    echo "=== Ordenamiento y Paginación ===\n\n";

    // 1. Ordenamiento simple
    echo "1. Usuarios ordenados alfabéticamente:\n";
    $usuarios = $orm->table('users')
        ->orderBy('name', 'ASC')
        ->limit(5)
        ->getAll();

    foreach ($usuarios as $usuario) {
        echo "- {$usuario['name']} ({$usuario['email']})\n";
    }

    // 2. Ordenamiento múltiple
    echo "\n2. Posts ordenados por estado y fecha:\n";
    $posts = $orm->table('posts')
        ->orderBy('published', 'DESC')  // Publicados primero
        ->orderBy('created_at', 'DESC') // Más recientes primero
        ->limit(5)
        ->getAll();

    foreach ($posts as $post) {
        $estado = $post['published'] ? 'Publicado' : 'Borrador';
        echo "- {$post['title']} ($estado) - {$post['created_at']}\n";
    }

    // 3. Top 3 usuarios más activos
    echo "\n3. Top 3 usuarios más activos:\n";
    $topUsuarios = $orm->table('users')
        ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
        ->select(['users.name', 'users.email'])
        ->selectRaw('COUNT(posts.id) as total_posts')
        ->groupBy(['users.id', 'users.name', 'users.email'])
        ->orderBy('total_posts', 'DESC')
        ->limit(3)
        ->getAll();

    foreach ($topUsuarios as $i => $usuario) {
        $posicion = $i + 1;
        echo "$posicion. {$usuario['name']}: {$usuario['total_posts']} posts\n";
    }

    // 4. Paginación simple
    echo "\n4. Paginación de posts (Página 1, 3 por página):\n";
    $postsPaginados = $orm->table('posts')
        ->where('published', '=', true)
        ->orderBy('created_at', 'DESC')
        ->limit(3)
        ->offset(0)
        ->getAll();

    foreach ($postsPaginados as $post) {
        echo "- {$post['title']} ({$post['created_at']})\n";
    }

    // Información de paginación
    $totalPosts = $orm->table('posts')
        ->where('published', '=', true)
        ->count();

    $totalPaginas = ceil($totalPosts / 3);
    echo "\nTotal: $totalPosts posts, $totalPaginas páginas\n";

    // 5. Ordenamiento con JOIN
    echo "\n5. Posts con autor, ordenados por nombre del autor:\n";
    $postsConAutor = $orm->table('posts')
        ->join('users', 'posts.user_id', '=', 'users.id')
        ->select(['posts.title', 'users.name as author', 'posts.created_at'])
        ->where('posts.published', '=', true)
        ->orderBy('users.name', 'ASC')
        ->orderBy('posts.created_at', 'DESC')
        ->limit(5)
        ->getAll();

    $autorActual = '';
    foreach ($postsConAutor as $post) {
        if ($post['author'] !== $autorActual) {
            $autorActual = $post['author'];
            echo "\n--- Posts de {$autorActual} ---\n";
        }
        echo "- {$post['title']} ({$post['created_at']})\n";
    }

} catch (VersaORMException $e) {
    echo "Error en la consulta: " . $e->getMessage() . "\n";
}
```

## Mejores prácticas

### ✅ Recomendado

```php
// Siempre usar ORDER BY con LIMIT para resultados consistentes
$orm->table('posts')
    ->orderBy('created_at', 'DESC')
    ->limit(10);

// Usar índices en columnas de ordenamiento para mejor rendimiento
// CREATE INDEX idx_posts_created_at ON posts(created_at);

// Validar parámetros de paginación
$pagina = max(1, (int)$_GET['page']);
$porPagina = min(100, max(1, (int)$_GET['per_page']));
```

### ❌ Evitar

```php
// No usar LIMIT sin ORDER BY (resultados impredecibles)
$orm->table('posts')->limit(10); // Evitar

// No usar OFFSET muy grandes (lento)
$orm->table('posts')->offset(10000)->limit(10); // Muy lento

// No ordenar por columnas sin índices en tablas grandes
$orm->table('big_table')->orderBy('unindexed_column'); // Lento
```

## Errores comunes

### Error: OFFSET sin LIMIT
```php
// Error: OFFSET requiere LIMIT
$orm->table('posts')->offset(10)->getAll(); // Puede fallar

// Solución: siempre usar LIMIT con OFFSET
$orm->table('posts')->limit(10)->offset(10)->getAll();
```

### Error: Ordenamiento inconsistente
```php
// Problema: sin ORDER BY, el orden puede cambiar entre consultas
$pagina1 = $orm->table('posts')->limit(10)->offset(0)->getAll();
$pagina2 = $orm->table('posts')->limit(10)->offset(10)->getAll();

// Solución: siempre usar ORDER BY
$pagina1 = $orm->table('posts')->orderBy('id')->limit(10)->offset(0)->getAll();
```

### Error: Paginación sin validación
```php
// Problema: parámetros no validados
$pagina = $_GET['page']; // Puede ser negativo o no numérico
$offset = ($pagina - 1) * 10;

// Solución: validar parámetros
$pagina = max(1, (int)($_GET['page'] ?? 1));
$offset = ($pagina - 1) * 10;
```

## Siguiente paso

Ahora que dominas el ordenamiento y la paginación, aprende sobre [Agregaciones](agregaciones.md) para realizar cálculos y resúmenes de datos.

## Navegación

- **Anterior**: [JOINs](joins.md)
- **Siguiente**: [Agregaciones](agregaciones.md)
- **Índice**: [Documentación Principal](../README.md)
