# Relaciones Uno-a-Muchos (hasMany/belongsTo)

Las relaciones uno-a-muchos son las más comunes en aplicaciones web. Representan situaciones donde un registro puede tener múltiples registros relacionados, pero cada registro relacionado pertenece a uno solo.

## Conceptos Clave

- **hasMany**: Un registro "tiene muchos" registros relacionados
- **belongsTo**: Un registro "pertenece a" otro registro
- **Clave Foránea**: Campo que conecta las tablas

## Estructura de Ejemplo

Usaremos las tablas `users` y `posts` para todos los ejemplos:

```sql
-- Un usuario puede tener muchos posts
-- Cada post pertenece a un usuario

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    content TEXT,
    user_id INT NOT NULL,  -- ← Clave foránea
    published BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## Implementación Básica

### Crear Datos de Ejemplo

```php
<?php
require_once 'vendor/autoload.php';

$orm = new VersaORM([
    'driver' => 'mysql',
    'host' => 'localhost',
    'database' => 'ejemplo',
    'username' => 'usuario',
    'password' => 'password',
    'charset' => 'utf8mb4'
]);
VersaModel::setORM($orm);

// Crear usuario
$user = VersaModel::dispense('users');
$user->name = 'Ana Martínez';
$user->email = 'ana@ejemplo.com';
$userId = $user->store();

// Crear posts para el usuario
$post1 = VersaModel::dispense('posts');
$post1->title = 'Introducción a PHP';
$post1->content = 'PHP es un lenguaje de programación...';
$post1->user_id = $userId;
$post1->published = true;
$post1->store();

$post2 = VersaModel::dispense('posts');
$post2->title = 'Bases de Datos con MySQL';
$post2->content = 'MySQL es un sistema de gestión...';
$post2->user_id = $userId;
$post2->published = false;
$post2->store();

echo "Usuario y posts creados correctamente\n";
```

**Devuelve:** Mensaje de confirmación

## Obtener Registros Relacionados

### Método 1: Consulta Directa (Recomendado para casos simples)

```php
// Obtener todos los posts de un usuario específico
$userPosts = VersaModel::findAll('posts', 'user_id = ?', [$userId]);

echo "Posts del usuario:\n";
foreach ($userPosts as $post) {
    echo "- {$post->title} (" . ($post->published ? 'Publicado' : 'Borrador') . ")\n";
}
```

**SQL Equivalente:**
```sql
SELECT * FROM posts WHERE user_id = 1;
```

**Devuelve:** Array de objetos VersaModel (posts)

### Método 2: Query Builder para Consultas Complejas

```php
// Posts publicados de un usuario, ordenados por fecha
$publishedPosts = $orm->table('posts')
    ->where('user_id', '=', $userId)
    ->where('published', '=', true)
    ->orderBy('created_at', 'DESC')
    ->getAll();

echo "Posts publicados (más recientes primero):\n";
foreach ($publishedPosts as $post) {
    echo "- {$post['title']} ({$post['created_at']})\n";
}
```

**SQL Equivalente:**
```sql
SELECT * FROM posts
WHERE user_id = 1 AND published = 1
ORDER BY created_at DESC;
```

**Devuelve:** Array de arrays asociativos

### Método 3: Obtener el Usuario de un Post (belongsTo)

```php
// Cargar un post específico
$post = VersaModel::load('posts', 1);

// Obtener el usuario que escribió el post
$author = VersaModel::load('users', $post->user_id);

echo "Post: {$post->title}\n";
echo "Autor: {$author->name} ({$author->email})\n";
```

**SQL Equivalente:**
```sql
-- Primera consulta
SELECT * FROM posts WHERE id = 1;

-- Segunda consulta
SELECT * FROM users WHERE id = [user_id del post];
```

**Devuelve:** Objetos VersaModel individuales

## Consultas Avanzadas con Relaciones

### Contar Registros Relacionados

```php
// Contar posts por usuario
$postCount = $orm->table('posts')
    ->where('user_id', '=', $userId)
    ->count();

echo "El usuario tiene {$postCount} posts\n";

// Contar solo posts publicados
$publishedCount = $orm->table('posts')
    ->where('user_id', '=', $userId)
    ->where('published', '=', true)
    ->count();

echo "Posts publicados: {$publishedCount}\n";
```

**SQL Equivalente:**
```sql
SELECT COUNT(*) FROM posts WHERE user_id = 1;
SELECT COUNT(*) FROM posts WHERE user_id = 1 AND published = 1;
```

**Devuelve:** Entero (número de registros)

### Consultas con JOIN

```php
// Obtener posts con información del autor
$postsWithAuthors = $orm->table('posts')
    ->join('users', 'posts.user_id = users.id')
    ->select('posts.title, posts.content, users.name as author_name, users.email')
    ->where('posts.published', '=', true)
    ->getAll();

foreach ($postsWithAuthors as $post) {
    echo "'{$post['title']}' por {$post['author_name']}\n";
}
```

**SQL Equivalente:**
```sql
SELECT posts.title, posts.content, users.name as author_name, users.email
FROM posts
JOIN users ON posts.user_id = users.id
WHERE posts.published = 1;
```

**Devuelve:** Array de arrays asociativos con datos combinados

### Filtrar por Datos Relacionados

```php
// Obtener usuarios que tienen posts publicados
$activeAuthors = $orm->table('users')
    ->join('posts', 'users.id = posts.user_id')
    ->where('posts.published', '=', true)
    ->groupBy('users.id')
    ->select('users.id, users.name, COUNT(posts.id) as post_count')
    ->getAll();

echo "Autores activos:\n";
foreach ($activeAuthors as $author) {
    echo "- {$author['name']}: {$author['post_count']} posts\n";
}
```

**SQL Equivalente:**
```sql
SELECT users.id, users.name, COUNT(posts.id) as post_count
FROM users
JOIN posts ON users.id = posts.user_id
WHERE posts.published = 1
GROUP BY users.id;
```

**Devuelve:** Array de arrays asociativos con datos agregados

## Operaciones CRUD con Relaciones

### Crear Post para Usuario Existente

```php
function createPostForUser($orm, $userId, $title, $content) {
    // Verificar que el usuario existe
    $user = VersaModel::load('users', $userId);
    if ($user === null) {
        throw new Exception("Usuario no encontrado");
    }

    // Crear el post
    $post = VersaModel::dispense('posts');
    $post->title = $title;
    $post->content = $content;
    $post->user_id = $userId;
    $post->published = false;

    $postId = $post->store();

    echo "Post '{$title}' creado para {$user->name}\n";
    return $postId;
}

// Uso
try {
    $newPostId = createPostForUser($orm, $userId, 'Nuevo Tutorial', 'Contenido del tutorial...');
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```

### Actualizar Posts de un Usuario

```php
// Publicar todos los borradores de un usuario
$drafts = VersaModel::findAll('posts', 'user_id = ? AND published = ?', [$userId, false]);

foreach ($drafts as $draft) {
    $draft->published = true;
    $draft->store();
}

echo "Se publicaron " . count($drafts) . " borradores\n";
```

**SQL Equivalente:**
```sql
UPDATE posts SET published = 1
WHERE user_id = 1 AND published = 0;
```

### Eliminar Posts de un Usuario

```php
// Eliminar posts no publicados de un usuario
$unpublishedPosts = VersaModel::findAll('posts', 'user_id = ? AND published = ?', [$userId, false]);

foreach ($unpublishedPosts as $post) {
    $post->trash();
}

echo "Se eliminaron " . count($unpublishedPosts) . " borradores\n";
```

**SQL Equivalente:**
```sql
DELETE FROM posts
WHERE user_id = 1 AND published = 0;
```

## Manejo de Errores

```php
try {
    // Intentar crear post sin usuario válido
    $post = VersaModel::dispense('posts');
    $post->title = 'Post huérfano';
    $post->user_id = 999; // Usuario que no existe
    $post->store();

} catch (VersaORMException $e) {
    echo "Error de integridad referencial: " . $e->getMessage() . "\n";
    // La base de datos rechazará esto por la clave foránea
}

try {
    // Intentar eliminar usuario con posts
    $userWithPosts = VersaModel::load('users', $userId);
    $userWithPosts->trash();

} catch (VersaORMException $e) {
    echo "No se puede eliminar usuario con posts: " . $e->getMessage() . "\n";
    // Primero hay que eliminar o reasignar los posts
}
```

## Mejores Prácticas

### 1. Verificar Existencia antes de Crear Relaciones

```php
function safeCreatePost($orm, $userId, $title, $content) {
    // Verificar que el usuario existe
    $user = VersaModel::load('users', $userId);
    if ($user === null) {
        return false;
    }

    $post = VersaModel::dispense('posts');
    $post->title = $title;
    $post->content = $content;
    $post->user_id = $userId;

    return $post->store();
}
```

### 2. Usar Transacciones para Operaciones Complejas

```php
$orm->begin();
try {
    // Crear usuario
    $user = VersaModel::dispense('users');
    $user->name = 'Nuevo Usuario';
    $user->email = 'nuevo@ejemplo.com';
    $userId = $user->store();

    // Crear post inicial
    $post = VersaModel::dispense('posts');
    $post->title = 'Post de bienvenida';
    $post->content = 'Contenido inicial...';
    $post->user_id = $userId;
    $post->published = true;
    $post->store();

    $orm->commit();
    echo "Usuario y post creados exitosamente\n";

} catch (Exception $e) {
    $orm->rollback();
    echo "Error: " . $e->getMessage() . "\n";
}
```

### 3. Optimizar Consultas con LIMIT

```php
// Obtener los 5 posts más recientes de un usuario
$recentPosts = $orm->table('posts')
    ->where('user_id', '=', $userId)
    ->orderBy('created_at', 'DESC')
    ->limit(5)
    ->getAll();
```

## Casos de Uso Comunes

### Blog Personal
- Usuario → Posts
- Usuario → Comentarios
- Categoría → Posts

### E-commerce
- Cliente → Pedidos
- Pedido → Items del Pedido
- Categoría → Productos

### Sistema de Gestión
- Departamento → Empleados
- Proyecto → Tareas
- Usuario → Actividades

## Próximos Pasos

En la siguiente sección aprenderemos sobre relaciones muchos-a-muchos, que nos permitirán modelar asociaciones más complejas como Posts ↔ Tags o Usuarios ↔ Roles.

## Navegación

- ← [Tipos de Relaciones](tipos-relaciones.md)
- → [Relaciones Muchos-a-Muchos](many-to-many.md)
