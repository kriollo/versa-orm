# Relaciones Muchos-a-Muchos

Las relaciones muchos-a-muchos permiten que múltiples registros de una tabla se relacionen con múltiples registros tabla. Estas relaciones requieren una **tabla pivot** (o tabla intermedia) para almacenar las asociaciones.

## Conceptos Clave

- **Tabla Pivot**: Tabla intermedia que almacena las relaciones
- **belongsToMany**: Método para definir relaciones muchos-a-muchos
- **Clave Compuesta**: La tabla pivot usa claves foráneas de ambas tablas
- **Datos Pivot**: Información adicional almacenada en la tabla intermedia

## Estructura de Ejemplo

Usaremos el sistema Posts ↔ Tags como ejemplo principal:

```sql
-- Tabla de posts
CREATE TABLE posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    content TEXT,
    user_id INT NOT NULL,
    published BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla de tags
CREATE TABLE tags (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabla pivot (intermedia)
CREATE TABLE post_tags (
    post_id INT NOT NULL,
    tag_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (post_id, tag_id),
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);
```

## Configuración Inicial

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

// Crear tags
$phpTag = VersaModel::dispense('tags');
$phpTag->name = 'PHP';
$phpTag->description = 'Lenguaje de programación PHP';
$phpTagId = $phpTag->store();

$mysqlTag = VersaModel::dispense('tags');
$mysqlTag->name = 'MySQL';
$mysqlTag->description = 'Sistema de gestión de bases de datos';
$mysqlTagId = $mysqlTag->store();

$webTag = VersaModel::dispense('tags');
$webTag->name = 'Desarrollo Web';
$webTag->description = 'Desarrollo de aplicaciones web';
$webTagId = $webTag->store();

// Crear posts
$post1 = VersaModel::dispense('posts');
$post1->title = 'Introducción a PHP y MySQL';
$post1->content = 'En este tutorial aprenderemos...';
$post1->user_id = 1;
$post1->published = true;
$post1Id = $post1->store();

$post2 = VersaModel::dispense('posts');
$post2->title = 'Desarrollo Web Moderno';
$post2->content = 'Las mejores prácticas para...';
$post2->user_id = 1;
$post2->published = true;
$post2Id = $post2->store();

echo "Posts y tags creados correctamente\n";
```

## Crear Relaciones Muchos-a-Muchos

### Método 1: Inserción Directa en Tabla Pivot

```php
// Asociar post 1 con tags PHP y MySQL
$postTag1 = VersaModel::dispense('post_tags');
$postTag1->post_id = $post1Id;
$postTag1->tag_id = $phpTagId;
$postTag1->store();

$postTag2 = VersaModel::dispense('post_tags');
$postTag2->post_id = $post1Id;
$postTag2->tag_id = $mysqlTagId;
$postTag2->store();

// Asociar post 2 con tags PHP y Desarrollo Web
$postTag3 = VersaModel::dispense('post_tags');
$postTag3->post_id = $post2Id;
$postTag3->tag_id = $phpTagId;
$postTag3->store();

$postTag4 = VersaModel::dispense('post_tags');
$postTag4->post_id = $post2Id;
$postTag4->tag_id = $webTagId;
$postTag4->store();

echo "Relaciones creadas correctamente\n";
```

**SQL Equivalente:**
```sql
INSERT INTO post_tags (post_id, tag_id) VALUES
(1, 1), (1, 2), (2, 1), (2, 3);
```

### Método 2: Función Helper para Múltiples Asociaciones

```php
function associatePostWithTags($orm, $postId, $tagIds) {
    // Limpiar asociaciones existentes
    $existingAssociations = VersaModel::findAll('post_tags', 'post_id = ?', [$postId]);
    foreach ($existingAssociations as $association) {
        $association->trash();
    }

    // Crear nuevas asociaciones
    foreach ($tagIds as $tagId) {
        $postTag = VersaModel::dispense('post_tags');
        $postTag->post_id = $postId;
        $postTag->tag_id = $tagId;
        $postTag->store();
    }

    echo "Post {$postId} asociado con " . count($tagIds) . " tags\n";
}

// Uso
associatePostWithTags($orm, $post1Id, [$phpTagId, $mysqlTagId, $webTagId]);
```

## Consultar Relaciones Muchos-a-Muchos

### Obtener Tags de un Post

```php
// Método 1: Con JOIN
$postTags = $orm->table('tags')
    ->join('post_tags', 'tags.id = post_tags.tag_id')
    ->where('post_tags.post_id', '=', $post1Id)
    ->select('tags.id, tags.name, tags.description')
    ->getAll();

echo "Tags del post '{$post1->title}':\n";
foreach ($postTags as $tag) {
    echo "- {$tag['name']}: {$tag['description']}\n";
}
```

**SQL Equivalente:**
```sql
SELECT tags.id, tags.name, tags.description
FROM tags
JOIN post_tags ON tags.id = post_tags.tag_id
WHERE post_tags.post_id = 1;
```

**Devuelve:** Array de arrays asociativos con datos de tags

### Obtener Posts de un Tag

```php
// Posts que tienen el tag "PHP"
$phpPosts = $orm->table('posts')
    ->join('post_tags', 'posts.id = post_tags.post_id')
    ->join('tags', 'post_tags.tag_id = tags.id')
    ->where('tags.name', '=', 'PHP')
    ->select('posts.id, posts.title, posts.content')
    ->getAll();

echo "Posts con tag 'PHP':\n";
foreach ($phpPosts as $post) {
    echo "- {$post['title']}\n";
}
```

**SQL Equivalente:**
```sql
SELECT posts.id, posts.title, posts.content
FROM posts
JOIN post_tags ON posts.id = post_tags.post_id
JOIN tags ON post_tags.tag_id = tags.id
WHERE tags.name = 'PHP';
```

### Consulta Completa con Información del Autor

```php
// Posts con sus tags y autores
$postsWithTagsAndAuthors = $orm->table('posts')
    ->join('users', 'posts.user_id = users.id')
    ->leftJoin('post_tags', 'posts.id = post_tags.post_id')
    ->leftJoin('tags', 'post_tags.tag_id = tags.id')
    ->select('posts.id, posts.title, users.name as author, tags.name as tag_name')
    ->orderBy('posts.id')
    ->getAll();

// Agrupar resultados por post
$groupedPosts = [];
foreach ($postsWithTagsAndAuthors as $row) {
    $postId = $row['id'];
    if (!isset($groupedPosts[$postId])) {
        $groupedPosts[$postId] = [
            'title' => $row['title'],
            'author' => $row['author'],
            'tags' => []
        ];
    }
    if ($row['tag_name']) {
        $groupedPosts[$postId]['tags'][] = $row['tag_name'];
    }
}

// Mostrar resultados
foreach ($groupedPosts as $postId => $post) {
    echo "'{$post['title']}' por {$post['author']}\n";
    echo "  Tags: " . implode(', ', $post['tags']) . "\n\n";
}
```

**SQL Equivalente:**
```sql
SELECT posts.id, posts.title, users.name as author, tags.name as tag_name
FROM posts
JOIN users ON posts.user_id = users.id
LEFT JOIN post_tags ON posts.id = post_tags.post_id
LEFT JOIN tags ON post_tags.tag_id = tags.id
ORDER BY posts.id;
```

## Operaciones Avanzadas

### Contar Relaciones

```php
// Contar posts por tag
$tagStats = $orm->table('tags')
    ->leftJoin('post_tags', 'tags.id = post_tags.tag_id')
    ->groupBy('tags.id')
    ->select('tags.name, COUNT(post_tags.post_id) as post_count')
    ->getAll();

echo "Estadísticas de tags:\n";
foreach ($tagStats as $stat) {
    echo "- {$stat['name']}: {$stat['post_count']} posts\n";
}
```

**SQL Equivalente:**
```sql
SELECT tags.name, COUNT(post_tags.post_id) as post_count
FROM tags
LEFT JOIN post_tags ON tags.id = post_tags.tag_id
GROUP BY tags.id;
```

### Buscar Posts con Tags Específicos

```php
// Posts que tienen TANTO el tag "PHP" COMO "MySQL"
$postsWithBothTags = $orm->table('posts')
    ->join('post_tags pt1', 'posts.id = pt1.post_id')
    ->join('tags t1', 'pt1.tag_id = t1.id AND t1.name = "PHP"')
    ->join('post_tags pt2', 'posts.id = pt2.post_id')
    ->join('tags t2', 'pt2.tag_id = t2.id AND t2.name = "MySQL"')
    ->select('DISTINCT posts.id, posts.title')
    ->getAll();

echo "Posts con tags PHP Y MySQL:\n";
foreach ($postsWithBothTags as $post) {
    echo "- {$post['title']}\n";
}
```

### Posts con Cualquiera de los Tags Especificados

```php
// Posts que tienen PHP O MySQL
$postsWithEitherTag = $orm->table('posts')
    ->join('post_tags', 'posts.id = post_tags.post_id')
    ->join('tags', 'post_tags.tag_id = tags.id')
    ->where('tags.name', 'IN', ['PHP', 'MySQL'])
    ->select('DISTINCT posts.id, posts.title')
    ->getAll();

echo "Posts con tags PHP O MySQL:\n";
foreach ($postsWithEitherTag as $post) {
    echo "- {$post['title']}\n";
}
```

**SQL Equivalente:**
```sql
SELECT DISTINCT posts.id, posts.title
FROM posts
JOIN post_tags ON posts.id = post_tags.post_id
JOIN tags ON post_tags.tag_id = tags.id
WHERE tags.name IN ('PHP', 'MySQL');
```

## Tabla Pivot con Datos Adicionales

A veces necesitamos almacenar información adicional en la tabla pivot:

```sql
-- Tabla pivot extendida
CREATE TABLE post_tags (
    post_id INT NOT NULL,
    tag_id INT NOT NULL,
    relevance_score INT DEFAULT 1,  -- Puntuación de relevancia
    added_by INT,                   -- Usuario que agregó el tag
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (post_id, tag_id),
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE,
    FOREIGN KEY (added_by) REFERENCES users(id)
);
```

### Trabajar con Datos Pivot Extendidos

```php
// Crear asociación con datos adicionales
$postTag = VersaModel::dispense('post_tags');
$postTag->post_id = $post1Id;
$postTag->tag_id = $phpTagId;
$postTag->relevance_score = 5;  // Muy relevante
$postTag->added_by = 1;         // Usuario que agregó el tag
$postTag->store();

// Consultar con datos pivot
$postTagsWithRelevance = $orm->table('tags')
    ->join('post_tags', 'tags.id = post_tags.tag_id')
    ->join('users', 'post_tags.added_by = users.id')
    ->where('post_tags.post_id', '=', $post1Id)
    ->select('tags.name, post_tags.relevance_score, users.name as added_by_user')
    ->orderBy('post_tags.relevance_score', 'DESC')
    ->getAll();

echo "Tags del post con relevancia:\n";
foreach ($postTagsWithRelevance as $tagInfo) {
    echo "- {$tagInfo['name']} (Relevancia: {$tagInfo['relevance_score']}, Agregado por: {$tagInfo['added_by_user']})\n";
}
```

## Operaciones de Mantenimiento

### Eliminar Relación Específica

```php
// Eliminar tag específico de un post
function removeTagFromPost($orm, $postId, $tagId) {
    $association = VersaModel::findOne('post_tags', 'post_id = ? AND tag_id = ?', [$postId, $tagId]);
    if ($association) {
        $association->trash();
        echo "Tag eliminado del post\n";
        return true;
    }
    echo "Relación no encontrada\n";
    return false;
}

// Uso
removeTagFromPost($orm, $post1Id, $mysqlTagId);
```

### Limpiar Tags Huérfanos

```php
// Encontrar tags que no están asociados a ningún post
$orphanTags = $orm->table('tags')
    ->leftJoin('post_tags', 'tags.id = post_tags.tag_id')
    ->where('post_tags.tag_id', 'IS', null)
    ->select('tags.id, tags.name')
    ->getAll();

echo "Tags sin posts asociados:\n";
foreach ($orphanTags as $tag) {
    echo "- {$tag['name']}\n";
    // Opcionalmente eliminar: $orm->exec('DELETE FROM tags WHERE id = ?', [$tag['id']]);
}
```

### Sincronizar Tags de un Post

```php
function syncPostTags($orm, $postId, $newTagIds) {
    $orm->begin();
    try {
        // Eliminar todas las asociaciones existentes
        $orm->exec('DELETE FROM post_tags WHERE post_id = ?', [$postId]);

        // Crear nuevas asociaciones
        foreach ($newTagIds as $tagId) {
            $postTag = VersaModel::dispense('post_tags');
            $postTag->post_id = $postId;
            $postTag->tag_id = $tagId;
            $postTag->store();
        }

        $orm->commit();
        echo "Tags sincronizados correctamente\n";

    } catch (Exception $e) {
        $orm->rollback();
        echo "Error al sincronizar tags: " . $e->getMessage() . "\n";
    }
}

// Cambiar los tags del post 1 a solo PHP y Web
syncPostTags($orm, $post1Id, [$phpTagId, $webTagId]);
```

## Casos de Uso Comunes

### Sistema de Blog
- Posts ↔ Tags
- Posts ↔ Categorías
- Usuarios ↔ Posts Favoritos

### E-commerce
- Productos ↔ Categorías
- Pedidos ↔ Productos
- Usuarios ↔ Productos Favoritos

### Sistema de Gestión
- Usuarios ↔ Roles
- Proyectos ↔ Empleados
- Tareas ↔ Etiquetas

### Red Social
- Usuarios ↔ Usuarios (Seguir/Seguidores)
- Posts ↔ Hashtags
- Usuarios ↔ Grupos

## Mejores Prácticas

### 1. Usar Transacciones para Operaciones Múltiples

```php
$orm->begin();
try {
    // Múltiples operaciones de asociación
    $orm->commit();
} catch (Exception $e) {
    $orm->rollback();
}
```

### 2. Validar Existencia antes de Crear Asociaciones

```php
function safeAssociate($orm, $postId, $tagId) {
    $post = VersaModel::load('posts', $postId);
    $tag = VersaModel::load('tags', $tagId);

    if (!$post->id || !$tag->id) {
        return false;
    }

    // Verificar que no existe ya la asociación
    $existing = VersaModel::findOne('post_tags', 'post_id = ? AND tag_id = ?', [$postId, $tagId]);
    if ($existing) {
        return false; // Ya existe
    }

    $postTag = VersaModel::dispense('post_tags');
    $postTag->post_id = $postId;
    $postTag->tag_id = $tagId;
    return $postTag->store();
}
```

### 3. Optimizar Consultas con LIMIT y Paginación

```php
// Obtener posts populares (con más tags) con paginación
$popularPosts = $orm->table('posts')
    ->leftJoin('post_tags', 'posts.id = post_tags.post_id')
    ->groupBy('posts.id')
    ->select('posts.id, posts.title, COUNT(post_tags.tag_id) as tag_count')
    ->orderBy('tag_count', 'DESC')
    ->limit(10)
    ->offset(0)
    ->getAll();
```

## Próximos Pasos

En la siguiente sección aprenderemos sobre estrategias de carga (eager loading vs lazy loading) para optimizar el rendimiento cuando trabajamos con relaciones.

## Navegación

- ← [Relaciones hasMany/belongsTo](hasMany-belongsTo.md)
- → [Carga Eager vs Lazy](eager-loading.md)
