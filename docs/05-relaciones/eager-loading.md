# Carga Eager vs Lazy Loading

La estrategia de carga de relaciones es crucial para el rendimiento de aplicacioneabajan con datos relacionados. VersaORM permite optimizar consultas mediante diferentes enfoques de carga.

## Conceptos Clave

- **Lazy Loading**: Cargar datos relacionados solo cuando se necesitan
- **Eager Loading**: Cargar datos relacionados de forma anticipada
- **Problema N+1**: Múltiples consultas innecesarias por carga lazy
- **JOIN**: Técnica para combinar datos en una sola consulta

## El Problema N+1

### Ejemplo del Problema

```php
<?php
require_once 'vendor/autoload.php';

$orm = new VersaORM();
$orm->setup('mysql:host=localhost;dbname=ejemplo', 'usuario', 'password');

// ❌ PROBLEMA: Esto genera múltiples consultas
$posts = VersaModel::findAll('post', 'published = ?', [true]);

echo "Posts publicados:\n";
foreach ($posts as $post) {
    // Cada iteración ejecuta una consulta adicional para obtener el autor
    $author = VersaModel::load('user', $post->user_id);
    echo "- '{$post->title}' por {$author->name}\n";
}
```

**Consultas SQL generadas:**
```sql
-- 1 consulta inicial
SELECT * FROM posts WHERE published = 1;

-- N consultas adicionales (una por cada post)
SELECT * FROM users WHERE id = 1;
SELECT * FROM users WHERE id = 2;
SELECT * FROM users WHERE id = 1;  -- ¡Duplicada!
SELECT * FROM users WHERE id = 3;
-- ... y así sucesivamente
```

**Problema:** Si hay 100 posts, se ejecutan 101 consultas (1 + 100)

## Solución 1: Eager Loading con JOIN

### Carga Anticipada Básica

```php
// ✅ SOLUCIÓN: Una sola consulta con JOIN
$postsWithAuthors = $orm->table('post')
    ->join('user', 'post.user_id = user.id')
    ->where('post.published', '=', true)
    ->select('post.id, post.title, post.content, post.created_at,
              user.name as author_name, user.email as author_email')
    ->getAll();

echo "Posts publicados (optimizado):\n";
foreach ($postsWithAuthors as $post) {
    echo "- '{$post['title']}' por {$post['author_name']}\n";
}
```

**SQL Equivalente:**
```sql
SELECT post.id, post.title, post.content, post.created_at,
       user.name as author_name, user.email as author_email
FROM posts post
JOIN users user ON post.user_id = user.id
WHERE post.published = 1;
```

**Resultado:** Solo 1 consulta para todos los datos

### Carga con Múltiples Relaciones

```php
// Posts con autores y conteo de tags
$postsComplete = $orm->table('post')
    ->join('user', 'post.user_id = user.id')
    ->leftJoin('post_tags', 'post.id = post_tags.post_id')
    ->where('post.published', '=', true)
    ->groupBy('post.id')
    ->select('post.id, post.title, user.name as author_name,
              COUNT(post_tags.tag_id) as tag_count')
    ->getAll();

echo "Posts con información completa:\n";
foreach ($postsComplete as $post) {
    echo "- '{$post['title']}' por {$post['author_name']} ({$post['tag_count']} tags)\n";
}
```

## Solución 2: Carga por Lotes (Batch Loading)

### Cargar Autores en Lote

```php
// Obtener posts
$posts = VersaModel::findAll('post', 'published = ?', [true]);

// Extraer IDs únicos de usuarios
$userIds = array_unique(array_column($posts, 'user_id'));

// Cargar todos los usuarios de una vez
$users = VersaModel::findAll('user', 'id IN (' . implode(',', array_fill(0, count($userIds), '?')) . ')', $userIds);

// Crear índice para acceso rápido
$userIndex = [];
foreach ($users as $user) {
    $userIndex[$user->id] = $user;
}

// Mostrar resultados
echo "Posts con autores (carga por lotes):\n";
foreach ($posts as $post) {
    $author = $userIndex[$post->user_id];
    echo "- '{$post->title}' por {$author->name}\n";
}
```

**Consultas SQL generadas:**
```sql
-- Solo 2 consultas en total
SELECT * FROM posts WHERE published = 1;
SELECT * FROM users WHERE id IN (1, 2, 3, 4, 5);
```

### Función Helper para Carga por Lotes

```php
function loadPostsWithAuthors($orm, $conditions = '', $params = []) {
    // Cargar posts
    $posts = empty($conditions)
        ? $orm->findAll('post')
        : VersaModel::findAll('post', $conditions, $params);

    if (empty($posts)) {
        return [];
    }

    // Cargar autores en lote
    $userIds = array_unique(array_column($posts, 'user_id'));
    $users = VersaModel::findAll('user', 'id IN (' . implode(',', array_fill(0, count($userIds), '?')) . ')', $userIds);

    // Crear índice de usuarios
    $userIndex = [];
    foreach ($users as $user) {
        $userIndex[$user->id] = $user;
    }

    // Combinar datos
    $result = [];
    foreach ($posts as $post) {
        $result[] = [
            'post' => $post,
            'author' => $userIndex[$post->user_id] ?? null
        ];
    }

    return $result;
}

// Uso
$postsWithAuthors = loadPostsWithAuthors($orm, 'published = ?', [true]);

foreach ($postsWithAuthors as $item) {
    $post = $item['post'];
    $author = $item['author'];
    echo "- '{$post->title}' por {$author->name}\n";
}
```

## Solución 3: Carga Condicional

### Cargar Relaciones Solo Cuando Sea Necesario

```php
class PostService {
    private $orm;
    private $userCache = [];

    public function __construct($orm) {
        $this->orm = $orm;
    }

    public function getPostsWithAuthors($includeAuthor = true) {
        $posts = $this->orm->find('post', 'published = ?', [true]);

        if (!$includeAuthor) {
            return $posts;
        }

        // Cargar autores solo si se solicita
        return $this->attachAuthors($posts);
    }

    private function attachAuthors($posts) {
        $userIds = array_unique(array_column($posts, 'user_id'));

        // Cargar solo usuarios que no están en caché
        $uncachedIds = array_diff($userIds, array_keys($this->userCache));
        if (!empty($uncachedIds)) {
            $users = $this->orm->find('user', 'id IN (' . implode(',', array_fill(0, count($uncachedIds), '?')) . ')', $uncachedIds);
            foreach ($users as $user) {
                $this->userCache[$user->id] = $user;
            }
        }

        // Combinar datos
        $result = [];
        foreach ($posts as $post) {
            $result[] = [
                'post' => $post,
                'author' => $this->userCache[$post->user_id] ?? null
            ];
        }

        return $result;
    }
}

// Uso
$postService = new PostService($orm);

// Solo posts (1 consulta)
$posts = $postService->getPostsWithAuthors(false);

// Posts con autores (2 consultas máximo)
$postsWithAuthors = $postService->getPostsWithAuthors(true);
```

## Estrategias para Relaciones Muchos-a-Muchos

### Problema N+1 con Tags

```php
// ❌ PROBLEMA: Múltiples consultas para tags
$posts = VersaModel::findAll('post', 'published = ?', [true]);

foreach ($posts as $post) {
    // Cada iteración ejecuta una consulta para obtener tags
    $tags = $orm->table('tag')
        ->join('post_tags', 'tag.id = post_tags.tag_id')
        ->where('post_tags.post_id', '=', $post->id)
        ->getAll();

    echo "'{$post->title}' - Tags: " . implode(', ', array_column($tags, 'name')) . "\n";
}
```

### Solución: Carga Anticipada de Tags

```php
// ✅ SOLUCIÓN: Cargar todos los tags de una vez
function loadPostsWithTags($orm, $conditions = '', $params = []) {
    // Cargar posts
    $posts = empty($conditions)
        ? $orm->findAll('post')
        : VersaModel::findAll('post', $conditions, $params);

    if (empty($posts)) {
        return [];
    }

    $postIds = array_column($posts, 'id');

    // Cargar todas las relaciones post-tag de una vez
    $postTags = $orm->table('post_tags')
        ->join('tag', 'post_tags.tag_id = tag.id')
        ->where('post_tags.post_id', 'IN', $postIds)
        ->select('post_tags.post_id, tag.id as tag_id, tag.name as tag_name')
        ->getAll();

    // Agrupar tags por post
    $tagsByPost = [];
    foreach ($postTags as $pt) {
        $tagsByPost[$pt['post_id']][] = [
            'id' => $pt['tag_id'],
            'name' => $pt['tag_name']
        ];
    }

    // Combinar datos
    $result = [];
    foreach ($posts as $post) {
        $result[] = [
            'post' => $post,
            'tags' => $tagsByPost[$post->id] ?? []
        ];
    }

    return $result;
}

// Uso (solo 2 consultas para todo)
$postsWithTags = loadPostsWithTags($orm, 'published = ?', [true]);

foreach ($postsWithTags as $item) {
    $post = $item['post'];
    $tags = $item['tags'];
    $tagNames = array_column($tags, 'name');
    echo "'{$post->title}' - Tags: " . implode(', ', $tagNames) . "\n";
}
```

## Comparación de Rendimiento

### Medición de Consultas

```php
class QueryCounter {
    private $queryCount = 0;
    private $orm;

    public function __construct($orm) {
        $this->orm = $orm;
    }

    public function resetCount() {
        $this->queryCount = 0;
    }

    public function getCount() {
        return $this->queryCount;
    }

    // Wrapper para contar consultas
    public function find($table, $conditions = '', $params = []) {
        $this->queryCount++;
        return $this->orm->find($table, $conditions, $params);
    }

    public function load($table, $id) {
        $this->queryCount++;
        return $this->orm->load($table, $id);
    }
}

// Comparar enfoques
$counter = new QueryCounter($orm);

// Enfoque Lazy (problemático)
$counter->resetCount();
$posts = $counter->find('post', 'published = ?', [true]);
foreach ($posts as $post) {
    $author = $counter->load('user', $post->user_id);
}
echo "Lazy Loading: {$counter->getCount()} consultas\n";

// Enfoque Eager (optimizado)
$counter->resetCount();
$postsWithAuthors = $orm->table('post')
    ->join('user', 'post.user_id = user.id')
    ->where('post.published', '=', true)
    ->getAll();
echo "Eager Loading: 1 consulta\n";
```

## Cuándo Usar Cada Estrategia

### Lazy Loading - Usar Cuando:

```php
// ✅ Bueno: No siempre necesitas los datos relacionados
function getPost($orm, $id, $includeAuthor = false) {
    $post = VersaModel::load('post', $id);

    if ($includeAuthor) {
        $post->author = VersaModel::load('user', $post->user_id);
    }

    return $post;
}

// ✅ Bueno: Trabajas con pocos registros
$post = VersaModel::load('post', 1);
$author = VersaModel::load('user', $post->user_id); // Solo 1 consulta adicional
```

### Eager Loading - Usar Cuando:

```php
// ✅ Bueno: Siempre necesitas los datos relacionados
function getPostsForListing($orm) {
    return $orm->table('post')
        ->join('user', 'post.user_id = user.id')
        ->where('post.published', '=', true)
        ->select('post.*, user.name as author_name')
        ->getAll();
}

// ✅ Bueno: Trabajas con muchos registros
function getPostsWithStats($orm) {
    return $orm->table('post')
        ->leftJoin('post_tags', 'post.id = post_tags.post_id')
        ->groupBy('post.id')
        ->select('post.*, COUNT(post_tags.tag_id) as tag_count')
        ->getAll();
}
```

## Mejores Prácticas

### 1. Identificar Patrones de Acceso

```php
// Analizar qué datos se usan juntos frecuentemente
class PostAnalytics {
    public function getMostViewedPostsWithAuthors($orm, $limit = 10) {
        // Siempre necesitamos autor para posts populares
        return $orm->table('post')
            ->join('user', 'post.user_id = user.id')
            ->orderBy('post.views', 'DESC')
            ->limit($limit)
            ->select('post.*, user.name as author_name')
            ->getAll();
    }

    public function getPostForEditing($orm, $id) {
        // Para edición, cargamos todo de una vez
        $post = $orm->table('post')
            ->join('user', 'post.user_id = user.id')
            ->where('post.id', '=', $id)
            ->select('post.*, user.name as author_name')
            ->firstArray();

        // Cargar tags también
        $tags = $orm->table('tag')
            ->join('post_tags', 'tag.id = post_tags.tag_id')
            ->where('post_tags.post_id', '=', $id)
            ->getAll();

        $post['tags'] = $tags;
        return $post;
    }
}
```

### 2. Usar Caché para Datos Frecuentes

```php
class CachedUserLoader {
    private static $userCache = [];

    public static function loadUser($orm, $userId) {
        if (!isset(self::$userCache[$userId])) {
            self::$userCache[$userId] = VersaModel::load('user', $userId);
        }
        return self::$userCache[$userId];
    }

    public static function loadUsers($orm, $userIds) {
        $uncachedIds = array_diff($userIds, array_keys(self::$userCache));

        if (!empty($uncachedIds)) {
            $users = VersaModel::findAll('user', 'id IN (' . implode(',', array_fill(0, count($uncachedIds), '?')) . ')', $uncachedIds);
            foreach ($users as $user) {
                self::$userCache[$user->id] = $user;
            }
        }

        return array_intersect_key(self::$userCache, array_flip($userIds));
    }
}
```

### 3. Paginación con Eager Loading

```php
function getPaginatedPostsWithAuthors($orm, $page = 1, $perPage = 10) {
    $offset = ($page - 1) * $perPage;

    return $orm->table('post')
        ->join('user', 'post.user_id = user.id')
        ->where('post.published', '=', true)
        ->orderBy('post.created_at', 'DESC')
        ->limit($perPage)
        ->offset($offset)
        ->select('post.*, user.name as author_name, user.email as author_email')
        ->getAll();
}

// Uso eficiente con paginación
$posts = getPaginatedPostsWithAuthors($orm, 1, 20); // Solo 1 consulta
```

## Herramientas de Debugging

### Monitor de Consultas

```php
class QueryLogger {
    private $queries = [];

    public function logQuery($sql, $params = []) {
        $this->queries[] = [
            'sql' => $sql,
            'params' => $params,
            'time' => microtime(true)
        ];
    }

    public function getQueryCount() {
        return count($this->queries);
    }

    public function getSlowQueries($threshold = 0.1) {
        $slow = [];
        for ($i = 1; $i < count($this->queries); $i++) {
            $duration = $this->queries[$i]['time'] - $this->queries[$i-1]['time'];
            if ($duration > $threshold) {
                $slow[] = [
                    'query' => $this->queries[$i],
                    'duration' => $duration
                ];
            }
        }
        return $slow;
    }
}
```

## Próximos Pasos

Con el conocimiento de relaciones y estrategias de carga, estás listo para explorar funcionalidades avanzadas como operaciones batch, transacciones y consultas raw en la siguiente sección.

## Navegación

- ← [Relaciones Muchos-a-Muchos](many-to-many.md)
- → [Funcionalidades Avanzadas](../06-avanzado/README.md)
