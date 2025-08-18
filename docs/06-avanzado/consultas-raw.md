# Consultas Raw

Aunque VersaORM proporciona un Query Builder potente, hay ocasiones donde necesitas usar SQL directo para aprovechar funcionalidades específicas de la base de datos o realizar consultas muy complejas que van más allá del Query Builder estándar.

## Conceptos Clave

- **Raw Queries**: Consultas SQL escirectamente
- **Parámetros Seguros**: Uso de placeholders para evitar SQL injection
- **Flexibilidad**: Acceso completo a funcionalidades específicas de la BD
- **Responsabilidad**: Mayor control pero también mayor responsabilidad en seguridad

## query() - Consultas SELECT Raw

### Ejemplo Básico

```php
<?php
require_once 'bootstrap.php';

try {
    // Consulta raw simple
    $sql = "SELECT u.name, u.email, COUNT(p.id) as post_count
            FROM users u
            LEFT JOIN posts p ON u.id = p.user_id
            WHERE u.active = ?
            GROUP BY u.id, u.name, u.email
            HAVING post_count > ?
            ORDER BY post_count DESC";

    $results = $orm->query($sql, [true, 2]);

    echo "Usuarios con más de 2 posts:\n";
    foreach ($results as $user) {
        echo "- {$user['name']} ({$user['email']}): {$user['post_count']} posts\n";
    }

} catch (VersaORMException $e) {
    echo "Error en consulta raw: " . $e->getMessage() . "\n";
}
```
**SQL Equivalente (ya raw - mostrado para formato):**
```sql
SELECT u.name, u.email, COUNT(p.id) as post_count
FROM users u
LEFT JOIN posts p ON u.id = p.user_id
WHERE u.active = ?
GROUP BY u.id, u.name, u.email
HAVING post_count > ?
ORDER BY post_count DESC;
```

**Devuelve:** Array de arrays asociativos con los resultados

### Consultas con Funciones Específicas de BD

```php
<?php
// Ejemplo para MySQL: usar funciones específicas
try {
    $sql = "SELECT
                u.name,
                u.created_at,
                TIMESTAMPDIFF(DAY, u.created_at, NOW()) as days_since_registration,
                DATE_FORMAT(u.created_at, '%Y-%m') as registration_month,
                JSON_EXTRACT(u.metadata, '$.preferences.theme') as theme_preference
            FROM users u
            WHERE u.created_at >= DATE_SUB(NOW(), INTERVAL ? MONTH)
            ORDER BY u.created_at DESC";

    $recentUsers = $orm->query($sql, [6]); // Últimos 6 meses

    foreach ($recentUsers as $user) {
        echo "Usuario: {$user['name']}\n";
        echo "Registrado hace: {$user['days_since_registration']} días\n";
        echo "Mes de registro: {$user['registration_month']}\n";
        echo "Tema preferido: " . ($user['theme_preference'] ?? 'No definido') . "\n\n";
    }

} catch (VersaORMException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```
**SQL Equivalente (idéntico, enfatizando placeholders):**
```sql
SELECT u.name,
       u.created_at,
       TIMESTAMPDIFF(DAY, u.created_at, NOW()) as days_since_registration,
       DATE_FORMAT(u.created_at, '%Y-%m') as registration_month,
       JSON_EXTRACT(u.metadata, '$.preferences.theme') as theme_preference
FROM users u
WHERE u.created_at >= DATE_SUB(NOW(), INTERVAL ? MONTH)
ORDER BY u.created_at DESC;
```

### Consultas con CTEs (Common Table Expressions)

```php
<?php
// Ejemplo para PostgreSQL: usar CTEs recursivos
try {
    $sql = "WITH RECURSIVE category_tree AS (
                -- Caso base: categorías raíz
                SELECT id, name, parent_id, 0 as level, name as path
                FROM categories
                WHERE parent_id IS NULL

                UNION ALL

                -- Caso recursivo: subcategorías
                SELECT c.id, c.name, c.parent_id, ct.level + 1,
                       ct.path || ' > ' || c.name
                FROM categories c
                INNER JOIN category_tree ct ON c.parent_id = ct.id
            )
            SELECT ct.*, COUNT(p.id) as product_count
            FROM category_tree ct
            LEFT JOIN products p ON ct.id = p.category_id
            GROUP BY ct.id, ct.name, ct.parent_id, ct.level, ct.path
            ORDER BY ct.path";

    $categoryTree = $orm->query($sql);

    echo "Árbol de categorías:\n";
    foreach ($categoryTree as $category) {
        $indent = str_repeat('  ', $category['level']);
        echo "$indent{$category['name']} ({$category['product_count']} productos)\n";
    }

} catch (VersaORMException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```
**SQL Equivalente (idéntico, PostgreSQL):**
```sql
WITH RECURSIVE category_tree AS (
    SELECT id, name, parent_id, 0 as level, name as path
    FROM categories
    WHERE parent_id IS NULL
    UNION ALL
    SELECT c.id, c.name, c.parent_id, ct.level + 1, ct.path || ' > ' || c.name
    FROM categories c
    INNER JOIN category_tree ct ON c.parent_id = ct.id
)
SELECT ct.*, COUNT(p.id) as product_count
FROM category_tree ct
LEFT JOIN products p ON ct.id = p.category_id
GROUP BY ct.id, ct.name, ct.parent_id, ct.level, ct.path
ORDER BY ct.path;
```

## execute() - Consultas de Modificación Raw

### INSERT, UPDATE, DELETE Raw

```php
<?php
try {
    // INSERT con ON DUPLICATE KEY UPDATE (MySQL)
    $sql = "INSERT INTO user_stats (user_id, login_count, last_login)
            VALUES (?, 1, NOW())
            ON DUPLICATE KEY UPDATE
                login_count = login_count + 1,
                last_login = NOW()";

    $affectedRows = $orm->execute($sql, [123]);
    echo "Estadísticas actualizadas: $affectedRows fila(s)\n";

    // UPDATE con subconsulta compleja
    $sql = "UPDATE posts p
            SET view_count = (
                SELECT COUNT(*)
                FROM post_views pv
                WHERE pv.post_id = p.id
                AND pv.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            )
            WHERE p.published = true";

    $updatedPosts = $orm->execute($sql);
    echo "Posts actualizados: $updatedPosts\n";

    // DELETE con JOIN
    $sql = "DELETE p FROM posts p
            INNER JOIN users u ON p.user_id = u.id
            WHERE u.active = false
            AND p.created_at < DATE_SUB(NOW(), INTERVAL 1 YEAR)";

    $deletedPosts = $orm->execute($sql);
    echo "Posts eliminados: $deletedPosts\n";

} catch (VersaORMException $e) {
    echo "Error en operación: " . $e->getMessage() . "\n";
}
```
**SQL Equivalente (mismas sentencias):**
```sql
INSERT INTO user_stats (user_id, login_count, last_login)
VALUES (?, 1, NOW())
ON DUPLICATE KEY UPDATE login_count = login_count + 1, last_login = NOW();

UPDATE posts p
SET view_count = (
    SELECT COUNT(*) FROM post_views pv
    WHERE pv.post_id = p.id
        AND pv.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
)
WHERE p.published = true;

DELETE p FROM posts p
INNER JOIN users u ON p.user_id = u.id
WHERE u.active = false
    AND p.created_at < DATE_SUB(NOW(), INTERVAL 1 YEAR);
```

**Devuelve:** Número de filas afectadas (integer)

### Operaciones Batch Complejas

```php
<?php
try {
    // Inserción masiva con datos calculados
    $sql = "INSERT INTO monthly_reports (user_id, month, year, post_count, comment_count, total_views)
            SELECT
                u.id,
                MONTH(p.created_at) as month,
                YEAR(p.created_at) as year,
                COUNT(DISTINCT p.id) as post_count,
                COUNT(DISTINCT c.id) as comment_count,
                COALESCE(SUM(p.view_count), 0) as total_views
            FROM users u
            LEFT JOIN posts p ON u.id = p.user_id
                AND p.created_at >= ?
                AND p.created_at < ?
            LEFT JOIN comments c ON p.id = c.post_id
            WHERE u.active = true
            GROUP BY u.id, MONTH(p.created_at), YEAR(p.created_at)
            HAVING post_count > 0";

    $startDate = '2024-01-01';
    $endDate = '2024-02-01';

    $reportRows = $orm->execute($sql, [$startDate, $endDate]);
    echo "Reportes mensuales generados: $reportRows\n";

} catch (VersaORMException $e) {
    echo "Error generando reportes: " . $e->getMessage() . "\n";
}
```
**SQL Equivalente (idéntico, enfatiza placeholders de fechas):**
```sql
INSERT INTO monthly_reports (user_id, month, year, post_count, comment_count, total_views)
SELECT u.id,
             MONTH(p.created_at) as month,
             YEAR(p.created_at) as year,
             COUNT(DISTINCT p.id) as post_count,
             COUNT(DISTINCT c.id) as comment_count,
             COALESCE(SUM(p.view_count), 0) as total_views
FROM users u
LEFT JOIN posts p ON u.id = p.user_id
    AND p.created_at >= ?
    AND p.created_at < ?
LEFT JOIN comments c ON p.id = c.post_id
WHERE u.active = true
GROUP BY u.id, MONTH(p.created_at), YEAR(p.created_at)
HAVING post_count > 0;
```

## queryFirst() - Primera Fila de Consulta Raw

### Consultas que Devuelven Un Solo Resultado

```php
<?php
try {
    // Obtener estadísticas generales
    $sql = "SELECT
                COUNT(DISTINCT u.id) as total_users,
                COUNT(DISTINCT p.id) as total_posts,
                COUNT(DISTINCT c.id) as total_comments,
                AVG(p.view_count) as avg_post_views,
                MAX(u.created_at) as last_registration
            FROM users u
            LEFT JOIN posts p ON u.id = p.user_id
            LEFT JOIN comments c ON p.id = c.post_id
            WHERE u.active = ?";

    $stats = $orm->queryFirst($sql, [true]);

    if ($stats) {
        echo "Estadísticas del sitio:\n";
        echo "- Usuarios totales: " . number_format($stats['total_users']) . "\n";
        echo "- Posts totales: " . number_format($stats['total_posts']) . "\n";
        echo "- Comentarios totales: " . number_format($stats['total_comments']) . "\n";
        echo "- Promedio de vistas por post: " . number_format($stats['avg_post_views'], 2) . "\n";
        echo "- Último registro: " . $stats['last_registration'] . "\n";
    }

} catch (VersaORMException $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```
**SQL Equivalente:**
```sql
SELECT COUNT(DISTINCT u.id) as total_users,
       COUNT(DISTINCT p.id) as total_posts,
       COUNT(DISTINCT c.id) as total_comments,
       AVG(p.view_count) as avg_post_views,
       MAX(u.created_at) as last_registration
FROM users u
LEFT JOIN posts p ON u.id = p.user_id
LEFT JOIN comments c ON p.id = c.post_id
WHERE u.active = ?;
```

**Devuelve:** Array asociativo con la primera fila o null si no hay resultados

### Verificación de Existencia Compleja

```php
<?php
try {
    // Verificar si un usuario puede realizar una acción específica
    $sql = "SELECT
                CASE
                    WHEN u.role = 'admin' THEN 'allowed'
                    WHEN u.role = 'moderator' AND ? IN ('edit', 'delete') THEN 'allowed'
                    WHEN u.id = p.user_id THEN 'allowed'
                    ELSE 'denied'
                END as permission,
                u.name as user_name,
                p.title as post_title
            FROM users u
            CROSS JOIN posts p
            WHERE u.id = ? AND p.id = ?";

    $userId = 5;
    $postId = 10;
    $action = 'edit';

    $permission = $orm->queryFirst($sql, [$action, $userId, $postId]);

    if ($permission) {
        echo "Usuario: {$permission['user_name']}\n";
        echo "Post: {$permission['post_title']}\n";
        echo "Acción '$action': " . strtoupper($permission['permission']) . "\n";

        if ($permission['permission'] === 'allowed') {
            echo "✅ Acción permitida\n";
        } else {
            echo "❌ Acción denegada\n";
        }
    }

} catch (VersaORMException $e) {
    echo "Error verificando permisos: " . $e->getMessage() . "\n";
}
```
**SQL Equivalente:**
```sql
SELECT CASE
                 WHEN u.role = 'admin' THEN 'allowed'
                 WHEN u.role = 'moderator' AND ? IN ('edit','delete') THEN 'allowed'
                 WHEN u.id = p.user_id THEN 'allowed'
                 ELSE 'denied'
             END as permission,
             u.name as user_name,
             p.title as post_title
FROM users u
CROSS JOIN posts p
WHERE u.id = ? AND p.id = ?;
```

## Casos de Uso Avanzados

### Análisis de Datos Complejos

```php
<?php
function generateAdvancedAnalytics($startDate, $endDate) {
    $orm = VersaORM::getInstance();

    try {
        // Análisis de engagement por día de la semana
        $sql = "SELECT
                    DAYNAME(p.created_at) as day_name,
                    DAYOFWEEK(p.created_at) as day_number,
                    COUNT(p.id) as posts_created,
                    AVG(p.view_count) as avg_views,
                    COUNT(DISTINCT c.id) as total_comments,
                    COUNT(DISTINCT p.user_id) as unique_authors
                FROM posts p
                LEFT JOIN comments c ON p.id = c.post_id
                WHERE p.created_at BETWEEN ? AND ?
                GROUP BY DAYOFWEEK(p.created_at), DAYNAME(p.created_at)
                ORDER BY day_number";

        $weeklyStats = $orm->query($sql, [$startDate, $endDate]);

        echo "Análisis de actividad por día de la semana:\n";
        echo str_repeat("-", 80) . "\n";
        printf("%-12s %-8s %-10s %-12s %-8s\n",
               "Día", "Posts", "Vistas Prom", "Comentarios", "Autores");
        echo str_repeat("-", 80) . "\n";

        foreach ($weeklyStats as $day) {
            printf("%-12s %-8d %-10.1f %-12d %-8d\n",
                   $day['day_name'],
                   $day['posts_created'],
                   $day['avg_views'],
                   $day['total_comments'],
                   $day['unique_authors']
            );
        }

        // Análisis de tendencias por mes
        $sql = "SELECT
                    DATE_FORMAT(created_at, '%Y-%m') as month,
                    COUNT(*) as posts,
                    COUNT(DISTINCT user_id) as active_users,
                    SUM(view_count) as total_views,
                    AVG(view_count) as avg_views_per_post
                FROM posts
                WHERE created_at BETWEEN ? AND ?
                GROUP BY DATE_FORMAT(created_at, '%Y-%m')
                ORDER BY month";

        $monthlyTrends = $orm->query($sql, [$startDate, $endDate]);

        echo "\n\nTendencias mensuales:\n";
        echo str_repeat("-", 70) . "\n";
        printf("%-8s %-8s %-12s %-12s %-15s\n",
               "Mes", "Posts", "Usuarios", "Vistas Tot", "Prom/Post");
        echo str_repeat("-", 70) . "\n";

        foreach ($monthlyTrends as $month) {
            printf("%-8s %-8d %-12d %-12s %-15.1f\n",
                   $month['month'],
                   $month['posts'],
                   $month['active_users'],
                   number_format($month['total_views']),
                   $month['avg_views_per_post']
            );
        }

    } catch (VersaORMException $e) {
        echo "Error en análisis: " . $e->getMessage() . "\n";
    }
}

// Generar análisis para el último trimestre
$endDate = date('Y-m-d');
$startDate = date('Y-m-d', strtotime('-3 months'));
generateAdvancedAnalytics($startDate, $endDate);
```

### Operaciones de Mantenimiento

```php
<?php
function performDatabaseMaintenance() {
    $orm = VersaORM::getInstance();

    try {
        echo "Iniciando mantenimiento de base de datos...\n";

        // 1. Limpiar datos huérfanos
        $sql = "DELETE c FROM comments c
                LEFT JOIN posts p ON c.post_id = p.id
                WHERE p.id IS NULL";

        $orphanComments = $orm->execute($sql);
        echo "Comentarios huérfanos eliminados: $orphanComments\n";

        // 2. Actualizar contadores desnormalizados
        $sql = "UPDATE posts p
                SET comment_count = (
                    SELECT COUNT(*)
                    FROM comments c
                    WHERE c.post_id = p.id
                )";

        $updatedPosts = $orm->execute($sql);
        echo "Contadores de comentarios actualizados: $updatedPosts posts\n";

        // 3. Limpiar sesiones expiradas
        $sql = "DELETE FROM user_sessions
                WHERE expires_at < NOW()";

        $expiredSessions = $orm->execute($sql);
        echo "Sesiones expiradas eliminadas: $expiredSessions\n";

        // 4. Optimizar tablas (MySQL específico)
        if ($orm->getDriverName() === 'mysql') {
            $tables = ['users', 'posts', 'comments', 'user_sessions'];

            foreach ($tables as $table) {
                $sql = "OPTIMIZE TABLE $table";
                $orm->execute($sql);
                echo "Tabla '$table' optimizada\n";
            }
        }

        // 5. Generar estadísticas de mantenimiento
        $sql = "SELECT
                    'users' as table_name,
                    COUNT(*) as total_records,
                    COUNT(CASE WHEN active = 1 THEN 1 END) as active_records
                FROM users
                UNION ALL
                SELECT
                    'posts' as table_name,
                    COUNT(*) as total_records,
                    COUNT(CASE WHEN published = 1 THEN 1 END) as active_records
                FROM posts
                UNION ALL
                SELECT
                    'comments' as table_name,
                    COUNT(*) as total_records,
                    COUNT(*) as active_records
                FROM comments";

        $stats = $orm->query($sql);

        echo "\nEstadísticas post-mantenimiento:\n";
        foreach ($stats as $stat) {
            echo "- {$stat['table_name']}: {$stat['total_records']} total, {$stat['active_records']} activos\n";
        }

        echo "Mantenimiento completado exitosamente\n";

    } catch (VersaORMException $e) {
        echo "Error durante mantenimiento: " . $e->getMessage() . "\n";
    }
}

// Ejecutar mantenimiento
performDatabaseMaintenance();
```

### Migración de Datos

```php
<?php
function migrateUserData() {
    $orm = VersaORM::getInstance();

    try {
        $orm->beginTransaction();

        // 1. Migrar datos de tabla antigua a nueva estructura
        $sql = "INSERT INTO user_profiles (user_id, bio, website, avatar_url, created_at)
                SELECT
                    u.id,
                    COALESCE(u.old_bio, '') as bio,
                    COALESCE(u.old_website, '') as website,
                    COALESCE(u.old_avatar, '') as avatar_url,
                    u.created_at
                FROM users u
                LEFT JOIN user_profiles up ON u.id = up.user_id
                WHERE up.user_id IS NULL
                AND (u.old_bio IS NOT NULL OR u.old_website IS NOT NULL OR u.old_avatar IS NOT NULL)";

        $migratedProfiles = $orm->execute($sql);
        echo "Perfiles migrados: $migratedProfiles\n";

        // 2. Normalizar datos de categorías
        $sql = "UPDATE posts p
                SET category_id = (
                    SELECT c.id
                    FROM categories c
                    WHERE LOWER(c.name) = LOWER(p.old_category_name)
                    LIMIT 1
                )
                WHERE p.category_id IS NULL
                AND p.old_category_name IS NOT NULL";

        $categorizedPosts = $orm->execute($sql);
        echo "Posts categorizados: $categorizedPosts\n";

        // 3. Limpiar datos duplicados
        $sql = "DELETE u1 FROM users u1
                INNER JOIN users u2
                WHERE u1.id > u2.id
                AND u1.email = u2.email";

        $duplicatesRemoved = $orm->execute($sql);
        echo "Usuarios duplicados eliminados: $duplicatesRemoved\n";

        $orm->commit();
        echo "Migración completada exitosamente\n";

    } catch (Exception $e) {
        $orm->rollback();
        echo "Error en migración: " . $e->getMessage() . "\n";
    }
}
```
**SQL Equivalente (idéntico, resaltando BETWEEN):**
```sql
SELECT DAYNAME(p.created_at) as day_name,
       DAYOFWEEK(p.created_at) as day_number,
       COUNT(p.id) as posts_created,
       AVG(p.view_count) as avg_views,
       COUNT(DISTINCT c.id) as total_comments,
       COUNT(DISTINCT p.user_id) as unique_authors
FROM posts p
LEFT JOIN comments c ON p.id = c.post_id
WHERE p.created_at BETWEEN ? AND ?
GROUP BY DAYOFWEEK(p.created_at), DAYNAME(p.created_at)
ORDER BY day_number;
```

### Operadores de Conjuntos (UNION / UNION ALL / INTERSECT / EXCEPT)

Los operadores de conjuntos permiten combinar resultados de múltiples SELECT. Usa siempre el mismo número y orden de columnas y tipos compatibles.

```php
<?php
// UNION (elimina duplicados) y UNION ALL (conserva duplicados)
$sql = "SELECT id, email, 'user' AS source FROM users WHERE active = 1
        UNION ALL
        SELECT id, email, 'subscriber' AS source FROM newsletter_subscribers";
$rows = $orm->query($sql);

// INTERSECT y EXCEPT sólo soportados por PostgreSQL / SQLite (MySQL no):
if (in_array($orm->getDriverName(), ['pgsql','sqlite'])) {
    $sqlIntersect = "SELECT email FROM users
                     INTERSECT
                     SELECT email FROM newsletter_subscribers"; // Correos en ambos
    $inBoth = $orm->query($sqlIntersect);

    $sqlExcept = "SELECT email FROM users
                  EXCEPT
                  SELECT email FROM newsletter_subscribers"; // Usuarios que no están suscritos
    $onlyUsers = $orm->query($sqlExcept);
} else {
    // Emulación INTERSECT en MySQL usando INNER JOIN
    $sqlIntersectMy = "SELECT u.email
                        FROM users u
                        INNER JOIN newsletter_subscribers n ON n.email = u.email";
    $inBoth = $orm->query($sqlIntersectMy);

    // Emulación EXCEPT en MySQL usando LEFT JOIN + IS NULL
    $sqlExceptMy = "SELECT u.email
                    FROM users u
                    LEFT JOIN newsletter_subscribers n ON n.email = u.email
                    WHERE n.email IS NULL";
    $onlyUsers = $orm->query($sqlExceptMy);
}
```
**SQL Equivalente (UNION / UNION ALL):**
```sql
SELECT id, email, 'user' AS source FROM users WHERE active = 1
UNION ALL
SELECT id, email, 'subscriber' AS source FROM newsletter_subscribers;
```
**SQL INTERSECT (PostgreSQL / SQLite):**
```sql
SELECT email FROM users
INTERSECT
SELECT email FROM newsletter_subscribers;
```
**SQL EXCEPT (PostgreSQL / SQLite):**
```sql
SELECT email FROM users
EXCEPT
SELECT email FROM newsletter_subscribers;
```
**Emulación MySQL INTERSECT:**
```sql
SELECT u.email
FROM users u
INNER JOIN newsletter_subscribers n ON n.email = u.email;
```
**Emulación MySQL EXCEPT:**
```sql
SELECT u.email
FROM users u
LEFT JOIN newsletter_subscribers n ON n.email = u.email
WHERE n.email IS NULL;
```

### Funciones de Ventana (Window Functions)

Las window functions calculan valores sobre un set de filas relacionado sin colapsar el resultado (a diferencia de GROUP BY). Disponibles en PostgreSQL, SQLite y MySQL >= 8.0.

```php
<?php
$sql = "SELECT
            p.id,
            p.user_id,
            p.view_count,
            ROW_NUMBER() OVER (PARTITION BY p.user_id ORDER BY p.view_count DESC) AS rn,
            RANK()       OVER (ORDER BY p.view_count DESC) AS global_rank,
            SUM(p.view_count) OVER (PARTITION BY p.user_id) AS user_total_views
        FROM posts p
        WHERE p.created_at >= ?";

$rows = $orm->query($sql, [date('Y-m-01')]);

foreach ($rows as $r) {
    // rn = posición dentro del usuario, global_rank = ranking global por vistas
}

// Ventana móvil (moving average) de vistas por día (PostgreSQL / MySQL 8 / SQLite 3.28+)
$sqlMA = "SELECT
              DATE(p.created_at) AS day,
              COUNT(*) AS posts,
              AVG(COUNT(*)) OVER (ORDER BY DATE(p.created_at)
                                   ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) AS ma7_posts
          FROM posts p
          WHERE p.created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
          GROUP BY DATE(p.created_at)";

// Nota: Sintaxis de DATE_SUB es MySQL; para PostgreSQL usar CURRENT_DATE - INTERVAL '30 days'
```
**SQL Equivalente (ranking por usuario y global):**
```sql
SELECT p.id,
       p.user_id,
       p.view_count,
       ROW_NUMBER() OVER (PARTITION BY p.user_id ORDER BY p.view_count DESC) AS rn,
       RANK()       OVER (ORDER BY p.view_count DESC) AS global_rank,
       SUM(p.view_count) OVER (PARTITION BY p.user_id) AS user_total_views
FROM posts p
WHERE p.created_at >= ?;
```
**SQL Equivalente (media móvil 7 días - PostgreSQL variante):**
```sql
SELECT DATE(p.created_at) AS day,
       COUNT(*) AS posts,
       AVG(COUNT(*)) OVER (ORDER BY DATE(p.created_at)
                            ROWS BETWEEN 6 PRECEDING AND CURRENT ROW) AS ma7_posts
FROM posts p
WHERE p.created_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY DATE(p.created_at);
```
**SQLite Nota:** Usar `DATE(p.created_at)` y reemplazar CURRENT_DATE - INTERVAL '30 days' por `DATE('now','-30 day')`.

### Consideraciones de Rendimiento para Window y Set Operations
| Técnica | Recomendación |
|---------|---------------|
| Índices | Indexar columnas en PARTITION BY / JOIN para evitar full scans |
| LIMIT | Encapsular en subconsulta y aplicar LIMIT externo si sólo necesitas top-N |
| Materialización | Para cadenas de UNIONs complejos, materializa en tabla temporal si se reutiliza |
| Filtros | Aplica WHERE antes de la ventana para reducir el conjunto |

**SQL Ejemplo optimizado (materialización temporal PostgreSQL):**
```sql
WITH filtered AS (
  SELECT * FROM posts WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'
)
SELECT id, user_id, view_count,
       ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY view_count DESC) AS rn
FROM filtered;
```

### Agregaciones Multidimensionales (GROUPING SETS / ROLLUP / CUBE)

Permiten obtener múltiples niveles de agregación en una sola pasada.

```php
<?php
if ($orm->getDriverName() === 'pgsql') {
    $sql = "SELECT
                DATE(created_at) AS day,
                user_id,
                COUNT(*) AS posts,
                GROUPING(DATE(created_at), user_id) AS grp_mask
            FROM posts
            WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'
            GROUP BY GROUPING SETS ((DATE(created_at), user_id), (DATE(created_at)), (user_id), ())
            ORDER BY day NULLS LAST, user_id NULLS LAST";
    $rows = $orm->query($sql);
} elseif ($orm->getDriverName() === 'mysql') {
    // MySQL soporta ROLLUP
    $sql = "SELECT DATE(created_at) AS day, user_id, COUNT(*) AS posts
            FROM posts
            WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            GROUP BY DATE(created_at), user_id WITH ROLLUP";
    $rows = $orm->query($sql);
} else {
    // SQLite: emulación mediante UNION ALL manual
    $sql = "SELECT DATE(created_at) AS day, user_id, COUNT(*) AS posts
            FROM posts
            WHERE created_at >= DATE('now','-7 day')
            GROUP BY DATE(created_at), user_id
            UNION ALL
            SELECT DATE(created_at) AS day, NULL user_id, COUNT(*) AS posts
            FROM posts
            WHERE created_at >= DATE('now','-7 day')
            GROUP BY DATE(created_at)
            UNION ALL
            SELECT NULL day, user_id, COUNT(*) AS posts
            FROM posts
            WHERE created_at >= DATE('now','-7 day')
            GROUP BY user_id
            UNION ALL
            SELECT NULL day, NULL user_id, COUNT(*) AS posts
            FROM posts
            WHERE created_at >= DATE('now','-7 day')";
    $rows = $orm->query($sql);
}
```
**SQL Equivalente (PostgreSQL GROUPING SETS):**
```sql
SELECT DATE(created_at) AS day,
       user_id,
       COUNT(*) AS posts,
       GROUPING(DATE(created_at), user_id) AS grp_mask
FROM posts
WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY GROUPING SETS ((DATE(created_at), user_id), (DATE(created_at)), (user_id), ());
```
**SQL Equivalente (MySQL ROLLUP):**
```sql
SELECT DATE(created_at) AS day, user_id, COUNT(*) AS posts
FROM posts
WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
GROUP BY DATE(created_at), user_id WITH ROLLUP;
```
**Emulación SQLite (UNION ALL):**
```sql
SELECT DATE(created_at) AS day, user_id, COUNT(*) AS posts
FROM posts
WHERE created_at >= DATE('now','-7 day')
GROUP BY DATE(created_at), user_id
UNION ALL
SELECT DATE(created_at) AS day, NULL user_id, COUNT(*) AS posts
FROM posts
WHERE created_at >= DATE('now','-7 day')
GROUP BY DATE(created_at)
UNION ALL
SELECT NULL day, user_id, COUNT(*) AS posts
FROM posts
WHERE created_at >= DATE('now','-7 day')
GROUP BY user_id
UNION ALL
SELECT NULL day, NULL user_id, COUNT(*) AS posts
FROM posts
WHERE created_at >= DATE('now','-7 day');
```
Interpretar totales: filas con `day` NULL representan subtotal por usuario; con `user_id` NULL subtotal por día; ambos NULL total general.

### Construcción Segura de Listas Dinámicas (IN / VALUES)

Nunca interpoles valores directamente en una cláusula IN. Genera placeholders dinámicamente.

```php
<?php
function fetchUsersByIds(array $ids) {
    $orm = VersaORM::getInstance();
    if (!$ids) { return []; }
    $placeholders = implode(',', array_fill(0, count($ids), '?'));
    $sql = "SELECT id, name FROM users WHERE id IN ($placeholders)";
    return $orm->query($sql, $ids);
}

// Inserción batch segura construyendo VALUES
function insertTags(array $names) {
    $orm = VersaORM::getInstance();
    if (!$names) return 0;
    $chunks = [];
    $params = [];
    foreach ($names as $n) { $chunks[] = '(?)'; $params[] = $n; }
    $sql = 'INSERT INTO tags (name) VALUES '.implode(',', $chunks);
    return $orm->execute($sql, $params);
}

// ORDER BY dinámico con whitelisting
function listPosts(string $orderBy = 'created_at', string $dir = 'DESC') {
    $allowedCols = ['created_at','view_count','title'];
    $allowedDir  = ['ASC','DESC'];
    if (!in_array($orderBy,$allowedCols)) $orderBy = 'created_at';
    if (!in_array(strtoupper($dir),$allowedDir)) $dir = 'DESC';
    $sql = "SELECT id,title,created_at,view_count FROM posts ORDER BY $orderBy $dir LIMIT 50";
    return VersaORM::getInstance()->query($sql);
}
```
**SQL Equivalente (patrón IN con placeholders):**
```sql
SELECT id, name FROM users WHERE id IN (?, ?, ?, ...);
```
**SQL Equivalente (batch insert tags):**
```sql
INSERT INTO tags (name) VALUES (?), (?), (?);
```
**Anti-Pattern (NO hacer):**
```sql
-- Vulnerable si se concatena: id IN (1,2,3); DROP TABLE users; --
```


---

## Seguridad en Consultas Raw

### Uso Correcto de Parámetros

```php
<?php
// ✅ Correcto: Usar parámetros preparados
function searchUsers($searchTerm, $limit = 10) {
    $orm = VersaORM::getInstance();

    $sql = "SELECT id, name, email
            FROM users
            WHERE (name LIKE ? OR email LIKE ?)
            AND active = 1
            ORDER BY name
            LIMIT ?";

    $searchPattern = "%$searchTerm%";
    return $orm->query($sql, [$searchPattern, $searchPattern, $limit]);
}

// ❌ Incorrecto: Concatenación directa (vulnerable a SQL injection)
function unsafeSearchUsers($searchTerm) {
    $orm = VersaORM::getInstance();

    // ¡NUNCA HAGAS ESTO!
    $sql = "SELECT * FROM users WHERE name LIKE '%$searchTerm%'";
    return $orm->query($sql);
}
```

### Validación de Entrada

```php
<?php
function safeComplexQuery($userId, $dateRange, $orderBy) {
    $orm = VersaORM::getInstance();

    // Validar parámetros
    if (!is_numeric($userId) || $userId <= 0) {
        throw new InvalidArgumentException("ID de usuario inválido");
    }

    // Whitelist para ORDER BY (no se puede parametrizar)
    $allowedOrderBy = ['created_at', 'title', 'view_count'];
    if (!in_array($orderBy, $allowedOrderBy)) {
        $orderBy = 'created_at';
    }

    // Validar formato de fecha
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $dateRange['start']) ||
        !preg_match('/^\d{4}-\d{2}-\d{2}$/', $dateRange['end'])) {
        throw new InvalidArgumentException("Formato de fecha inválido");
    }

    $sql = "SELECT p.*, u.name as author_name
            FROM posts p
            INNER JOIN users u ON p.user_id = u.id
            WHERE p.user_id = ?
            AND p.created_at BETWEEN ? AND ?
            ORDER BY p.$orderBy DESC"; // Validado previamente

    return $orm->query($sql, [$userId, $dateRange['start'], $dateRange['end']]);
}
```

## Cuándo Usar Consultas Raw

### Casos Apropiados

```php
<?php
// ✅ Usar Raw cuando:

// 1. Funciones específicas de la base de datos
$sql = "SELECT *, MATCH(title, content) AGAINST(? IN BOOLEAN MODE) as relevance
        FROM posts
        WHERE MATCH(title, content) AGAINST(? IN BOOLEAN MODE)
        ORDER BY relevance DESC";

// 2. Consultas muy complejas con múltiples JOINs y subconsultas
$sql = "SELECT u.name,
               (SELECT COUNT(*) FROM posts WHERE user_id = u.id) as post_count,
               (SELECT AVG(rating) FROM post_ratings pr
                JOIN posts p ON pr.post_id = p.id
                WHERE p.user_id = u.id) as avg_rating
        FROM users u
        WHERE u.id IN (
            SELECT DISTINCT user_id FROM posts
            WHERE created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
        )";

// 3. Operaciones de mantenimiento y administración
$sql = "ANALYZE TABLE posts";

// 4. Consultas de reporting complejas
$sql = "SELECT DATE(created_at) as date,
               COUNT(*) as posts,
               COUNT(DISTINCT user_id) as unique_authors
        FROM posts
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        GROUP BY DATE(created_at)
        ORDER BY date";
```

### Casos Donde NO Usar Raw

```php
<?php
// ❌ NO usar Raw para:

// 1. Consultas simples que el Query Builder puede manejar
// En lugar de:
// $sql = "SELECT * FROM users WHERE active = 1 ORDER BY name";
// Usar:
$users = $orm->table('users')->where('active', '=', true)->orderBy('name')->getAll();

// 2. Operaciones CRUD básicas
// En lugar de:
// $sql = "INSERT INTO users (name, email) VALUES (?, ?)";
// Usar:
$userId = $orm->table('users')->insert(['name' => $name, 'email' => $email]);

// 3. Consultas que pueden beneficiarse del sistema de relaciones
// En lugar de:
// $sql = "SELECT u.*, p.title FROM users u JOIN posts p ON u.id = p.user_id";
// Usar:
$users = $orm->table('users')->with('posts')->getAll();
```

## Debugging y Optimización

### Log de Consultas Raw

```php
<?php
class RawQueryLogger {
    private $orm;
    private $queries = [];

    public function __construct($orm) {
        $this->orm = $orm;
    }

    public function loggedQuery($sql, $params = []) {
        $start = microtime(true);

        try {
            $result = $this->orm->query($sql, $params);
            $duration = microtime(true) - $start;

            $this->queries[] = [
                'sql' => $sql,
                'params' => $params,
                'duration' => $duration,
                'rows' => count($result),
                'success' => true
            ];

            return $result;

        } catch (Exception $e) {
            $duration = microtime(true) - $start;

            $this->queries[] = [
                'sql' => $sql,
                'params' => $params,
                'duration' => $duration,
                'error' => $e->getMessage(),
                'success' => false
            ];

            throw $e;
        }
    }

    public function getQueryLog() {
        return $this->queries;
    }

    public function printQueryLog() {
        echo "Log de consultas Raw:\n";
        echo str_repeat("-", 100) . "\n";

        foreach ($this->queries as $i => $query) {
            echo "Query #" . ($i + 1) . ":\n";
            echo "SQL: " . $query['sql'] . "\n";
            echo "Params: " . json_encode($query['params']) . "\n";
            echo "Duration: " . number_format($query['duration'], 4) . "s\n";

            if ($query['success']) {
                echo "Rows: " . $query['rows'] . "\n";
            } else {
                echo "Error: " . $query['error'] . "\n";
            }

            echo str_repeat("-", 50) . "\n";
        }
    }
}

// Uso del logger
$logger = new RawQueryLogger($orm);

$results = $logger->loggedQuery(
    "SELECT * FROM users WHERE created_at > ? ORDER BY name LIMIT ?",
    ['2024-01-01', 10]
);

$logger->printQueryLog();
```

## Siguiente Paso

¡Felicidades! Has completado la sección de funcionalidades avanzadas. Ahora tienes las herramientas para manejar operaciones complejas, transacciones robustas y consultas especializadas.

Continúa con [Seguridad y Tipado](../07-seguridad-tipado/README.md) para aprender sobre las características de seguridad y el sistema de tipado estricto de VersaORM.
