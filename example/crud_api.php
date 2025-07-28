<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/index.php';

use VersaORM\Exceptions\VersaORMException;
use VersaORM\VersaORM;
use VersaORM\Model;

class VersaORMTestAPI
{
    private ?VersaORM $orm = null;

    public function __construct()
    {
        $this->connectORM();
        Model::setORM($this->orm);
    }

    private function connectORM(): void
    {
        global $config;

        if (!isset($config['DB'])) {
            throw new Exception('Database configuration not found');
        }

        $db_config = $config['DB'];

        $this->orm = new VersaORM([
            'driver' => $db_config['DB_DRIVER'],
            'host' => $db_config['DB_HOST'],
            'port' => $db_config['DB_PORT'],
            'database' => $db_config['DB_NAME'],
            'username' => $db_config['DB_USER'],
            'password' => $db_config['DB_PASS']
        ]);
    }

    /**
     * Inicializar las tablas de prueba
     */
    public function initializeTables(): array
    {
        $results = [];

        // Crear tabla users
        $createUsersTable = "
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(150) UNIQUE NOT NULL,
                age INT DEFAULT NULL,
                status ENUM('active', 'inactive') DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB
        ";

        // Crear tabla posts
        $createPostsTable = "
            CREATE TABLE IF NOT EXISTS posts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                title VARCHAR(200) NOT NULL,
                content TEXT,
                views INT DEFAULT 0,
                published BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            ) ENGINE=InnoDB
        ";

        try {
            $this->orm->exec($createUsersTable);
            $results['users_table'] = 'Created successfully';

            $this->orm->exec($createPostsTable);
            $results['posts_table'] = 'Created successfully';

            return $results;
        } catch (Exception $e) {
            throw new Exception("Error creating tables: " . $e->getMessage());
        }
    }

    /**
     * Insertar datos de ejemplo
     */
    public function seedData(): array
    {
        $results = [];

        try {
            // Insertar usuarios de ejemplo
            $users = [
                ['name' => 'Juan Pérez', 'email' => 'juan@example.com', 'age' => 25],
                ['name' => 'María García', 'email' => 'maria@example.com', 'age' => 30],
                ['name' => 'Carlos López', 'email' => 'carlos@example.com', 'age' => 28],
                ['name' => 'Ana Martínez', 'email' => 'ana@example.com', 'age' => 35, 'status' => 'inactive']
            ];

            $userIds = [];
            foreach ($users as $user) {
                $sql = "INSERT INTO users (name, email, age" . (isset($user['status']) ? ', status' : '') . ") VALUES (?, ?, ?" . (isset($user['status']) ? ', ?' : '') . ")";
                $params = [$user['name'], $user['email'], $user['age']];
                if (isset($user['status'])) {
                    $params[] = $user['status'];
                }
                $this->orm->exec($sql, $params);
                $lastIdResult = $this->orm->exec('SELECT id FROM users WHERE email = ?', [$user['email']]);
                $lastId = (int)$lastIdResult[0]['id'];
                $userIds[] = $lastId;
                $results['users'][] = "User '{$user['name']}' created with ID: $lastId";
                $results['debug_user_ids'][] = "Stored user ID: $lastId (type: " . gettype($lastId) . ")";
            }

            // Insertar posts de ejemplo
            $posts = [
                ['user_id' => $userIds[0], 'title' => 'Mi primer post', 'content' => 'Este es el contenido de mi primer post', 'published' => true],
                ['user_id' => $userIds[0], 'title' => 'Aprendiendo VersaORM', 'content' => 'VersaORM es muy fácil de usar', 'views' => 15],
                ['user_id' => $userIds[1], 'title' => 'Tutorial de PHP', 'content' => 'En este tutorial aprenderemos PHP básico', 'published' => true, 'views' => 42],
                ['user_id' => $userIds[2], 'title' => 'Rust y PHP', 'content' => 'Combinando lo mejor de ambos mundos', 'views' => 8],
                ['user_id' => $userIds[1], 'title' => 'Base de datos relacionales', 'content' => 'Conceptos fundamentales de SQL', 'published' => true, 'views' => 23]
            ];

            // Debug: Verificar que tenemos user IDs válidos
            $results['debug_available_user_ids'] = $userIds;
            
            // Verificar que los usuarios realmente existen
            $existingUsers = $this->orm->exec('SELECT id FROM users ORDER BY id');
            $results['debug_existing_users'] = $existingUsers;
            
            foreach ($posts as $index => $post) {
                $results['debug_posts'][] = "Attempting to create post '{$post['title']}' for user_id: {$post['user_id']}";
                
                $sql = "INSERT INTO posts (user_id, title, content, views, published) VALUES (?, ?, ?, ?, ?)";
                $params = [
                    (int)$post['user_id'], 
                    $post['title'], 
                    $post['content'], 
                    (int)($post['views'] ?? 0), 
                    ($post['published'] ?? false) ? 1 : 0
                ];
                
                $results['debug_post_params'][] = [
                    'sql' => $sql,
                    'params' => $params
                ];
                
                $this->orm->exec($sql, $params);
                $postId = $this->orm->exec('SELECT LAST_INSERT_ID() as id')[0]['id'];
                $results['posts'][] = "Post '{$post['title']}' created with ID: $postId";
            }

            return $results;
        } catch (Exception $e) {
            throw new Exception("Error seeding data: " . $e->getMessage());
        }
    }

    /**
     * Operaciones CRUD básicas para usuarios
     */
    public function usersCRUD(): array
    {
        $results = [];

        try {
            // CREATE - Crear nuevo usuario usando raw query
            $newUser = [
                'name' => 'Pedro Silva',
                'email' => 'pedro@example.com',
                'age' => 32
            ];
            $this->orm->exec('INSERT INTO users (name, email, age) VALUES (?, ?, ?)', [
                $newUser['name'], $newUser['email'], $newUser['age']
            ]);
            $userResult = $this->orm->exec('SELECT id FROM users WHERE email = ?', [$newUser['email']]);
            $userId = $userResult[0]['id'];
            $results['create'] = "User created with ID: $userId";

            // READ - Obtener todos los usuarios
            $allUsers = $this->orm->table('users')->get();
            $results['read_all'] = count($allUsers) . " users found";

            // READ - Obtener usuario específico
            $user = $this->orm->table('users')->where('id', '=', $userId)->first();
            $results['read_one'] = $user ? "User found: {$user['name']}" : "User not found";

            // UPDATE - Actualizar usuario usando raw query
            $this->orm->exec('UPDATE users SET age = ?, status = ? WHERE id = ?', [33, 'active', $userId]);
            $results['update'] = "User with ID $userId updated successfully";

            // DELETE - Eliminar usuario (lo crearemos y eliminaremos para no afectar otros tests)
            $this->orm->exec('INSERT INTO users (name, email, age) VALUES (?, ?, ?)', [
                'Temp User', 'temp@example.com', 20
            ]);
            $tempUserResult = $this->orm->exec('SELECT id FROM users WHERE email = ?', ['temp@example.com']);
            $tempUserId = $tempUserResult[0]['id'];
            $this->orm->exec('DELETE FROM users WHERE id = ?', [$tempUserId]);
            $results['delete'] = "Temp user with ID $tempUserId deleted successfully";

            return $results;
        } catch (Exception $e) {
            throw new Exception("Error in users CRUD: " . $e->getMessage());
        }
    }

    /**
     * Consultas con WHERE complejas
     */
    public function complexQueries(): array
    {
        $results = [];

        try {
            // WHERE con múltiples condiciones
            $activeAdults = $this->orm->table('users')
                ->where('status', '=', 'active')
                ->where('age', '>=', 25)
                ->get();
            $results['active_adults'] = count($activeAdults) . " active users aged 25+";

            // WHERE con OR
            $youngOrSenior = $this->orm->table('users')
                ->where('age', '<', 26)
                ->orWhere('age', '>', 34)
                ->get();
            $results['young_or_senior'] = count($youngOrSenior) . " users under 26 or over 34";

            // WHERE IN
            $specificUsers = $this->orm->table('users')
                ->whereIn('name', ['Juan Pérez', 'María García'])
                ->get();
            $results['specific_users'] = count($specificUsers) . " specific users found";

            // WHERE LIKE
            $mariasUsers = $this->orm->table('users')
                ->where('name', 'LIKE', '%María%')
                ->get();
            $results['marias'] = count($mariasUsers) . " users with 'María' in name";

            // COUNT
            $totalUsers = $this->orm->table('users')->count();
            $results['total_count'] = "Total users: $totalUsers";

            // COUNT con WHERE
            $activeCount = $this->orm->table('users')
                ->where('status', '=', 'active')
                ->count();
            $results['active_count'] = "Active users: $activeCount";

            return $results;
        } catch (Exception $e) {
            throw new Exception("Error in complex queries: " . $e->getMessage());
        }
    }

    /**
     * Consultas con JOIN
     */
    public function joinQueries(): array
    {
        $results = [];

        try {
            // INNER JOIN - Usuarios con sus posts
            $usersWithPosts = $this->orm->table('users')
                ->select(['users.name', 'users.email', 'posts.title', 'posts.views'])
                ->join('posts', 'users.id', '=', 'posts.user_id')
                ->get();
            $results['users_with_posts'] = count($usersWithPosts) . " user-post combinations";

            // LEFT JOIN - Todos los usuarios, con o sin posts
            $allUsersWithPosts = $this->orm->table('users')
                ->select(['users.name', 'users.email', 'COUNT(posts.id) as post_count'])
                ->leftJoin('posts', 'users.id', '=', 'posts.user_id')
                ->groupBy(['users.id', 'users.name', 'users.email'])
                ->get();
            $results['all_users_post_count'] = count($allUsersWithPosts) . " users with post counts";

            // JOIN con WHERE
            $publishedPostsAuthors = $this->orm->table('users')
                ->select(['users.name', 'posts.title', 'posts.views'])
                ->join('posts', 'users.id', '=', 'posts.user_id')
                ->where('posts.published', '=', true)
                ->orderBy('posts.views', 'DESC')
                ->get();
            $results['published_posts'] = count($publishedPostsAuthors) . " published posts with authors";

            return $results;
        } catch (Exception $e) {
            throw new Exception("Error in join queries: " . $e->getMessage());
        }
    }

    /**
     * Agregaciones y funciones
     */
    public function aggregations(): array
    {
        $results = [];

        try {
            // AVG, MIN, MAX, SUM usando consultas raw
            $userStats = $this->orm->exec("
                SELECT 
                    AVG(age) as avg_age,
                    MIN(age) as min_age,
                    MAX(age) as max_age,
                    COUNT(*) as total_users
                FROM users 
                WHERE age IS NOT NULL
            ");
            $results['user_stats'] = $userStats[0] ?? 'No stats available';

            $postStats = $this->orm->exec("
                SELECT 
                    AVG(views) as avg_views,
                    MAX(views) as max_views,
                    SUM(views) as total_views,
                    COUNT(*) as total_posts
                FROM posts
            ");
            $results['post_stats'] = $postStats[0] ?? 'No stats available';

            // GROUP BY con HAVING
            $activeUsersByStatus = $this->orm->exec("
                SELECT 
                    status,
                    COUNT(*) as user_count,
                    AVG(age) as avg_age
                FROM users 
                GROUP BY status
                HAVING user_count > 0
            ");
            $results['users_by_status'] = $activeUsersByStatus;

            return $results;
        } catch (Exception $e) {
            throw new Exception("Error in aggregations: " . $e->getMessage());
        }
    }

    /**
     * Operaciones con el ORM Model
     */
    public function modelOperations(): array
    {
        $results = [];

        try {
            // Usar Model::dispense para crear nuevos objetos
            $user = Model::dispense('users');
            $user->name = 'Usuario Modelo';
            $user->email = 'modelo@example.com';
            $user->age = 27;
            
            // Guardar con store
            $savedUser = Model::store($user);
            $results['dispense_store'] = "User created via Model with ID: " . $savedUser['id'];

            // Cargar con load
            $loadedUser = Model::load('users', $savedUser['id']);
            $results['load'] = $loadedUser ? "User loaded: {$loadedUser->name}" : "User not found";

            // Modificar y guardar
            if ($loadedUser) {
                $loadedUser->age = 28;
                $updatedUser = Model::store($loadedUser);
                $results['update_model'] = "User age updated to: " . $updatedUser['age'];
            }

            // Usar find methods
            $foundUsers = Model::find('users', 'age > ?', [25]);
            $results['find'] = count($foundUsers) . " users found with age > 25";

            $firstUser = Model::findFirst('users', 'status = ?', ['active']);
            $results['find_first'] = $firstUser ? "First active user: {$firstUser->name}" : "No active user found";

            return $results;
        } catch (Exception $e) {
            throw new Exception("Error in model operations: " . $e->getMessage());
        }
    }

    /**
     * Operaciones de esquema
     */
    public function schemaOperations(): array
    {
        $results = [];

        try {
            // Obtener tablas
            $tables = $this->orm->schema('tables');
            $results['tables'] = $tables;

            // Obtener columnas de la tabla users
            $userColumns = $this->orm->schema('columns', 'users');
            $results['user_columns'] = $userColumns;

            // Obtener índices
            $userIndexes = $this->orm->schema('indexes', 'users');
            $results['user_indexes'] = $userIndexes;

            // Obtener claves foráneas
            $postsForeignKeys = $this->orm->schema('foreignKeys', 'posts');
            $results['posts_foreign_keys'] = $postsForeignKeys;

            return $results;
        } catch (Exception $e) {
            throw new Exception("Error in schema operations: " . $e->getMessage());
        }
    }

    /**
     * Operaciones de caché
     */
    public function cacheOperations(): array
    {
        $results = [];

        try {
            // Habilitar caché
            $this->orm->cache('enable');
            $results['cache_enabled'] = true;

            // Estado del caché
            $status = $this->orm->cache('status');
            $results['cache_status'] = $status;

            // Limpiar caché
            $this->orm->cache('clear');
            $results['cache_cleared'] = true;

            // Deshabilitar caché
            $this->orm->cache('disable');
            $results['cache_disabled'] = true;

            return $results;
        } catch (Exception $e) {
            throw new Exception("Error in cache operations: " . $e->getMessage());
        }
    }

    /**
     * Limpiar datos de prueba
     */
    public function cleanup(): array
    {
        $results = [];

        try {
            // Eliminar datos (pero mantener estructura)
            $deletedPosts = $this->orm->exec("DELETE FROM posts");
            $deletedUsers = $this->orm->exec("DELETE FROM users");
            
            // Resetear AUTO_INCREMENT
            $this->orm->exec("ALTER TABLE posts AUTO_INCREMENT = 1");
            $this->orm->exec("ALTER TABLE users AUTO_INCREMENT = 1");

            $results['cleanup'] = 'All test data removed, tables preserved';
            return $results;
        } catch (Exception $e) {
            throw new Exception("Error in cleanup: " . $e->getMessage());
        }
    }

    /**
     * Eliminar tablas completamente
     */
    public function dropTables(): array
    {
        $results = [];

        try {
            $this->orm->exec("DROP TABLE IF EXISTS posts");
            $this->orm->exec("DROP TABLE IF EXISTS users");
            
            $results['drop_tables'] = 'All test tables dropped';
            return $results;
        } catch (Exception $e) {
            throw new Exception("Error dropping tables: " . $e->getMessage());
        }
    }
}

// Manejar la API REST
header('Content-Type: application/json; charset=utf-8');

// Obtener acción desde URL
$action = $_GET['action'] ?? 'help';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

try {
    $api = new VersaORMTestAPI();

    $result = match ($action) {
        'help' => [
            'available_actions' => [
                'init' => 'Initialize tables (POST)',
                'seed' => 'Add sample data (POST)',
                'users-crud' => 'Test basic CRUD operations (GET)',
                'complex-queries' => 'Test complex WHERE queries (GET)',
                'joins' => 'Test JOIN queries (GET)',
                'aggregations' => 'Test aggregation functions (GET)',
                'models' => 'Test Model operations (GET)',
                'schema' => 'Test schema introspection (GET)',
                'cache' => 'Test cache operations (GET)',
                'cleanup' => 'Remove test data but keep tables (DELETE)',
                'drop' => 'Drop all test tables (DELETE)',
                'full-test' => 'Run all tests in sequence (POST)'
            ],
            'usage' => 'Add ?action=<action_name> to URL',
            'example' => 'crud_api.php?action=init'
        ],

        'init' => $method === 'POST' ? $api->initializeTables() : 
            ['error' => 'Use POST method to initialize tables'],

        'seed' => $method === 'POST' ? $api->seedData() : 
            ['error' => 'Use POST method to seed data'],

        'users-crud' => $api->usersCRUD(),
        'complex-queries' => $api->complexQueries(),
        'joins' => $api->joinQueries(),
        'aggregations' => $api->aggregations(),
        'models' => $api->modelOperations(),
        'schema' => $api->schemaOperations(),
        'cache' => $api->cacheOperations(),

        'cleanup' => $method === 'DELETE' ? $api->cleanup() : 
            ['error' => 'Use DELETE method to cleanup'],

        'drop' => $method === 'DELETE' ? $api->dropTables() : 
            ['error' => 'Use DELETE method to drop tables'],

        'full-test' => $method === 'POST' ? [
            'step_1_init' => $api->initializeTables(),
            'step_2_seed' => $api->seedData(),
            'step_3_crud' => $api->usersCRUD(),
            'step_4_queries' => $api->complexQueries(),
            'step_5_joins' => $api->joinQueries(),
            'step_6_aggregations' => $api->aggregations(),
            'step_7_models' => $api->modelOperations(),
            'step_8_schema' => $api->schemaOperations(),
            'step_9_cache' => $api->cacheOperations()
        ] : ['error' => 'Use POST method for full test'],

        default => ['error' => 'Unknown action. Use ?action=help for available actions']
    };

    echo json_encode([
        'status' => 'success',
        'action' => $action,
        'method' => $method,
        'data' => $result
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);

} catch (VersaORMException $e) {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'type' => 'VersaORM Error',
        'action' => $action,
        'message' => $e->getMessage(),
        'details' => $e->getDetails() ?? null,
        'suggestions' => $e->getSuggestions() ?? null
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);

} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'type' => 'General Error',
        'action' => $action,
        'message' => $e->getMessage(),
        'file' => $e->getFile(),
        'line' => $e->getLine()
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
}

?>
