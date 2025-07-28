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
            }

            // Insertar posts de ejemplo
            $posts = [
                ['user_id' => $userIds[0], 'title' => 'Mi primer post', 'content' => 'Este es el contenido de mi primer post', 'published' => true],
                ['user_id' => $userIds[0], 'title' => 'Aprendiendo VersaORM', 'content' => 'VersaORM es muy fácil de usar', 'views' => 15],
                ['user_id' => $userIds[1], 'title' => 'Tutorial de PHP', 'content' => 'En este tutorial aprenderemos PHP básico', 'published' => true, 'views' => 42],
                ['user_id' => $userIds[2], 'title' => 'Rust y PHP', 'content' => 'Combinando lo mejor de ambos mundos', 'views' => 8],
                ['user_id' => $userIds[1], 'title' => 'Base de datos relacionales', 'content' => 'Conceptos fundamentales de SQL', 'published' => true, 'views' => 23]
            ];
            
            foreach ($posts as $index => $post) {
                $sql = "INSERT INTO posts (user_id, title, content, views, published) VALUES (?, ?, ?, ?, ?)";
                $params = [
                    (int)$post['user_id'], 
                    $post['title'], 
                    $post['content'], 
                    (int)($post['views'] ?? 0), 
                    ($post['published'] ?? false) ? 1 : 0
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
     * Consultas básicas para verificar datos
     */
    public function verifyData(): array
    {
        $results = [];

        try {
            // Contar usuarios
            $userCount = $this->orm->table('users')->count();
            $results['user_count'] = "Total users: $userCount";

            // Contar posts
            $postCount = $this->orm->table('posts')->count();  
            $results['post_count'] = "Total posts: $postCount";
            
            // Obtener algunos usuarios
            $users = $this->orm->table('users')->get();
            $results['users'] = [];
            foreach ($users as $user) {
                $results['users'][] = "ID: {$user['id']}, Name: {$user['name']}, Email: {$user['email']}, Age: {$user['age']}, Status: {$user['status']}";
            }

            // Obtener algunos posts
            $posts = $this->orm->table('posts')->get();
            $results['posts'] = [];
            foreach ($posts as $post) {
                $results['posts'][] = "ID: {$post['id']}, User ID: {$post['user_id']}, Title: {$post['title']}, Views: {$post['views']}, Published: " . ($post['published'] ? 'Yes' : 'No');
            }

            return $results;
        } catch (Exception $e) {
            throw new Exception("Error verifying data: " . $e->getMessage());
        }
    }
}

// Ejecutar el flujo de pruebas
echo "=== VERSAORM CRUD API FLOW TEST ===\n\n";

try {
    $api = new VersaORMTestAPI();

    echo "STEP 1: Dropping existing tables...\n";
    $dropResult = $api->dropTables();
    echo json_encode($dropResult, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n\n";

    echo "STEP 2: Initializing tables...\n";
    $initResult = $api->initializeTables();
    echo json_encode($initResult, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n\n";

    echo "STEP 3: Seeding data...\n";
    $seedResult = $api->seedData();
    echo json_encode($seedResult, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n\n";

    echo "STEP 4: Verifying seeded data...\n";
    $verifyResult = $api->verifyData();
    echo json_encode($verifyResult, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n\n";

    echo "STEP 5: Testing CRUD operations...\n";
    $crudResult = $api->usersCRUD();
    echo json_encode($crudResult, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n\n";

    echo "STEP 6: Final verification...\n";
    $finalVerifyResult = $api->verifyData();
    echo json_encode($finalVerifyResult, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n\n";

    echo "=== ALL TESTS COMPLETED SUCCESSFULLY ===\n";

} catch (VersaORMException $e) {
    echo "VersaORM Error: " . $e->getMessage() . "\n";
    if ($e->getDetails()) {
        echo "Details: " . json_encode($e->getDetails(), JSON_PRETTY_PRINT) . "\n";
    }
    if ($e->getSuggestions()) {
        echo "Suggestions: " . json_encode($e->getSuggestions(), JSON_PRETTY_PRINT) . "\n";
    }
} catch (Throwable $e) {
    echo "General Error: " . $e->getMessage() . "\n";
    echo "File: " . $e->getFile() . "\n";
    echo "Line: " . $e->getLine() . "\n";
}

?>
