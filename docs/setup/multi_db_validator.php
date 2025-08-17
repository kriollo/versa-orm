<?php
/**
 * Validador Multi-Base de Datos para VersaORM
 *
 * Este script prueba la compatibillos ejemplos de documentación
 * con MySQL, PostgreSQL y SQLite.
 */

declare(strict_types=1);

require_once __DIR__ . '/../../vendor/autoload.php';
require_once __DIR__ . '/validate_documentation.php';

use VersaORM\VersaORM;
use VersaORM\VersaModel;
use VersaORM\VersaORMException;

class MultiDatabaseValidator extends DocumentationValidator
{
    private array $databaseConfigs;
    private array $testResults = [];

    public function __construct()
    {
        $this->databaseConfigs = require __DIR__ . '/database_test_config.php';
        $this->docsPath = __DIR__ . '/..';
    }

    /**
     * Ejecuta validación en todas las bases de datos disponibles
     */
    public function validateAllDatabases(): bool
    {
        echo "=== Validación Multi-Base de Datos VersaORM ===\n\n";

        $overallSuccess = true;

        foreach ($this->databaseConfigs as $dbName => $config) {
            if (!$config['enabled']) {
                echo "⏭️  Saltando {$dbName} (no configurado)\n\n";
                continue;
            }

            echo "🗄️  Probando con {$dbName}...\n";

            try {
                $success = $this->validateDatabase($dbName, $config);
                $this->testResults[$dbName] = $success;

                if ($success) {
                    echo "✅ {$dbName}: Todas las pruebas pasaron\n\n";
                } else {
                    echo "❌ {$dbName}: Algunas pruebas fallaron\n\n";
                    $overallSuccess = false;
                }

            } catch (Exception $e) {
                echo "💥 {$dbName}: Error de conexión - {$e->getMessage()}\n\n";
                $this->testResults[$dbName] = false;
                $overallSuccess = false;
            }
        }

        $this->generateMultiDbReport();
        return $overallSuccess;
    }

    /**
     * Valida ejemplos con una base de datos específica
     */
    private function validateDatabase(string $dbName, array $config): bool
    {
        // Inicializar ORM para esta base de datos
        $this->orm = new VersaORM($config);
        VersaModel::setORM($this->orm);

        // Configurar tablas específicas para cada motor
        $this->setupDatabaseSpecificTables($dbName);
        $this->insertTestData();

        // Extraer y validar ejemplos
        $this->extractCodeExamples();

        // Filtrar ejemplos específicos para este motor de BD
        $filteredExamples = $this->filterExamplesForDatabase($dbName);

        $passed = 0;
        $total = count($filteredExamples);

        foreach ($filteredExamples as $example) {
            $result = $this->validateSingleExample($example);
            if ($result['valid']) {
                $passed++;
            } else {
                echo "   ❌ {$this->getRelativePath($example['file'])}:{$example['line']} - {$result['error']}\n";
            }
        }

        echo "   📊 Resultados: {$passed}/{$total} ejemplos válidos\n";

        // Limpiar para la siguiente base de datos
        $this->cleanup();

        return $passed === $total;
    }

    /**
     * Configura tablas específicas para cada motor de base de datos
     */
    private function setupDatabaseSpecificTables(string $dbName): void
    {
        $sqlStatements = $this->getDatabaseSpecificSQL($dbName);

        foreach ($sqlStatements as $sql) {
            try {
                $this->orm->exec($sql);
            } catch (Exception $e) {
                echo "   ⚠️  Advertencia creando tabla: {$e->getMessage()}\n";
            }
        }
    }

    /**
     * Obtiene SQL específico para cada motor de base de datos
     */
    private function getDatabaseSpecificSQL(string $dbName): array
    {
        switch ($dbName) {
            case 'mysql':
                return [
                    "DROP TABLE IF EXISTS post_tags",
                    "DROP TABLE IF EXISTS posts",
                    "DROP TABLE IF EXISTS tags",
                    "DROP TABLE IF EXISTS users",
                    "
                    CREATE TABLE users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        name VARCHAR(100) NOT NULL,
                        email VARCHAR(100) UNIQUE NOT NULL,
                        active BOOLEAN DEFAULT TRUE,
                        age INT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    ) ENGINE=InnoDB
                    ",
                    "
                    CREATE TABLE posts (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        title VARCHAR(200) NOT NULL,
                        content TEXT,
                        user_id INT,
                        published BOOLEAN DEFAULT FALSE,
                        views INT DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                    ) ENGINE=InnoDB
                    ",
                    "
                    CREATE TABLE tags (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        name VARCHAR(50) NOT NULL UNIQUE
                    ) ENGINE=InnoDB
                    ",
                    "
                    CREATE TABLE post_tags (
                        post_id INT,
                        tag_id INT,
                        PRIMARY KEY (post_id, tag_id),
                        FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
                        FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
                    ) ENGINE=InnoDB
                    "
                ];

            case 'postgresql':
                return [
                    "DROP TABLE IF EXISTS post_tags CASCADE",
                    "DROP TABLE IF EXISTS posts CASCADE",
                    "DROP TABLE IF EXISTS tags CASCADE",
                    "DROP TABLE IF EXISTS users CASCADE",
                    "
                    CREATE TABLE users (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(100) NOT NULL,
                        email VARCHAR(100) UNIQUE NOT NULL,
                        active BOOLEAN DEFAULT TRUE,
                        age INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                    ",
                    "
                    CREATE TABLE posts (
                        id SERIAL PRIMARY KEY,
                        title VARCHAR(200) NOT NULL,
                        content TEXT,
                        user_id INTEGER,
                        published BOOLEAN DEFAULT FALSE,
                        views INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                    )
                    ",
                    "
                    CREATE TABLE tags (
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(50) NOT NULL UNIQUE
                    )
                    ",
                    "
                    CREATE TABLE post_tags (
                        post_id INTEGER,
                        tag_id INTEGER,
                        PRIMARY KEY (post_id, tag_id),
                        FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
                        FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
                    )
                    "
                ];

            case 'sqlite':
            default:
                return [
                    "DROP TABLE IF EXISTS post_tags",
                    "DROP TABLE IF EXISTS posts",
                    "DROP TABLE IF EXISTS tags",
                    "DROP TABLE IF EXISTS users",
                    "
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name VARCHAR(100) NOT NULL,
                        email VARCHAR(100) UNIQUE NOT NULL,
                        active BOOLEAN DEFAULT 1,
                        age INTEGER,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                    ",
                    "
                    CREATE TABLE posts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title VARCHAR(200) NOT NULL,
                        content TEXT,
                        user_id INTEGER,
                        published BOOLEAN DEFAULT 0,
                        views INTEGER DEFAULT 0,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )
                    ",
                    "
                    CREATE TABLE tags (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name VARCHAR(50) NOT NULL UNIQUE
                    )
                    ",
                    "
                    CREATE TABLE post_tags (
                        post_id INTEGER,
                        tag_id INTEGER,
                        PRIMARY KEY (post_id, tag_id),
                        FOREIGN KEY (post_id) REFERENCES posts(id),
                        FOREIGN KEY (tag_id) REFERENCES tags(id)
                    )
                    "
                ];
        }
    }

    /**
     * Filtra ejemplos relevantes para una base de datos específica
     */
    private function filterExamplesForDatabase(string $dbName): array
    {
        // Por ahora, todos los ejemplos deberían funcionar en todas las BD
        // En el futuro se pueden agregar filtros específicos
        return $this->codeExamples;
    }

    /**
     * Inserta datos de prueba compatibles con todas las BD
     */
    protected function insertTestData(): void
    {
        // Limpiar datos existentes
        try {
            $this->orm->exec("DELETE FROM post_tags");
            $this->orm->exec("DELETE FROM posts");
            $this->orm->exec("DELETE FROM tags");
            $this->orm->exec("DELETE FROM users");
        } catch (Exception $e) {
            // Ignorar errores de limpieza
        }

        // Insertar usuarios usando VersaORM (más compatible)
        $users = [
            ['name' => 'Juan Pérez', 'email' => 'juan@ejemplo.com', 'active' => true, 'age' => 30],
            ['name' => 'María García', 'email' => 'maria@ejemplo.com', 'active' => true, 'age' => 25],
            ['name' => 'Carlos López', 'email' => 'carlos@ejemplo.com', 'active' => false, 'age' => 35],
        ];

        foreach ($users as $userData) {
            $user = VersaModel::dispense('users');
            foreach ($userData as $key => $value) {
                $user->$key = $value;
            }
            $user->store();
        }

        // Insertar posts
        $posts = [
            ['title' => 'Mi primer post', 'content' => 'Contenido del primer post', 'user_id' => 1, 'published' => true, 'views' => 100],
            ['title' => 'Segundo post', 'content' => 'Contenido del segundo post', 'user_id' => 1, 'published' => false, 'views' => 50],
            ['title' => 'Post de María', 'content' => 'Contenido de María', 'user_id' => 2, 'published' => true, 'views' => 75],
        ];

        foreach ($posts as $postData) {
            $post = VersaModel::dispense('posts');
            foreach ($postData as $key => $value) {
                $post->$key = $value;
            }
            $post->store();
        }

        // Insertar tags
        $tags = [
            ['name' => 'php'],
            ['name' => 'orm'],
            ['name' => 'tutorial'],
        ];

        foreach ($tags as $tagData) {
            $tag = VersaModel::dispense('tags');
            $tag->name = $tagData['name'];
            $tag->store();
        }

        // Insertar relaciones usando VersaORM
        $postTagRelations = [
            [1, 1], [1, 2], [2, 1], [3, 3]
        ];

        foreach ($postTagRelations as [$postId, $tagId]) {
            try {
                $this->orm->exec(
                    "INSERT INTO post_tags (post_id, tag_id) VALUES (?, ?)",
                    [$postId, $tagId]
                );
            } catch (Exception $e) {
                // Ignorar duplicados
            }
        }
    }

    /**
     * Limpia recursos después de cada prueba
     */
    private function cleanup(): void
    {
        $this->orm = null;
        $this->codeExamples = [];
        $this->validationResults = [];
    }

    /**
     * Genera reporte de compatibilidad multi-base de datos
     */
    private function generateMultiDbReport(): void
    {
        echo "=== REPORTE DE COMPATIBILIDAD MULTI-BD ===\n\n";

        $totalDatabases = count(array_filter($this->databaseConfigs, fn($config) => $config['enabled']));
        $successfulDatabases = count(array_filter($this->testResults));

        echo "📊 Resumen de Compatibilidad:\n";
        foreach ($this->testResults as $dbName => $success) {
            $status = $success ? '✅' : '❌';
            echo "   {$status} {$dbName}\n";
        }

        echo "\n📈 Estadísticas Generales:\n";
        echo "   - Bases de datos probadas: {$totalDatabases}\n";
        echo "   - Bases de datos exitosas: {$successfulDatabases}\n";
        echo "   - Tasa de éxito: " . round(($successfulDatabases / max($totalDatabases, 1)) * 100, 1) . "%\n\n";

        if ($successfulDatabases === $totalDatabases) {
            echo "🎉 ¡Compatibilidad completa!\n";
            echo "   Todos los ejemplos funcionan en todas las bases de datos.\n";
        } else {
            echo "⚠️  Problemas de compatibilidad detectados.\n";
            echo "   Revisa los errores específicos arriba.\n";
        }

        // Guardar reporte
        $reportFile = __DIR__ . '/multi_db_report.json';
        $report = [
            'timestamp' => date('Y-m-d H:i:s'),
            'databases_tested' => $totalDatabases,
            'successful_databases' => $successfulDatabases,
            'success_rate' => round(($successfulDatabases / max($totalDatabases, 1)) * 100, 1),
            'results' => $this->testResults,
            'configurations' => array_map(
                fn($config) => array_intersect_key($config, array_flip(['driver', 'enabled'])),
                $this->databaseConfigs
            )
        ];

        file_put_contents($reportFile, json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        echo "\n📄 Reporte detallado guardado en: multi_db_report.json\n";
    }
}

// Ejecutar validación multi-BD si se llama directamente
if (basename(__FILE__) === basename($_SERVER['SCRIPT_NAME'])) {
    $validator = new MultiDatabaseValidator();
    $success = $validator->validateAllDatabases();
    exit($success ? 0 : 1);
}
