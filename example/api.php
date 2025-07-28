<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/index.php';

use VersaORM\Exceptions\VersaORMException;
use VersaORM\VersaORM;

class ApiTestProvider
{
    private ?VersaORM $orm = null;

    public function __construct()
    {
        $this->connectORM();
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

    public function testExistingTable(): array
    {
        if (!$this->orm) {
            throw new Exception('ORM connection not established');
        }

        // Intentar obtener datos de una tabla que sí existe
        return $this->orm->table('versausers')->limit(5)->get();
    }

    public function testNonExistentTable(): array
    {
        if (!$this->orm) {
            throw new Exception('ORM connection not established');
        }

        // Intentar obtener datos de una tabla que NO existe - esto debería lanzar una excepción
        return $this->orm->table('nonexistent_table')->get();
    }

    public function testConnection(): array
    {
        if (!$this->orm) {
            throw new Exception('ORM connection not established');
        }

        // Probar una consulta básica
        return $this->orm->exec('SELECT 1 as test');
    }
}

header('Content-Type: application/json; charset=utf-8');

// Obtener el parámetro de prueba
$test = $_GET['test'] ?? 'nonexistent';

try {
    $provider = new ApiTestProvider();

    switch ($test) {
        case 'existing':
            $result = $provider->testExistingTable();
            $message = 'Testing existing table (versausers)';
            break;

        case 'connection':
            $result = $provider->testConnection();
            $message = 'Testing basic connection';
            break;

        case 'nonexistent':
        default:
            $result = $provider->testNonExistentTable();
            $message = 'Testing non-existent table (should throw error)';
            break;
    }

    echo json_encode([
        'status' => 'success',
        'message' => $message,
        'data' => $result,
        'note' => 'If you see this with test=nonexistent, there might be an issue with error detection'
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
} catch (VersaORMException $e) {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'type' => 'VersaORM Error',
        'message' => $e->getMessage(),
        'details' => $e->getDetails() ?? null,
        'suggestions' => $e->getSuggestions() ?? null
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'type' => 'General Error',
        'message' => $e->getMessage(),
        'file' => $e->getFile(),
        'line' => $e->getLine()
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
}
