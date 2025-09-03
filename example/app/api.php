<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

header('Content-Type: application/json');

// Instancia del ORM por petición
$orm = app()->orm();

$resource = $_GET['resource'] ?? null;

try {
    $tableName = null;

    switch ($resource) {
        case 'projects':
            $tableName = 'projects';
            break;
        case 'tasks':
            $tableName = 'tasks';
            break;
        case 'notes':
            $tableName = 'task_notes';
            break;
        case 'users':
            $tableName = 'users';
            break;
        default:
            http_response_code(400);
            $data = ['error' => 'Invalid resource requested. Available resources: projects, tasks, notes, users.'];
            echo json_encode($data, JSON_PRETTY_PRINT);
            exit();
    }

    // Usar el QueryBuilder para obtener todos los registros como arrays
    $data = $orm->table($tableName)->getAll();
} catch (Exception $e) {
    http_response_code(500);
    $data = ['error' => 'An internal server error occurred.', 'message' => $e->getMessage()];
}

echo json_encode($data, JSON_PRETTY_PRINT);
