<?php

require_once __DIR__ . '/bootstrap.php';

use VersaORM\VersaModel;


header('Content-Type: application/json');

// Obtener la instancia del ORM que fue configurada en bootstrap.php
use App\Models\Label;
use App\Models\Project;
use App\Models\Task;
use App\Models\User;

$orm = Task::getGlobalORM();

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
            exit;
    }

    // Usar el QueryBuilder para obtener todos los registros como arrays
    $data = $orm->table($tableName)->getAll();
} catch (Exception $e) {
    http_response_code(500);
    $data = ['error' => 'An internal server error occurred.', 'message' => $e->getMessage()];
}

echo json_encode($data, JSON_PRETTY_PRINT);
