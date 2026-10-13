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
        case 'labels':
            $tableName = 'labels';
            break;
        default:
            http_response_code(400);
            $data = [
                'error' => 'Invalid resource requested. '
                    . 'Available resources: projects, tasks, notes, users, labels.',
            ];
            echo json_encode($data, JSON_PRETTY_PRINT);
            exit();
    }

    // Usar el QueryBuilder para obtener todos los registros como arrays
    $rows = $orm->table($tableName)->getAll();

    // VersaORM castea las columnas datetime a objetos DateTime. Serializarlos tal cual
    // emite su estructura interna ({"date":...,"timezone_type":3,...}) en vez de la
    // fecha, así que se formatean antes de responder.
    $data = array_map(static function (array $row): array {
        foreach ($row as $key => $value) {
            if ($value instanceof DateTimeInterface) {
                $row[$key] = $value->format('Y-m-d H:i:s');
            }
        }

        return $row;
    }, $rows);
} catch (Exception $e) {
    http_response_code(500);
    $data = ['error' => 'An internal server error occurred.', 'message' => $e->getMessage()];
}

echo json_encode($data, JSON_PRETTY_PRINT);
