<?php
// index.php - Controlador principal
require_once __DIR__ . '/autoload.php';

use Example\Models\Task;
use VersaORM\VersaORMException;

$config = [
    'DB' => [
        'DB_DRIVER' => 'mysql',
        'DB_HOST' => 'localhost',
        'DB_PORT' => 3306,
        'DB_NAME' => 'versaorm_test',
        'DB_USER' => 'local',
        'DB_PASS' => 'local'
    ]
];

// Manejo de acciones básicas
$action = $_GET['action'] ?? 'list';

if ($action === 'new') {
    include __DIR__ . '/views/new.php';
    exit;
}

if ($action === 'create' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = [
        'title' => $_POST['title'],
        'description' => $_POST['description'],
        'completed' => isset($_POST['completed']) ? true : false
    ];

    try {
        $task = Task::create($data);
        if ($task) {
            header('Location: index.php?success=created');
        } else {
            header('Location: index.php?error=create_failed');
        }
    } catch (Exception $e) {
        header('Location: index.php?error=' . urlencode($e->getMessage()));
    }
    exit;
}

if ($action === 'delete' && isset($_GET['id'])) {
    try {
        $task = Task::find($_GET['id']);
        if ($task && $task->delete()) {
            header('Location: index.php?success=deleted');
        } else {
            header('Location: index.php?error=delete_failed');
        }
    } catch (Exception $e) {
        header('Location: index.php?error=' . urlencode($e->getMessage()));
    }
    exit;
}

if ($action === 'edit' && isset($_GET['id'])) {
    try {
        $task = Task::find($_GET['id']);
        if (!$task) {
            header('Location: index.php?error=task_not_found');
            exit;
        }
        include __DIR__ . '/views/edit.php';
    } catch (Exception $e) {
        header('Location: index.php?error=' . urlencode($e->getMessage()));
    }
    exit;
}

if ($action === 'update' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $id = $_POST['id'];
    $data = [
        'title' => $_POST['title'],
        'description' => $_POST['description'],
        'completed' => isset($_POST['completed']) ? true : false
    ];

    try {
        $task = Task::find($id);
        if ($task && $task->update($data)) {
            header('Location: index.php?success=updated');
        } else {
            header('Location: index.php?error=update_failed');
        }
    } catch (Exception $e) {
        header('Location: index.php?error=' . urlencode($e->getMessage()));
    }
    exit;
}

if ($action === 'api' && ($_GET['format'] ?? '') === 'json') {
    $search = $_GET['search'] ?? '';

    try {
        if (empty($search)) {
            // Si no hay búsqueda, obtener todas las tareas
            $tasks = Task::all();
        } else {
            // Usar búsqueda case-insensitive estandarizada
            $tasks = Task::searchTasks($search);
        }

        // Convertir modelos a arrays exportables usando toArray() estandarizado
        // $tasksArray = [];
        // foreach ($tasks as $task) {
        //     $tasksArray[] = $task->toArray();
        // }

        // Establecer cabeceras HTTP para JSON
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Content-Type: application/json');

        // Responder con JSON
        echo json_encode([
            'success' => true,
            'count' => count($tasks),
            'search' => $search,
            'tasks' => $tasks
        ]);
    } catch (VersaORMException $e) {
        // Manejar errores y enviar respuesta de error
        header('HTTP/1.1 500 Internal Server Error');
        header('Content-Type: application/json');

        // Extraer query y bindings del mensaje de error si están disponibles
        $errorData = [
            'success' => false,
            'error' => $e->getMessage(),
            'trace' => $e->getTraceAsString(),
            'search' => $search ?? ''
        ];

        // Intentar extraer query y bindings de la excepción si están disponibles
        if (method_exists($e, 'getQuery') && $e->getQuery()) {
            $errorData['query'] = $e->getQuery();
        }
        if (method_exists($e, 'getBindings') && $e->getBindings()) {
            $errorData['bindings'] = $e->getBindings();
        }

        echo json_encode($errorData);
    }

    exit;
}

// Filtros y búsqueda avanzada
$search = $_GET['search'] ?? '';
$status = $_GET['status'] ?? '';
$order = $_GET['order'] ?? 'id';
$dir = $_GET['dir'] ?? 'desc';
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = isset($_GET['perPage']) ? max(1, (int)$_GET['perPage']) : 10;

// Obtener tareas usando métodos estandarizados
if (!empty($search) && empty($status)) {
    // Solo búsqueda de texto
    $tasks = Task::searchTasks($search);
    // Aplicar paginación manual para búsquedas
    $tasks = array_slice($tasks, ($page - 1) * $perPage, $perPage);
} elseif (!empty($status) && empty($search)) {
    // Solo filtro por estado
    $tasks = ($status === '1') ? Task::completed() : Task::pending();
    $tasks = array_slice($tasks, ($page - 1) * $perPage, $perPage);
} elseif (!empty($search) && !empty($status)) {
    // Búsqueda + filtro por estado (consulta personalizada)
    $taskModel = new Task();
    $searchLower = strtolower($search);
    $completedValue = ($status === '1') ? 1 : 0;

    $sql = "SELECT * FROM {$taskModel->getTable()}
            WHERE (LOWER(title) LIKE ? OR LOWER(description) LIKE ?)
            AND completed = ?
            ORDER BY {$order} {$dir}
            LIMIT ? OFFSET ?";

    $results = $taskModel->getORM()->exec($sql, [
        "%$searchLower%",
        "%$searchLower%",
        $completedValue,
        $perPage,
        ($page - 1) * $perPage
    ]);

    // Convertir a modelos
    $tasks = [];
    foreach ($results as $result) {
        $task = new Task();
        $task->loadInstance($result);
        $tasks[] = $task;
    }
} else {
    // Sin filtros, usar paginación estandarizada
    $paginationData = Task::paginate($page, $perPage);
    $tasks = $paginationData['data'];
}

// Estadísticas usando métodos estandarizados
$stats = Task::getStats();
$total = $stats['total'];
$completed = $stats['completed'];
$pending = $stats['pending'];

// Listar tareas
include __DIR__ . '/views/list.php';
