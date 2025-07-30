<?php
// index.php - Controlador principal
require_once __DIR__ . '/autoload.php';

use Example\Models\Project;
use Example\Models\Task;
use Example\Models\User;
use VersaORM\VersaORMException;

$config = [
    'DB' => [
        'DB_DRIVER' => 'mysql',
        'DB_HOST' => 'localhost',
        'DB_PORT' => 3306,
        'DB_NAME' => 'versaorm_test',
        'DB_USER' => 'local',
        'DB_PASS' => 'local',
        // Activar modo debug para errores detallados y logging
        'debug' => true  // false para producción
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
    if (isset($_POST['project_id']) && is_numeric($_POST['project_id'])) {
        $data['project_id'] = (int)$_POST['project_id'];
    }
    try {
        $task = Task::create($data);
        if ($task) {
            if (isset($data['project_id'])) {
                header('Location: index.php?action=show_project&id=' . $data['project_id'] . '&success=created');
            } else {
                header('Location: index.php?success=created');
            }
        } else {
            header('Location: index.php?error=create_failed');
        }
    } catch (VersaORMException $e) {
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
    } catch (VersaORMException $e) {
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

// --- Módulo de Proyectos como pantalla principal ---
// (No repetir el use Example\Models\Project; aquí, ya está declarado arriba)

if (!isset($action) || $action === 'projects' || $action === 'list' || $action === '') {
    // Listar proyectos y tareas asociadas (pantalla principal)
    $projects = Project::allArray();
    $tasksByProject = [];
    foreach ($projects as $project) {
        $tasksByProject[$project['id']] = (new Project())->find($project['id'])->tasksArray();
    }
    include __DIR__ . '/views/projects_list.php';
    exit;
}

if ($action === 'show_project' && isset($_GET['id'])) {
    $projectObj = Project::find($_GET['id']);
    if (!$projectObj) {
        header('Location: index.php?action=projects&error=not_found');
        exit;
    }
    $project = $projectObj->toArray();
    $tasks = $projectObj->tasksArray();
    $user = $projectObj->userArray();
    $completedCount = count($projectObj->completedTasksArray());
    $totalCount = $projectObj->countTasks();
    $cacheStatus = $projectObj->cacheStatus();
    include __DIR__ . '/views/project_show.php';
    exit;
}

if ($action === 'complete_all_tasks' && isset($_GET['id'])) {
    $projectObj = Project::find($_GET['id']);
    if ($projectObj) {
        try {
            $projectObj->completeAllTasks();
            header('Location: index.php?action=show_project&id=' . $projectObj->id . '&success=all_completed');
        } catch (Exception $e) {
            header('Location: index.php?action=show_project&id=' . $projectObj->id . '&error=tx_failed');
        }
    } else {
        header('Location: index.php?action=projects&error=not_found');
    }
    exit;
}

if ($action === 'export_project_json' && isset($_GET['id'])) {
    $projectObj = Project::find($_GET['id']);
    if ($projectObj) {
        $data = [
            'project' => $projectObj->toArray(),
            'tasks' => $projectObj->tasksArray(),
            'user' => $projectObj->userArray()
        ];
        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="project_' . $projectObj->id . '.json"');
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }
    header('Location: index.php?action=projects&error=not_found');
    exit;
}

if ($action === 'new_user') {
    include __DIR__ . '/views/user_new.php';
    exit;
}

if ($action === 'create_user' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = [
        'name' => $_POST['name'],
        'email' => $_POST['email']
    ];
    try {
        $user = User::create($data);
        if ($user) {
            header('Location: index.php?action=projects&success=user_created');
        } else {
            header('Location: index.php?action=projects&error=user_create_failed');
        }
    } catch (Exception $e) {
        header('Location: index.php?action=projects&error=' . urlencode($e->getMessage()));
    }
    exit;
}

if ($action === 'new_project') {
    $users = User::allArray();
    include __DIR__ . '/views/project_new.php';
    exit;
}

if ($action === 'edit_project' && isset($_GET['id'])) {
    $project = Project::find($_GET['id']);
    if (!$project) {
        header('Location: index.php?action=projects&error=not_found');
        exit;
    }
    $users = User::allArray();
    include __DIR__ . '/views/edit_project.php';
    exit;
}

if ($action === 'create_project' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = [
        'name' => $_POST['name'],
        'description' => $_POST['description'] ?? ''
    ];
    if (!empty($_POST['user_id'])) {
        $data['user_id'] = (int)$_POST['user_id'];
    }
    try {
        $project = Project::create($data);
        if ($project) {
            header('Location: index.php?action=show_project&id=' . $project->id . '&success=created');
        } else {
            header('Location: index.php?action=projects&error=create_failed');
        }
    } catch (Exception $e) {
        header('Location: index.php?action=projects&error=' . urlencode($e->getMessage()));
    }
    exit;
}

if ($action === 'update_project' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $id = $_POST['id'];
    $data = [
        'name' => $_POST['name'],
        'description' => $_POST['description']
    ];
    if (!empty($_POST['user_id'])) {
        $data['user_id'] = (int)$_POST['user_id'];
    }
    try {
        $project = Project::find($id);
        if ($project && $project->update($data)) {
            header('Location: index.php?action=show_project&id=' . $id . '&success=updated');
        } else {
            header('Location: index.php?action=projects&error=update_failed');
        }
    } catch (Exception $e) {
        header('Location: index.php?action=projects&error=' . urlencode($e->getMessage()));
    }
    exit;
}

// === Gestión de etiquetas ===
if (isset($_GET['view']) && $_GET['view'] === 'labels_list') {
    include __DIR__ . '/views/labels_list.php';
    exit;
}
if (isset($_GET['view']) && $_GET['view'] === 'label_new') {
    include __DIR__ . '/views/label_new.php';
    exit;
}
if (isset($_GET['view']) && $_GET['view'] === 'task_labels_edit' && isset($_GET['task_id'])) {
    include __DIR__ . '/views/task_labels_edit.php';
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
    // Solo búsqueda de texto (array asociativo, paginación en SQL)
    $taskModel = new Task();
    $searchLower = strtolower($search);
    $sql = "SELECT * FROM {$taskModel->getTable()}\n            WHERE (LOWER(title) LIKE ? OR LOWER(description) LIKE ?)\n            ORDER BY {$order} {$dir}\n            LIMIT ? OFFSET ?";
    $tasks = $taskModel->getORM()->exec($sql, [
        "%$searchLower%",
        "%$searchLower%",
        $perPage,
        ($page - 1) * $perPage
    ]);
} elseif (!empty($status) && empty($search)) {
    // Solo filtro por estado (array asociativo)
    if ($status === '1') {
        $tasks = Task::whereArray('completed', '=', 1);
    } else {
        $tasks = Task::whereArray('completed', '=', 0);
    }
    $tasks = array_slice($tasks, ($page - 1) * $perPage, $perPage);
} elseif (!empty($search) && !empty($status)) {
    // Búsqueda + filtro por estado (consulta personalizada, array asociativo)
    $taskModel = new Task();
    $searchLower = strtolower($search);
    $completedValue = ($status === '1') ? 1 : 0;
    $sql = "SELECT * FROM {$taskModel->getTable()}\n            WHERE (LOWER(title) LIKE ? OR LOWER(description) LIKE ?)\n            AND completed = ?\n            ORDER BY {$order} {$dir}\n            LIMIT ? OFFSET ?";
    $tasks = $taskModel->getORM()->exec($sql, [
        "%$searchLower%",
        "%$searchLower%",
        $completedValue,
        $perPage,
        ($page - 1) * $perPage
    ]);
} else {
    // Sin filtros, usar paginación estandarizada (array asociativo)
    $paginationData = Task::paginateArray($page, $perPage);
    $tasks = $paginationData['data'];
}

// Estadísticas usando métodos estandarizados
$stats = Task::getStats();
$total = $stats['total'];
$completed = $stats['completed'];
$pending = $stats['pending'];

// Listar tareas
include __DIR__ . '/views/list.php';
