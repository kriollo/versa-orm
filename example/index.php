<?php
// index.php - Controlador principal
require_once __DIR__ . '/autoload.php';

use VersaORM\VersaORM;
use VersaORM\VersaModel;
use VersaORM\VersaORMException;
use Example\Models\Project;
use Example\Models\Task;
use Example\Models\Label;
use Example\Models\User;

$config = [
    'DB' => [
        'driver' => 'mysql',
        'host' => 'localhost',
        'port' => 3306,
        'database' => 'versaorm_test',
        'username' => 'local',
        'password' => 'local',
        // Activar modo debug para errores detallados y logging
        'debug' => true  // false para producción
    ]
];

$orm = new VersaORM($config['DB']);
VersaModel::setORM($orm);

function render_view($view, $vars = [])
{
    extract($vars);
    ob_start();
    include __DIR__ . "/views/$view.php";
    $content = ob_get_clean();
    include __DIR__ . '/views/layout.php';
}

// --- PRIORIDAD: Si hay parámetro view, mostrar la vista correspondiente ---
if (isset($_GET['view'])) {
    if ($_GET['view'] === 'labels_list') {
        $labels = Label::all();
        $selectedLabelId = $_GET['label_id'] ?? null;
        $tareas = $selectedLabelId ? Task::byLabel((int)$selectedLabelId) : [];

        // Preparar tareas por etiqueta para evitar consultas en la vista
        $tareasPorEtiqueta = [];
        foreach ($labels as $label) {
            $labelId = is_object($label) ? $label->id : $label['id'];
            try {
                $tareasPorEtiqueta[$labelId] = Task::byLabel($labelId);
            } catch (Exception $e) {
                $tareasPorEtiqueta[$labelId] = [];
            }
        }

        render_view('labels_list', compact('labels', 'selectedLabelId', 'tareas', 'tareasPorEtiqueta'));
        return;
    }
    if ($_GET['view'] === 'label_new') {
        render_view('label_new');
        return;
    }
    if ($_GET['view'] === 'task_labels_edit' && isset($_GET['task_id'])) {
        $task_id = (int)$_GET['task_id'];
        render_view('task_labels_edit', compact('task_id'));
        return;
    }
    if ($_GET['view'] === 'label_edit' && isset($_GET['id'])) {
        $id = (int)$_GET['id'];
        render_view('label_edit', compact('id'));
        return;
    }
}

$action = $_GET['action'] ?? 'projects';

if ($action === 'new') {
    render_view('new');
    return;
}

if ($action === 'edit' && isset($_GET['id'])) {
    try {
        $task = Task::find($_GET['id']);
        if (!$task) {
            render_view('error', ['message' => 'Tarea no encontrada']);
            return;
        }
        $allLabels = Label::all();
        $allProjects = Project::allArray();
        $allUsers = User::allArray();
        render_view('edit', compact('task', 'allLabels', 'allProjects', 'allUsers'));
    } catch (VersaORMException $e) {
        render_view('error', ['message' => $e->getMessage()]);
    }
    return;
}

if ($action === 'new_user') {
    render_view('user_new');
    return;
}

if ($action === 'new_project') {
    $users = User::allArray();
    render_view('project_new', compact('users'));
    return;
}

if ($action === 'edit_project' && isset($_GET['id'])) {
    $project = Project::find($_GET['id']);
    if (!$project) {
        render_view('error', ['message' => 'Proyecto no encontrado']);
        return;
    }
    $users = User::allArray();
    render_view('edit_project', compact('project', 'users'));
    return;
}

if ($action === 'projects' || $action === '' || !isset($action)) {
    $projects = Project::allArray();
    $tasksByProject = [];
    foreach ($projects as $project) {
        $tasksByProject[$project['id']] = (new Project())->find($project['id'])->tasksArray();
    }
    render_view('projects_list', compact('projects', 'tasksByProject'));
    return;
}

if ($action === 'tasks') {
    $search = $_GET['search'] ?? '';
    $status = $_GET['status'] ?? '';
    $labelId = isset($_GET['label_id']) ? (int)$_GET['label_id'] : null;
    $projectId = isset($_GET['project_id']) ? (int)$_GET['project_id'] : null;
    $order = $_GET['order'] ?? 'id';
    $dir = $_GET['dir'] ?? 'desc';
    $page = max(1, (int)($_GET['page'] ?? 1));
    $perPage = isset($_GET['perPage']) ? max(1, (int)$_GET['perPage']) : 10;
    $allProjects = Project::allArray();
    $allLabels = Label::all();
    $filters = [];
    if ($projectId) $filters[] = ['project_id', '=', $projectId];
    if ($status !== '') $filters[] = ['completed', '=', $status === '1' ? 1 : 0];
    if ($labelId) {
        $taskIds = array_column(Task::byLabel($labelId), 'id');
        $filters[] = $taskIds ? ['id', 'IN', $taskIds] : ['id', 'IN', [0]];
    }
    $tasksData = [];
    $total = 0;
    $totalPages = 1;
    if ($search !== '') {
        $results = Task::searchArray($search, ['title', 'description']);
        foreach ($filters as $f) {
            $results = array_filter($results, function ($t) use ($f) {
                [$col, $op, $val] = $f;
                if ($op === 'IN') return in_array($t[$col], (array)$val);
                return $t[$col] == $val;
            });
        }
        $total = count($results);
        $totalPages = max(1, ceil($total / $perPage));
        $tasksData = array_slice(array_values($results), ($page - 1) * $perPage, $perPage);
    } else {
        $orm = VersaModel::getGlobalORM();
        $query = $orm->table('tasks');
        foreach ($filters as $f) {
            [$col, $op, $val] = $f;
            $query = $op === 'IN' ? $query->whereIn($col, $val) : $query->where($col, $op, $val);
        }
        $query = $query->orderBy($order, $dir)->limit($perPage)->offset(($page - 1) * $perPage);
        $tasksData = $query->getAll();
        $total = $orm->table('tasks');
        foreach ($filters as $f) {
            [$col, $op, $val] = $f;
            $total = $op === 'IN' ? $total->whereIn($col, $val) : $total->where($col, $op, $val);
        }
        $total = $total->count();
        $totalPages = max(1, ceil($total / $perPage));
    }
    render_view('list', compact('tasksData', 'allProjects', 'allLabels', 'search', 'status', 'labelId', 'projectId', 'order', 'dir', 'page', 'perPage', 'total', 'totalPages') + ['tasks' => $tasksData]);
    return;
}

// Manejo de acciones básicas
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

if (!isset($action) || $action === 'projects' || $action === '' || !isset($action)) {
    // Listar proyectos y tareas asociadas (pantalla principal)
    $projects = Project::allArray();
    $tasksByProject = [];
    foreach ($projects as $project) {
        $tasksByProject[$project['id']] = (new Project())->find($project['id'])->tasksArray();
    }
    render_view('projects_list', compact('projects', 'tasksByProject'));
    return;
}

if ($action === 'show_project' && isset($_GET['id'])) {
    $projectObj = Project::find($_GET['id']);
    if (!$projectObj) {
        header('Location: index.php?action=projects&error=not_found');
        exit;
    }
    $project = $projectObj->toArray();
    $user = $projectObj->userArray();
    $completedCount = count($projectObj->completedTasksArray());
    $totalCount = $projectObj->countTasks();
    $cacheStatus = $projectObj->cacheStatus();

    // --- Filtros y paginación para tareas de este proyecto ---
    $search = $_GET['search'] ?? '';
    $status = $_GET['status'] ?? '';
    $labelId = isset($_GET['label_id']) ? (int)$_GET['label_id'] : null;
    $order = $_GET['order'] ?? 'id';
    $dir = $_GET['dir'] ?? 'desc';
    $page = max(1, (int)($_GET['page'] ?? 1));
    $perPage = isset($_GET['perPage']) ? max(1, (int)$_GET['perPage']) : 10;

    // Obtener todas las etiquetas para el filtro
    $allLabels = Label::all();

    // Construir consulta usando solo métodos del ORM
    $filters = [['project_id', '=', $projectObj->id]];
    if ($status !== '') {
        $filters[] = ['completed', '=', $status === '1' ? 1 : 0];
    }
    if ($labelId) {
        $taskIds = array_column(Task::byLabel($labelId), 'id');
        if ($taskIds) {
            $filters[] = ['id', 'IN', $taskIds];
        } else {
            $filters[] = ['id', 'IN', [0]];
        }
    }
    $tasksData = [];
    $total = 0;
    $totalPages = 1;

    // 1. Obtener tareas filtradas por ORM (proyecto, estado, etiqueta)
    $orm = VersaModel::getGlobalORM();
    $query = $orm->table('tasks');
    foreach ($filters as $f) {
        [$col, $op, $val] = $f;
        $query = $op === 'IN' ? $query->whereIn($col, $val) : $query->where($col, $op, $val);
    }
    $query = $query->orderBy($order, $dir);
    $allFiltered = $query->getAll();

    // 2. Si hay búsqueda, filtrar sobre ese subconjunto
    if ($search !== '') {
        $searchLower = mb_strtolower($search);
        $allFiltered = array_filter($allFiltered, function ($t) use ($searchLower) {
            return mb_strpos(mb_strtolower($t['title']), $searchLower) !== false || mb_strpos(mb_strtolower($t['description']), $searchLower) !== false;
        });
    }
    $total = count($allFiltered);
    $totalPages = max(1, ceil($total / $perPage));
    $tasksData = array_slice(array_values($allFiltered), ($page - 1) * $perPage, $perPage);

    render_view('project_show', compact('project', 'user', 'completedCount', 'totalCount', 'cacheStatus', 'tasksData', 'allLabels', 'search', 'status', 'labelId', 'order', 'dir', 'page', 'perPage', 'total', 'totalPages'));
    return;
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
    return;
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

// --- Filtros y búsqueda avanzada para listado general de tareas ---
if ($action === 'list' || $action === 'tasks' || $action === '') {
    $search = $_GET['search'] ?? '';
    $status = $_GET['status'] ?? '';
    $labelId = isset($_GET['label_id']) ? (int)$_GET['label_id'] : null;
    $projectId = isset($_GET['project_id']) ? (int)$_GET['project_id'] : null;
    $order = $_GET['order'] ?? 'id';
    $dir = $_GET['dir'] ?? 'desc';
    $page = max(1, (int)($_GET['page'] ?? 1));
    $perPage = isset($_GET['perPage']) ? max(1, (int)$_GET['perPage']) : 10;

    // Para selects
    $allProjects = Project::allArray();
    $allLabels = Label::all();

    // Construir consulta usando solo métodos del ORM
    $filters = [];
    if ($projectId) {
        $filters[] = ['project_id', '=', $projectId];
    }
    if ($status !== '') {
        $filters[] = ['completed', '=', $status === '1' ? 1 : 0];
    }
    // Filtro por etiqueta (muchos a muchos)
    if ($labelId) {
        $taskIds = array_column(Task::byLabel($labelId), 'id');
        if ($taskIds) {
            $filters[] = ['id', 'IN', $taskIds];
        } else {
            $filters[] = ['id', 'IN', [0]]; // No hay tareas con esa etiqueta
        }
    }
    // Filtro por búsqueda
    $tasksData = [];
    $total = 0;
    $totalPages = 1;
    if ($search !== '') {
        $results = Task::searchArray($search, ['title', 'description']);
        // Aplicar filtros adicionales
        foreach ($filters as $f) {
            $results = array_filter($results, function ($t) use ($f) {
                [$col, $op, $val] = $f;
                if ($op === 'IN') return in_array($t[$col], (array)$val);
                return $t[$col] == $val;
            });
        }
        $total = count($results);
        $totalPages = max(1, ceil($total / $perPage));
        $tasksData = array_slice(array_values($results), ($page - 1) * $perPage, $perPage);
    } else {
        // Sin búsqueda, usar paginación ORM
        $orm = VersaModel::getGlobalORM();
        $query = $orm->table('tasks');
        foreach ($filters as $f) {
            [$col, $op, $val] = $f;
            $query = $op === 'IN' ? $query->whereIn($col, $val) : $query->where($col, $op, $val);
        }
        $query = $query->orderBy($order, $dir)->limit($perPage)->offset(($page - 1) * $perPage);
        $tasksData = $query->getAll();
        $total = $orm->table('tasks');
        foreach ($filters as $f) {
            [$col, $op, $val] = $f;
            $total = $op === 'IN' ? $total->whereIn($col, $val) : $total->where($col, $op, $val);
        }
        $total = $total->count();
        $totalPages = max(1, ceil($total / $perPage));
    }
    render_view('list', compact('tasksData', 'allProjects', 'allLabels', 'search', 'status', 'labelId', 'projectId', 'order', 'dir', 'page', 'perPage', 'total', 'totalPages') + ['tasks' => $tasksData]);
    return;
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
    $sql = "SELECT * FROM {$taskModel->getTable()} WHERE (LOWER(title) LIKE ? OR LOWER(description) LIKE ?) ORDER BY {$order} {$dir} LIMIT ? OFFSET ?";
    $tasks = VersaModel::getGlobalORM()->exec($sql, [
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
    $sql = "SELECT * FROM {$taskModel->getTable()} WHERE (LOWER(title) LIKE ? OR LOWER(description) LIKE ?) AND completed = ? ORDER BY {$order} {$dir} LIMIT ? OFFSET ?";
    $tasks = VersaModel::getGlobalORM()->exec($sql, [
        "%$searchLower%",
        "%$searchLower%",
        $completedValue,
        $perPage,
        ($page - 1) * $perPage
    ]);
} else {
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
