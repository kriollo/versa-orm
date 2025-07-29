<?php
// index.php - Controlador principal
require_once __DIR__ . '/autoload.php';

use Example\Models\Task;

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
    $taskModel = new Task();
    $taskModel->create($data);
    header('Location: index.php');
    exit;
}

if ($action === 'delete' && isset($_GET['id'])) {
    $taskModel = new Task();
    $taskModel->delete($_GET['id']);
    header('Location: index.php');
    exit;
}

if ($action === 'edit' && isset($_GET['id'])) {
    $taskModel = new Task();
    $task = $taskModel->find($_GET['id']);
    include __DIR__ . '/views/edit.php';
    exit;
}

if ($action === 'update' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $id = $_POST['id'];
    $data = [
        'title' => $_POST['title'],
        'description' => $_POST['description'],
        'completed' => isset($_POST['completed']) ? true : false
    ];
    $taskModel = new Task();
    $taskModel->update($id, $data);
    header('Location: index.php');
    exit;
}

if ($action === 'api' && ($_GET['format'] ?? '') === 'json') {
    $search = $_GET['search'] ?? '';
    $taskModel = new Task();
    // Usar la clase Task explícitamente en el QueryBuilder
    $query = $taskModel->getORM()->table($taskModel->table, Task::class);
    if ($search) {
        $query = $query->where('title', 'LIKE', "%$search%")
            ->orWhere('description', 'LIKE', "%$search%");
    }
    $tasks = $query->findAll();
    $tasksArray = [];
    foreach ($tasks as $task) {
        if (is_object($task) && method_exists($task, 'getAttributes')) {
            $tasksArray[] = $task->getAttributes();
        } elseif (is_array($task)) {
            $tasksArray[] = $task;
        }
    }
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Content-Type: application/json');
    echo json_encode([
        'tasks' => $tasksArray
    ]);
    exit;
}

// Filtros y búsqueda avanzada
$search = $_GET['search'] ?? '';
$status = $_GET['status'] ?? '';
$order = $_GET['order'] ?? 'id';
$dir = $_GET['dir'] ?? 'desc';
$page = max(1, (int)($_GET['page'] ?? 1));
$perPage = isset($_GET['perPage']) ? max(1, (int)$_GET['perPage']) : 10;

$taskModel = new Task();
$query = $taskModel->getORM()->table($taskModel->table);
if ($search) {
    $query = $query->where('title', 'LIKE', "%$search%")
        ->orWhere('description', 'LIKE', "%$search%");
}
if ($status !== '') {
    $query = $query->where('completed', '=', $status === '1');
}
$query = $query->orderBy($order, $dir)
    ->limit($perPage)
    ->offset(($page - 1) * $perPage);
$tasks = $query->findAll();

// Estadísticas
$total = $taskModel->getORM()->table($taskModel->table)->count();
$completed = $taskModel->getORM()->table($taskModel->table)->where('completed', '=', true)->count();
$pending = $taskModel->getORM()->table($taskModel->table)->where('completed', '=', false)->count();

// Listar tareas
include __DIR__ . '/views/list.php';
