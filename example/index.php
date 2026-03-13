<?php

declare(strict_types=1);

/**
 * VersaORM Trello Demo
 * Aplicación de demostración tipo Trello para mostrar las capacidades de VersaORM.
 */

require_once __DIR__ . '/app/bootstrap.php';

// Autoload de controladores
spl_autoload_register(function ($class) {
    if (str_starts_with($class, 'Controllers\\')) {
        $className = str_replace('Controllers\\', '', $class);
        $file = __DIR__ . '/controllers/' . $className . '.php';
        if (file_exists($file)) {
            require_once $file;
        }
    }
});

// Obtener la acción y parámetros de la URL
$action = $_GET['action'] ?? 'dashboard';
$id = isset($_GET['id']) ? (int) $_GET['id'] : null;
app()->orm();

try {
    if ($action === 'dashboard') {
        Controllers\DashboardController::handle();
    } elseif (in_array(
        $action,
        [
            'projects',
            'project_show',
            'project_create',
            'project_edit',
            'project_add_member',
            'project_remove_member',
            'project_delete',
        ],
        true,
    )) {
        Controllers\ProjectController::handle($action, $id);
    } elseif (in_array(
        $action,
        [
            'tasks',
            'task_create',
            'task_edit',
            'task_delete',
            'task_change_status',
        ],
        true,
    )) {
        Controllers\TaskController::handle($action, $id);
    } elseif (in_array(
        $action,
        [
            'users',
            'user_create',
            'user_edit',
            'user_delete',
        ],
        true,
    )) {
        Controllers\UserController::handle($action, $id);
    } elseif (in_array(
        $action,
        [
            'labels',
            'label_tasks',
            'label_create',
            'label_edit',
            'label_delete',
        ],
        true,
    )) {
        Controllers\LabelController::handle($action, $id);
    } else {
        flash('error', 'Acción no encontrada');
        redirect('?action=dashboard');
    }
} catch (Exception $e) {
    flash('error', 'Error del sistema: ' . $e->getMessage());
    render('error', ['message' => $e->getMessage()]);
}
