<?php

use App\Models\Label;
use App\Models\Project;
use App\Models\Task;
use App\Models\User;

$title = 'Dashboard - VersaORM Trello Demo';

$pendingTasks ??= 0; ?>

<div class="mb-8">
    <h1 class="text-3xl font-bold text-gray-900 dark:text-white mb-2">Dashboard</h1>
    <p class="text-gray-600 dark:text-gray-400">Bienvenido a la demostración de VersaORM con una aplicación tipo Trello</p>
</div>

<!-- Estadísticas -->
<div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
    <div class="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
        <div class="p-5">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <i class="fas fa-folder text-2xl text-blue-600"></i>
                </div>
                <div class="ml-5 w-0 flex-1">
                    <dl>
                        <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Proyectos</dt>
                        <dd class="text-3xl font-bold text-gray-900 dark:text-white"><?php echo $totalProjects; ?></dd>
                    </dl>
                </div>
            </div>
        </div>
        <div class="bg-gray-50 dark:bg-gray-700 px-5 py-3">
            <div class="text-sm">
                <a href="?action=projects" class="font-medium text-blue-600 hover:text-blue-500 dark:text-blue-400 dark:hover:text-blue-300">
                    Ver todos <span aria-hidden="true">&rarr;</span>
                </a>
            </div>
        </div>
    </div>

    <div class="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
        <div class="p-5">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <i class="fas fa-tasks text-2xl text-green-600"></i>
                </div>
                <div class="ml-5 w-0 flex-1">
                    <dl>
                        <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Tareas Totales</dt>
                        <dd class="text-3xl font-bold text-gray-900 dark:text-white"><?php echo $totalTasks; ?></dd>
                    </dl>
                </div>
            </div>
        </div>
        <div class="bg-gray-50 dark:bg-gray-700 px-5 py-3">
            <div class="text-sm">
                <a href="?action=tasks" class="font-medium text-green-600 hover:text-green-500 dark:text-green-400 dark:hover:text-green-300">
                    Ver todas <span aria-hidden="true">&rarr;</span>
                </a>
            </div>
        </div>
    </div>

    <div class="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
        <div class="p-5">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <i class="fas fa-users text-2xl text-purple-600"></i>
                </div>
                <div class="ml-5 w-0 flex-1">
                    <dl>
                        <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Usuarios</dt>
                        <dd class="text-3xl font-bold text-gray-900 dark:text-white"><?php echo $totalUsers; ?></dd>
                    </dl>
                </div>
            </div>
        </div>
        <div class="bg-gray-50 dark:bg-gray-700 px-5 py-3">
            <div class="text-sm">
                <a href="?action=users" class="font-medium text-purple-600 hover:text-purple-500 dark:text-purple-400 dark:hover:text-purple-300">
                    Ver todos <span aria-hidden="true">&rarr;</span>
                </a>
            </div>
        </div>
    </div>

    <div class="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
        <div class="p-5">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <i class="fas fa-tags text-2xl text-orange-600"></i>
                </div>
                <div class="ml-5 w-0 flex-1">
                    <dl>
                        <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Etiquetas</dt>
                        <dd class="text-3xl font-bold text-gray-900 dark:text-white"><?php echo $totalLabels; ?></dd>
                    </dl>
                </div>
            </div>
        </div>
        <div class="bg-gray-50 dark:bg-gray-700 px-5 py-3">
            <div class="text-sm">
                <a href="?action=labels" class="font-medium text-orange-600 hover:text-orange-500 dark:text-orange-400 dark:hover:text-orange-300">
                    Ver todas <span aria-hidden="true">&rarr;</span>
                </a>
            </div>
        </div>
    </div>

    <div class="bg-white dark:bg-gray-800 overflow-hidden shadow rounded-lg">
        <div class="p-5">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <i class="fas fa-clock text-2xl text-yellow-600"></i>
                </div>
                <div class="ml-5 w-0 flex-1">
                    <dl>
                        <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">Tareas Pendientes</dt>
                        <dd class="text-3xl font-bold text-gray-900 dark:text-white"><?php echo $pendingTasks; ?></dd>
                    </dl>
                </div>
            </div>
        </div>
        <div class="bg-gray-50 dark:bg-gray-700 px-5 py-3">
            <div class="text-sm">
                <a href="?action=tasks&status=todo" class="font-medium text-yellow-600 hover:text-yellow-500 dark:text-yellow-400 dark:hover:text-yellow-300">
                    Ver pendientes <span aria-hidden="true">&rarr;</span>
                </a>
            </div>
        </div>
    </div>
</div>

<!-- Acciones rápidas -->
<div class="bg-white dark:bg-gray-800 shadow rounded-lg mb-8">
    <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
        <h2 class="text-lg font-semibold text-gray-900 dark:text-white">Acciones Rápidas</h2>
    </div>
    <div class="p-6">
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <a href="?action=project_create" class="flex flex-col items-center p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                <i class="fas fa-plus-circle text-2xl text-blue-600 mb-2"></i>
                <span class="text-sm font-medium text-gray-900 dark:text-white">Nuevo Proyecto</span>
            </a>

            <a href="?action=task_create" class="flex flex-col items-center p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                <i class="fas fa-plus text-2xl text-green-600 mb-2"></i>
                <span class="text-sm font-medium text-gray-900 dark:text-white">Nueva Tarea</span>
            </a>

            <a href="?action=user_create" class="flex flex-col items-center p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                <i class="fas fa-user-plus text-2xl text-purple-600 mb-2"></i>
                <span class="text-sm font-medium text-gray-900 dark:text-white">Nuevo Usuario</span>
            </a>

            <a href="?action=label_create" class="flex flex-col items-center p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                <i class="fas fa-tag text-2xl text-orange-600 mb-2"></i>
                <span class="text-sm font-medium text-gray-900 dark:text-white">Nueva Etiqueta</span>
            </a>
        </div>
    </div>
</div>

<!-- Tareas pendientes -->
<div class="bg-white dark:bg-gray-800 shadow rounded-lg">
    <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
        <h2 class="text-lg font-semibold text-gray-900 dark:text-white">Tareas Pendientes</h2>
    </div>
    <div class="divide-y divide-gray-200 dark:divide-gray-700">
        <?php if (empty($recentTasks)) { ?>
            <div class="p-6 text-center text-gray-500 dark:text-gray-400">
                <i class="fas fa-tasks text-4xl text-gray-300 dark:text-gray-600 mb-4"></i>
                <p>No hay tareas aún</p>
                <a href="?action=task_create" class="mt-2 inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 dark:bg-blue-600 dark:hover:bg-blue-500">
                    Crear primera tarea
                </a>
            </div>
        <?php } else { ?>
            <?php foreach ($recentTasks as $task) { ?>
                <div class="p-6 hover:bg-gray-50 dark:hover:bg-gray-700">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center space-x-3">
                            <div class="flex-shrink-0">
                                <?php
                                $statusColors = [
                                    'todo' => 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200',
                                    'in_progress' => 'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300',
                                    'done' => 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
                                ];
                $statusColor = $statusColors[$task['status']] ?? 'bg-gray-100 text-gray-800';
                ?>
                                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?php echo
                    $statusColor
                ; ?>">
                                    <?php echo ucfirst(str_replace('_', ' ', $task['status'])); ?>
                                </span>
                            </div>
                            <div>
                                <h3 class="text-sm font-medium text-gray-900 dark:text-white"><?php echo
                    htmlspecialchars($task['title'])
                ; ?></h3>
                                <?php if ($task['description']) { ?>
                                    <p class="text-sm text-gray-500 dark:text-gray-400"><?php echo
                        htmlspecialchars(substr($task['description'], 0, 100))
                                    ; ?><?php echo strlen($task['description']) > 100 ? '...' : ''; ?></p>
                                <?php } ?>
                            </div>
                        </div>
                        <div class="flex items-center space-x-2">
                            <?php
                            $priorityColors = [
                                'low' => 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
                                'medium' => 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300',
                                'high' => 'bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300',
                                'urgent' => 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300',
                            ];
                $priorityColor = $priorityColors[$task['priority']] ?? 'bg-gray-100 text-gray-800';
                ?>
                            <span class="inline-flex items-center px-2 py-1 rounded text-xs font-medium <?php echo
                    $priorityColor
                ; ?>">
                                <?php echo ucfirst($task['priority']); ?>
                            </span>
                            <span class="text-sm text-gray-500 dark:text-gray-400"><?php echo
                    safe_date('d/m/Y', $task['created_at'])
                ; ?></span>
                        </div>
                    </div>
                </div>
            <?php } ?>
        <?php } ?>
    </div>
</div>

<!-- Sistema de tipado fuerte activo -->
<div class="bg-gradient-to-r from-green-50 to-blue-50 dark:from-gray-800 dark:to-gray-700 shadow rounded-lg border-l-4 border-green-400 dark:border-green-600 mt-3">
    <div class="px-6 py-4">
        <div class="flex items-center">
            <div class="flex-shrink-0">
                <i class="fas fa-shield-alt text-2xl text-green-600"></i>
            </div>
            <div class="ml-4">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white">Sistema de Tipado Fuerte Activo</h3>
                <p class="mt-1 text-sm text-gray-600 dark:text-gray-300">
                    VersaORM está validando automáticamente los tipos de datos en todos los modelos.
                    <?php
                    $typedModels = [
                        'User' => User::definePropertyTypes(),
                        'Project' => Project::definePropertyTypes(),
                        'Task' => Task::definePropertyTypes(),
                        'Label' => Label::definePropertyTypes(),
                    ];
$totalProperties = array_sum(array_map('count', $typedModels));
?>
                    <strong><?php echo count($typedModels); ?> modelos</strong> con <strong><?php echo
    $totalProperties
; ?> propiedades tipadas</strong>.
                </p>
                <div class="mt-2 flex flex-wrap gap-2">
                    <?php foreach ($typedModels as $modelName => $properties) { ?>
                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                            <?php echo $modelName; ?>: <?php echo count($properties); ?> props
                        </span>
                    <?php } ?>
                </div>
            </div>
        </div>
    </div>
</div>
