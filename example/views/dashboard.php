<?php $title = 'Dashboard - VersaORM Trello Demo'; ?>

<div class="mb-8">
    <h1 class="text-3xl font-bold text-gray-900 mb-2">Dashboard</h1>
    <p class="text-gray-600">Bienvenido a la demostración de VersaORM con una aplicación tipo Trello</p>
</div>

<!-- Estadísticas -->
<div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
    <div class="bg-white overflow-hidden shadow rounded-lg">
        <div class="p-5">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <i class="fas fa-folder text-2xl text-blue-600"></i>
                </div>
                <div class="ml-5 w-0 flex-1">
                    <dl>
                        <dt class="text-sm font-medium text-gray-500 truncate">Proyectos</dt>
                        <dd class="text-3xl font-bold text-gray-900"><?= $totalProjects ?></dd>
                    </dl>
                </div>
            </div>
        </div>
        <div class="bg-gray-50 px-5 py-3">
            <div class="text-sm">
                <a href="?action=projects" class="font-medium text-blue-600 hover:text-blue-500">
                    Ver todos <span aria-hidden="true">&rarr;</span>
                </a>
            </div>
        </div>
    </div>

    <div class="bg-white overflow-hidden shadow rounded-lg">
        <div class="p-5">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <i class="fas fa-tasks text-2xl text-green-600"></i>
                </div>
                <div class="ml-5 w-0 flex-1">
                    <dl>
                        <dt class="text-sm font-medium text-gray-500 truncate">Tareas</dt>
                        <dd class="text-3xl font-bold text-gray-900"><?= $totalTasks ?></dd>
                    </dl>
                </div>
            </div>
        </div>
        <div class="bg-gray-50 px-5 py-3">
            <div class="text-sm">
                <a href="?action=tasks" class="font-medium text-green-600 hover:text-green-500">
                    Ver todas <span aria-hidden="true">&rarr;</span>
                </a>
            </div>
        </div>
    </div>

    <div class="bg-white overflow-hidden shadow rounded-lg">
        <div class="p-5">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <i class="fas fa-users text-2xl text-purple-600"></i>
                </div>
                <div class="ml-5 w-0 flex-1">
                    <dl>
                        <dt class="text-sm font-medium text-gray-500 truncate">Usuarios</dt>
                        <dd class="text-3xl font-bold text-gray-900"><?= $totalUsers ?></dd>
                    </dl>
                </div>
            </div>
        </div>
        <div class="bg-gray-50 px-5 py-3">
            <div class="text-sm">
                <a href="?action=users" class="font-medium text-purple-600 hover:text-purple-500">
                    Ver todos <span aria-hidden="true">&rarr;</span>
                </a>
            </div>
        </div>
    </div>

    <div class="bg-white overflow-hidden shadow rounded-lg">
        <div class="p-5">
            <div class="flex items-center">
                <div class="flex-shrink-0">
                    <i class="fas fa-tags text-2xl text-orange-600"></i>
                </div>
                <div class="ml-5 w-0 flex-1">
                    <dl>
                        <dt class="text-sm font-medium text-gray-500 truncate">Etiquetas</dt>
                        <dd class="text-3xl font-bold text-gray-900"><?= $totalLabels ?></dd>
                    </dl>
                </div>
            </div>
        </div>
        <div class="bg-gray-50 px-5 py-3">
            <div class="text-sm">
                <a href="?action=labels" class="font-medium text-orange-600 hover:text-orange-500">
                    Ver todas <span aria-hidden="true">&rarr;</span>
                </a>
            </div>
        </div>
    </div>
</div>

<!-- Acciones rápidas -->
<div class="bg-white shadow rounded-lg mb-8">
    <div class="px-6 py-4 border-b border-gray-200">
        <h2 class="text-lg font-semibold text-gray-900">Acciones Rápidas</h2>
    </div>
    <div class="p-6">
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
            <a href="?action=project_create" class="flex flex-col items-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                <i class="fas fa-plus-circle text-2xl text-blue-600 mb-2"></i>
                <span class="text-sm font-medium text-gray-900">Nuevo Proyecto</span>
            </a>

            <a href="?action=task_create" class="flex flex-col items-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                <i class="fas fa-plus text-2xl text-green-600 mb-2"></i>
                <span class="text-sm font-medium text-gray-900">Nueva Tarea</span>
            </a>

            <a href="?action=user_create" class="flex flex-col items-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                <i class="fas fa-user-plus text-2xl text-purple-600 mb-2"></i>
                <span class="text-sm font-medium text-gray-900">Nuevo Usuario</span>
            </a>

            <a href="?action=label_create" class="flex flex-col items-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                <i class="fas fa-tag text-2xl text-orange-600 mb-2"></i>
                <span class="text-sm font-medium text-gray-900">Nueva Etiqueta</span>
            </a>
        </div>
    </div>
</div>

<!-- Tareas recientes -->
<div class="bg-white shadow rounded-lg">
    <div class="px-6 py-4 border-b border-gray-200">
        <h2 class="text-lg font-semibold text-gray-900">Tareas Recientes</h2>
    </div>
    <div class="divide-y divide-gray-200">
        <?php if (empty($recentTasks)): ?>
            <div class="p-6 text-center text-gray-500">
                <i class="fas fa-tasks text-4xl text-gray-300 mb-4"></i>
                <p>No hay tareas aún</p>
                <a href="?action=task_create" class="mt-2 inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700">
                    Crear primera tarea
                </a>
            </div>
        <?php else: ?>
            <?php foreach ($recentTasks as $task): ?>
                <div class="p-6 hover:bg-gray-50">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center space-x-3">
                            <div class="flex-shrink-0">
                                <?php
                                $statusColors = [
                                    'todo' => 'bg-gray-100 text-gray-800',
                                    'in_progress' => 'bg-blue-100 text-blue-800',
                                    'done' => 'bg-green-100 text-green-800',
                                ];
                $statusColor = $statusColors[$task->status] ?? 'bg-gray-100 text-gray-800';
                ?>
                                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?= $statusColor ?>">
                                    <?= ucfirst(str_replace('_', ' ', $task->status)) ?>
                                </span>
                            </div>
                            <div>
                                <h3 class="text-sm font-medium text-gray-900"><?= htmlspecialchars($task->title) ?></h3>
                                <?php if ($task->description): ?>
                                    <p class="text-sm text-gray-500"><?= htmlspecialchars(substr($task->description, 0, 100)) ?><?= strlen($task->description) > 100 ? '...' : '' ?></p>
                                <?php endif; ?>
                            </div>
                        </div>
                        <div class="flex items-center space-x-2">
                            <?php
                            $priorityColors = [
                'low' => 'bg-green-100 text-green-800',
                'medium' => 'bg-yellow-100 text-yellow-800',
                'high' => 'bg-orange-100 text-orange-800',
                'urgent' => 'bg-red-100 text-red-800',
                            ];
                $priorityColor = $priorityColors[$task->priority] ?? 'bg-gray-100 text-gray-800';
                ?>
                            <span class="inline-flex items-center px-2 py-1 rounded text-xs font-medium <?= $priorityColor ?>">
                                <?= ucfirst($task->priority) ?>
                            </span>
                            <span class="text-sm text-gray-500"><?= date('d/m/Y', strtotime($task->created_at)) ?></span>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>
</div>
