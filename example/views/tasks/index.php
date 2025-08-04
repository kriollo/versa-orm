<?php

/**
 * Vista para listar todas las tareas.
 */
?>

<div class="max-w-7xl mx-auto">
    <!-- Header -->
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Tareas</h1>
            <p class="text-gray-600">Gestiona todas las tareas del sistema</p>
        </div>
        <a href="?action=task_create" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors">
            <i class="fas fa-plus mr-2"></i>
            Nueva Tarea
        </a>
    </div>

    <!-- Filtros -->
    <div class="bg-white shadow rounded-lg p-4 mb-6">
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">Estado</label>
                <select class="w-full border border-gray-300 rounded-md px-3 py-2">
                    <option value="">Todos los estados</option>
                    <option value="todo">Por Hacer</option>
                    <option value="in_progress">En Progreso</option>
                    <option value="done">Completadas</option>
                </select>
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">Prioridad</label>
                <select class="w-full border border-gray-300 rounded-md px-3 py-2">
                    <option value="">Todas las prioridades</option>
                    <option value="urgent">Urgente</option>
                    <option value="high">Alta</option>
                    <option value="medium">Media</option>
                    <option value="low">Baja</option>
                </select>
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">Proyecto</label>
                <select class="w-full border border-gray-300 rounded-md px-3 py-2">
                    <option value="">Todos los proyectos</option>
                    <?php foreach ($projects as $project): ?>
                        <option value="<?= $project['id'] ?>"><?= htmlspecialchars($project['name']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">Asignado a</label>
                <select class="w-full border border-gray-300 rounded-md px-3 py-2">
                    <option value="">Todos los usuarios</option>
                    <?php foreach ($users as $user): ?>
                        <option value="<?= $user['id'] ?>"><?= htmlspecialchars($user['name']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
        </div>
    </div>

    <!-- Estadísticas rápidas -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <?php
        $totalTasks = count($tasks);
$todoTasks = count(array_filter($tasks, fn ($t) => $t['status'] === 'todo'));
$inProgressTasks = count(array_filter($tasks, fn ($t) => $t['status'] === 'in_progress'));
$doneTasks = count(array_filter($tasks, fn ($t) => $t['status'] === 'done'));
?>

        <div class="bg-white p-4 rounded-lg shadow">
            <div class="flex items-center">
                <div class="p-2 bg-gray-100 rounded-lg mr-3">
                    <i class="fas fa-tasks text-gray-600"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold"><?= $totalTasks ?></p>
                    <p class="text-gray-600 text-sm">Total</p>
                </div>
            </div>
        </div>

        <div class="bg-white p-4 rounded-lg shadow">
            <div class="flex items-center">
                <div class="p-2 bg-gray-100 rounded-lg mr-3">
                    <i class="fas fa-clock text-gray-600"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold"><?= $todoTasks ?></p>
                    <p class="text-gray-600 text-sm">Por Hacer</p>
                </div>
            </div>
        </div>

        <div class="bg-white p-4 rounded-lg shadow">
            <div class="flex items-center">
                <div class="p-2 bg-blue-100 rounded-lg mr-3">
                    <i class="fas fa-spinner text-blue-600"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold"><?= $inProgressTasks ?></p>
                    <p class="text-gray-600 text-sm">En Progreso</p>
                </div>
            </div>
        </div>

        <div class="bg-white p-4 rounded-lg shadow">
            <div class="flex items-center">
                <div class="p-2 bg-green-100 rounded-lg mr-3">
                    <i class="fas fa-check text-green-600"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold"><?= $doneTasks ?></p>
                    <p class="text-gray-600 text-sm">Completadas</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Lista de tareas -->
    <?php if (!empty($tasks)): ?>
        <div class="bg-white shadow rounded-lg overflow-hidden">
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Tarea</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Proyecto</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Asignado</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Estado</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Prioridad</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Vencimiento</th>
                            <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Acciones</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        <?php foreach ($tasks as $task): ?>
                            <?php
                    // Buscar información del proyecto y usuario
                    $taskProject = array_filter($projects, fn ($p) => $p['id'] == $task['project_id']);
                            $taskProject = !empty($taskProject) ? array_values($taskProject)[0] : null;

                            $taskUser = null;
                            if ($task['user_id']) {
                                $taskUser = array_filter($users, fn ($u) => $u['id'] == $task['user_id']);
                                $taskUser = !empty($taskUser) ? array_values($taskUser)[0] : null;
                            }
                            ?>
                            <tr class="hover:bg-gray-50">
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <div>
                                        <div class="font-medium text-gray-900"><?= htmlspecialchars($task['title']) ?></div>
                                        <?php if ($task['description']): ?>
                                            <div class="text-sm text-gray-500"><?= htmlspecialchars(substr($task['description'], 0, 60)) ?><?= strlen($task['description']) > 60 ? '...' : '' ?></div>
                                        <?php endif; ?>
                                    </div>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <?php if ($taskProject): ?>
                                        <div class="flex items-center">
                                            <div class="w-3 h-3 rounded-full mr-2" style="background-color: <?= htmlspecialchars($taskProject['color']) ?>"></div>
                                            <span class="text-sm text-gray-900"><?= htmlspecialchars($taskProject['name']) ?></span>
                                        </div>
                                    <?php else: ?>
                                        <span class="text-gray-400">-</span>
                                    <?php endif; ?>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <?php if ($taskUser): ?>
                                        <div class="flex items-center">
                                            <div class="avatar-sm mr-2" style="background-color: <?= htmlspecialchars($taskUser['avatar_color']) ?>">
                                                <?= strtoupper(substr($taskUser['name'], 0, 2)) ?>
                                            </div>
                                            <span class="text-sm text-gray-900"><?= htmlspecialchars($taskUser['name']) ?></span>
                                        </div>
                                    <?php else: ?>
                                        <span class="text-gray-400">Sin asignar</span>
                                    <?php endif; ?>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <?php
                                    $statusClasses = [
                                        'todo' => 'bg-gray-100 text-gray-800',
                                        'in_progress' => 'bg-blue-100 text-blue-800',
                                        'done' => 'bg-green-100 text-green-800',
                                    ];
                            $statusNames = [
                                'todo' => 'Por Hacer',
                                'in_progress' => 'En Progreso',
                                'done' => 'Completada',
                            ];
                            ?>
                                    <span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full <?= $statusClasses[$task['status']] ?>">
                                        <?= $statusNames[$task['status']] ?>
                                    </span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <?php
                            $priorityClasses = [
                                'urgent' => 'bg-red-100 text-red-800',
                                'high' => 'bg-orange-100 text-orange-800',
                                'medium' => 'bg-yellow-100 text-yellow-800',
                                'low' => 'bg-green-100 text-green-800',
                            ];
                            $priorityNames = [
                                'urgent' => 'Urgente',
                                'high' => 'Alta',
                                'medium' => 'Media',
                                'low' => 'Baja',
                            ];
                            ?>
                                    <span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full <?= $priorityClasses[$task['priority']] ?>">
                                        <?= $priorityNames[$task['priority']] ?>
                                    </span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                    <?php if ($task['due_date']): ?>
                                        <?php
                                $dueDate = new DateTime($task['due_date']);
                                        $today = new DateTime();
                                        $diff = $today->diff($dueDate);
                                        $isOverdue = $today > $dueDate;
                                        ?>
                                        <span class="<?= $isOverdue ? 'text-red-600' : '' ?>">
                                            <?= $dueDate->format('d/m/Y') ?>
                                            <?php if ($isOverdue): ?>
                                                <i class="fas fa-exclamation-triangle ml-1"></i>
                                            <?php endif; ?>
                                        </span>
                                    <?php else: ?>
                                        <span class="text-gray-400">-</span>
                                    <?php endif; ?>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                    <div class="flex items-center justify-end space-x-2">
                                        <a href="?action=task_edit&id=<?= $task['id'] ?>" class="text-yellow-600 hover:text-yellow-900">
                                            <i class="fas fa-edit"></i>
                                        </a>
                                        <a href="?action=task_delete&id=<?= $task['id'] ?>"
                                            onclick="return confirm('¿Estás seguro de que quieres eliminar esta tarea?')"
                                            class="text-red-600 hover:text-red-900">
                                            <i class="fas fa-trash"></i>
                                        </a>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    <?php else: ?>
        <div class="bg-white shadow rounded-lg p-12 text-center">
            <i class="fas fa-tasks text-4xl text-gray-300 mb-4"></i>
            <h3 class="text-lg font-medium text-gray-900 mb-2">No hay tareas</h3>
            <p class="text-gray-500 mb-4">Comienza creando tu primera tarea</p>
            <a href="?action=task_create" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors">
                <i class="fas fa-plus mr-2"></i>
                Crear Tarea
            </a>
        </div>
    <?php endif; ?>
</div>

<style>
    .avatar-sm {
        width: 24px;
        height: 24px;
        border-radius: 50%;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        font-size: 10px;
        font-weight: 500;
        color: white;
    }
</style>
