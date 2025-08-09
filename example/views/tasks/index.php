<?php

/**
 * Vista para listar todas las tareas.
 */
?>

<div class="max-w-7xl mx-auto">
    <!-- Header -->
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900 dark:text-white transition-colors">Tareas</h1>
            <p class="text-gray-600 dark:text-gray-300 transition-colors">Gestiona todas las tareas del sistema</p>
        </div>
        <a href="?action=task_create" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors">
            <i class="fas fa-plus mr-2"></i>
            Nueva Tarea
        </a>
    </div>

    <!-- Filtros -->
    <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-4 mb-6 transition-colors">
        <form method="GET" action="?action=tasks" id="filtersForm">
            <input type="hidden" name="action" value="tasks">
            <div class="grid grid-cols-1 md:grid-cols-5 gap-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 transition-colors">Estado</label>
                    <select name="status" class="w-full border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 rounded-md px-3 py-2 transition-colors">
                        <option value="">Todos los estados</option>
                        <option value="todo" <?= ($filters['status'] ?? '') === 'todo' ? 'selected' : '' ?>>Por Hacer</option>
                        <option value="in_progress" <?= ($filters['status'] ?? '') === 'in_progress' ? 'selected' : '' ?>>En Progreso</option>
                        <option value="done" <?= ($filters['status'] ?? '') === 'done' ? 'selected' : '' ?>>Completadas</option>
                    </select>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 transition-colors">Prioridad</label>
                    <select name="priority" class="w-full border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 rounded-md px-3 py-2 transition-colors">
                        <option value="">Todas las prioridades</option>
                        <option value="urgent" <?= ($filters['priority'] ?? '') === 'urgent' ? 'selected' : '' ?>>Urgente</option>
                        <option value="high" <?= ($filters['priority'] ?? '') === 'high' ? 'selected' : '' ?>>Alta</option>
                        <option value="medium" <?= ($filters['priority'] ?? '') === 'medium' ? 'selected' : '' ?>>Media</option>
                        <option value="low" <?= ($filters['priority'] ?? '') === 'low' ? 'selected' : '' ?>>Baja</option>
                    </select>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 transition-colors">Proyecto</label>
                    <select name="project_id" class="w-full border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 rounded-md px-3 py-2 transition-colors">
                        <option value="">Todos los proyectos</option>
                        <?php foreach ($projects as $project): ?>
                            <option value="<?= $project['id'] ?>" <?= ($filters['project_id'] ?? '') == $project['id'] ? 'selected' : '' ?>>
                                <?= htmlspecialchars($project['name']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 transition-colors">Asignado a</label>
                    <select name="user_id" class="w-full border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 rounded-md px-3 py-2 transition-colors">
                        <option value="">Todos los usuarios</option>
                        <?php foreach ($users as $user): ?>
                            <option value="<?= $user['id'] ?>" <?= ($filters['user_id'] ?? '') == $user['id'] ? 'selected' : '' ?>>
                                <?= htmlspecialchars($user['name']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="flex items-end space-x-2">
                    <button type="submit" class="flex-1 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md transition-colors">
                        <i class="fas fa-search mr-2"></i>Filtrar
                    </button>
                    <a href="?action=tasks" class="bg-gray-500 hover:bg-gray-600 text-white px-4 py-2 rounded-md transition-colors" title="Limpiar filtros">
                        <i class="fas fa-times"></i>
                    </a>
                </div>
            </div>
        </form>
    </div>

    <!-- Controles de paginación y resultados -->
    <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-4 mb-6 transition-colors">
        <div class="flex flex-col md:flex-row md:items-center md:justify-between space-y-4 md:space-y-0">
            <div class="flex items-center space-x-4">
                <span class="text-sm text-gray-700 dark:text-gray-300 transition-colors">
                    Mostrando <?= $pagination['showing_from'] ?? 0 ?> - <?= $pagination['showing_to'] ?? 0 ?>
                    de <?= $pagination['total'] ?? 0 ?> tareas
                </span>
                <form method="GET" action="?action=tasks" class="flex items-center space-x-2">
                    <input type="hidden" name="action" value="tasks">
                    <?php if (!empty($filters['status'])): ?>
                        <input type="hidden" name="status" value="<?= htmlspecialchars($filters['status']) ?>">
                    <?php endif; ?>
                    <?php if (!empty($filters['priority'])): ?>
                        <input type="hidden" name="priority" value="<?= htmlspecialchars($filters['priority']) ?>">
                    <?php endif; ?>
                    <?php if (!empty($filters['project_id'])): ?>
                        <input type="hidden" name="project_id" value="<?= htmlspecialchars($filters['project_id']) ?>">
                    <?php endif; ?>
                    <?php if (!empty($filters['user_id'])): ?>
                        <input type="hidden" name="user_id" value="<?= htmlspecialchars($filters['user_id']) ?>">
                    <?php endif; ?>
                    <label class="text-sm text-gray-700 dark:text-gray-300 transition-colors">Por página:</label>
                    <select name="per_page" onchange="this.form.submit()" class="border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 rounded px-2 py-1 text-sm transition-colors">
                        <option value="1" <?= ($pagination['per_page'] ?? 10) == 1 ? 'selected' : '' ?>>1</option>
                        <option value="5" <?= ($pagination['per_page'] ?? 10) == 5 ? 'selected' : '' ?>>5</option>
                        <option value="10" <?= ($pagination['per_page'] ?? 10) == 10 ? 'selected' : '' ?>>10</option>
                        <option value="20" <?= ($pagination['per_page'] ?? 10) == 20 ? 'selected' : '' ?>>20</option>
                        <option value="50" <?= ($pagination['per_page'] ?? 10) == 50 ? 'selected' : '' ?>>50</option>
                        <option value="100" <?= ($pagination['per_page'] ?? 10) == 100 ? 'selected' : '' ?>>100</option>
                    </select>
                </form>
            </div>

            <!-- Paginación -->
            <?php if (($pagination['total_pages'] ?? 1) > 1): ?>
                <div class="flex items-center space-x-2">
                    <?php if ($pagination['has_prev'] ?? false): ?>
                        <a href="?action=tasks&page=<?= $pagination['prev_page'] ?>&per_page=<?= $pagination['per_page'] ?><?= !empty($filters['status']) ? '&status=' . urlencode($filters['status']) : '' ?><?= !empty($filters['priority']) ? '&priority=' . urlencode($filters['priority']) : '' ?><?= !empty($filters['project_id']) ? '&project_id=' . urlencode($filters['project_id']) : '' ?><?= !empty($filters['user_id']) ? '&user_id=' . urlencode($filters['user_id']) : '' ?>"
                            class="px-3 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-200 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">
                            <i class="fas fa-chevron-left"></i>
                        </a>
                    <?php endif; ?>

                    <span class="px-3 py-2 bg-blue-600 text-white rounded">
                        <?= $pagination['current_page'] ?? 1 ?> / <?= $pagination['total_pages'] ?? 1 ?>
                    </span>

                    <?php if ($pagination['has_next'] ?? false): ?>
                        <a href="?action=tasks&page=<?= $pagination['next_page'] ?>&per_page=<?= $pagination['per_page'] ?><?= !empty($filters['status']) ? '&status=' . urlencode($filters['status']) : '' ?><?= !empty($filters['priority']) ? '&priority=' . urlencode($filters['priority']) : '' ?><?= !empty($filters['project_id']) ? '&project_id=' . urlencode($filters['project_id']) : '' ?><?= !empty($filters['user_id']) ? '&user_id=' . urlencode($filters['user_id']) : '' ?>"
                            class="px-3 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-200 rounded hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">
                            <i class="fas fa-chevron-right"></i>
                        </a>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Estadísticas rápidas -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <?php
        // Calcular estadísticas basadas en el total filtrado (antes de paginación)
        $totalFiltered = $pagination['total'] ?? 0;
$todoTasks             = count(array_filter($tasks, fn ($t) => $t['status'] === 'todo'));
$inProgressTasks       = count(array_filter($tasks, fn ($t) => $t['status'] === 'in_progress'));
$doneTasks             = count(array_filter($tasks, fn ($t) => $t['status'] === 'done'));
?>

        <div class="bg-white dark:bg-gray-800 p-4 rounded-lg shadow transition-colors">
            <div class="flex items-center">
                <div class="p-2 bg-gray-100 dark:bg-gray-700 rounded-lg mr-3 transition-colors">
                    <i class="fas fa-tasks text-gray-600 dark:text-gray-300"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold text-gray-900 dark:text-white transition-colors"><?= $totalFiltered ?></p>
                    <p class="text-gray-600 dark:text-gray-300 text-sm transition-colors">Total<?= !empty(array_filter($filters)) ? ' (Filtrado)' : '' ?></p>
                </div>
            </div>
        </div>


        <div class="bg-white dark:bg-gray-800 p-4 rounded-lg shadow transition-colors">
            <div class="flex items-center">
                <div class="p-2 bg-gray-100 dark:bg-gray-700 rounded-lg mr-3 transition-colors">
                    <i class="fas fa-clock text-gray-600 dark:text-gray-300"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold text-gray-900 dark:text-white transition-colors"><?= $todoTasks ?></p>
                    <p class="text-gray-600 dark:text-gray-300 text-sm transition-colors">Por Hacer</p>
                </div>
            </div>
        </div>

        <div class="bg-white dark:bg-gray-800 p-4 rounded-lg shadow transition-colors">
            <div class="flex items-center">
                <div class="p-2 bg-blue-100 dark:bg-blue-900/40 rounded-lg mr-3 transition-colors">
                    <i class="fas fa-spinner text-blue-600 dark:text-blue-400"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold text-gray-900 dark:text-white transition-colors"><?= $inProgressTasks ?></p>
                    <p class="text-gray-600 dark:text-gray-300 text-sm transition-colors">En Progreso</p>
                </div>
            </div>
        </div>

        <div class="bg-white dark:bg-gray-800 p-4 rounded-lg shadow transition-colors">
            <div class="flex items-center">
                <div class="p-2 bg-green-100 dark:bg-green-900/40 rounded-lg mr-3 transition-colors">
                    <i class="fas fa-check text-green-600 dark:text-green-400"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold text-gray-900 dark:text-white transition-colors"><?= $doneTasks ?></p>
                    <p class="text-gray-600 dark:text-gray-300 text-sm transition-colors">Completadas</p>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Lista de tareas -->
<?php if (!empty($tasks)): ?>
    <div class="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden transition-colors">
        <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead class="bg-gray-50 dark:bg-gray-700">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Tarea</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Proyecto</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Asignado</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Estado</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Prioridad</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Vencimiento</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Notas</th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">Acciones</th>
                    </tr>
                </thead>
                <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700 transition-colors">
                    <?php foreach ($tasks as $task): ?>
                        <tr class="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                            <td class="px-6 py-4 whitespace-nowrap">
                                <div>
                                    <div class="font-medium text-gray-900 dark:text-white transition-colors"><?= htmlspecialchars($task['title']) ?></div>
                                    <?php if ($task['description']): ?>
                                        <div class="text-sm text-gray-500 dark:text-gray-300 transition-colors"><?= htmlspecialchars(substr($task['description'], 0, 60)) ?><?= strlen($task['description']) > 60 ? '...' : '' ?></div>
                                    <?php endif; ?>
                                </div>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap">
                                <?php if ($task['project_name']): ?>
                                    <div class="flex items-center">
                                        <div class="w-3 h-3 rounded-full mr-2" style="background-color: <?= htmlspecialchars($task['project_color'] ?? '#6B7280') ?>"></div>
                                        <span class="text-sm text-gray-900 dark:text-white transition-colors"><?= htmlspecialchars($task['project_name']) ?></span>
                                    </div>
                                <?php else: ?>
                                    <span class="text-gray-400">-</span>
                                <?php endif; ?>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap">
                                <?php if ($task['user_name']): ?>
                                    <div class="flex items-center">
                                        <div class="avatar-sm mr-2" style="background-color: <?= htmlspecialchars($task['avatar_color'] ?? '#6B7280') ?>">
                                            <?= strtoupper(substr($task['user_name'], 0, 2)) ?>
                                        </div>
                                        <span class="text-sm text-gray-900 dark:text-white transition-colors"><?= htmlspecialchars($task['user_name']) ?></span>
                                    </div>
                                <?php else: ?>
                                    <span class="text-gray-400">Sin asignar</span>
                                <?php endif; ?>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap">
                                <?php
                        $statusClasses = [
                            'todo'        => 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200',
                            'in_progress' => 'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300',
                            'done'        => 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
                        ];
                        $statusNames = [
                            'todo'        => 'Por Hacer',
                            'in_progress' => 'En Progreso',
                            'done'        => 'Completada',
                        ];
                        ?>
                                <span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full <?= $statusClasses[$task['status']] ?>">
                                    <?= $statusNames[$task['status']] ?>
                                </span>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap">
                                <?php
                        $priorityClasses = [
                            'urgent' => 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300',
                            'high'   => 'bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300',
                            'medium' => 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300',
                            'low'    => 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
                        ];
                        $priorityNames = [
                            'urgent' => 'Urgente',
                            'high'   => 'Alta',
                            'medium' => 'Media',
                            'low'    => 'Baja',
                        ];
                        ?>
                                <span class="inline-flex px-2 py-1 text-xs font-semibold rounded-full <?= $priorityClasses[$task['priority']] ?>">
                                    <?= $priorityNames[$task['priority']] ?>
                                </span>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white transition-colors">
                                <?php if ($task['due_date']): ?>
                                    <?php
                            $dueDate           = new DateTime($task['due_date']);
                                    $today     = new DateTime();
                                    $diff      = $today->diff($dueDate);
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
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white transition-colors">
                                <button class="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300 open-notes-modal <?= ($task['notes_count'] ?? 0) > 0 ? 'has-notes' : '' ?>"
                                        data-task-id="<?= $task['id'] ?>" 
                                        data-task-title="<?= htmlspecialchars($task['title']) ?>">
                                    <i class="fas fa-sticky-note"></i>
                                    <?php if (($task['notes_count'] ?? 0) > 0): ?>
                                        <span class="note-count-badge"><?= $task['notes_count'] ?></span>
                                    <?php endif; ?>
                                </button>
                            </td>
                            <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                <div class="flex items-center justify-end space-x-2">
                                    <a href="?action=task_edit&id=<?= $task['id'] ?>" class="text-yellow-600 hover:text-yellow-900 dark:text-yellow-400 dark:hover:text-yellow-300 transition-colors">
                                        <i class="fas fa-edit"></i>
                                    </a>
                                    <a href="?action=task_delete&id=<?= $task['id'] ?>"
                                        onclick="return confirm('¿Estás seguro de que quieres eliminar esta tarea?')"
                                        class="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300 transition-colors">
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
    <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-12 text-center transition-colors">
        <i class="fas fa-tasks text-4xl text-gray-300 dark:text-gray-500 mb-4 transition-colors"></i>
        <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-2 transition-colors">No hay tareas</h3>
        <p class="text-gray-500 dark:text-gray-300 mb-4 transition-colors">Comienza creando tu primera tarea</p>
        <a href="?action=task_create" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors">
            <i class="fas fa-plus mr-2"></i>
            Crear Tarea
        </a>
    </div>
<?php endif; ?>

<!-- Controles de Paginación -->
<?php if (isset($pagination) && $pagination['total_pages'] > 1): ?>
    <div class="bg-white dark:bg-gray-800 px-4 py-3 flex items-center justify-between border-t border-gray-200 dark:border-gray-700 sm:px-6 mt-4 rounded-lg shadow transition-colors">
        <div class="flex-1 flex justify-between sm:hidden">
            <?php if ($pagination['current_page'] > 1): ?>
                <a href="?action=tasks&page=<?= $pagination['current_page'] - 1 ?>&per_page=<?= $pagination['per_page'] ?><?= $filterQueryString ?>"
                    class="relative inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-900 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    Anterior
                </a>
            <?php endif; ?>
            <?php if ($pagination['current_page'] < $pagination['total_pages']): ?>
                <a href="?action=tasks&page=<?= $pagination['current_page'] + 1 ?>&per_page=<?= $pagination['per_page'] ?><?= $filterQueryString ?>"
                    class="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-900 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    Siguiente
                </a>
            <?php endif; ?>
        </div>
        <div class="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
            <div>
                <p class="text-sm text-gray-700 dark:text-gray-300 transition-colors">
                    Mostrando
                    <span class="font-medium"><?= $pagination['start'] ?></span>
                    a
                    <span class="font-medium"><?= $pagination['end'] ?></span>
                    de
                    <span class="font-medium"><?= $pagination['total'] ?></span>
                    resultados
                </p>
            </div>
            <div class="flex items-center space-x-2">
                <!-- Selector de elementos por página -->
                <select onchange="changePerPage(this.value)" class="form-select border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 rounded-md text-sm transition-colors">
                    <option value="1" <?= $pagination['per_page'] == 1 ? 'selected' : '' ?>>1 por página</option>
                    <option value="5" <?= $pagination['per_page'] == 5 ? 'selected' : '' ?>>5 por página</option>
                    <option value="10" <?= $pagination['per_page'] == 10 ? 'selected' : '' ?>>10 por página</option>
                    <option value="20" <?= $pagination['per_page'] == 20 ? 'selected' : '' ?>>20 por página</option>
                    <option value="50" <?= $pagination['per_page'] == 50 ? 'selected' : '' ?>>50 por página</option>
                    <option value="100" <?= $pagination['per_page'] == 100 ? 'selected' : '' ?>>100 por página</option>
                </select>

                <!-- Navegación de páginas -->
                <nav class="relative z-0 inline-flex rounded-md shadow-sm -space-x-px" aria-label="Pagination">
                    <!-- Botón Anterior -->
                    <?php if ($pagination['current_page'] > 1): ?>
                        <a href="?action=tasks&page=<?= $pagination['current_page'] - 1 ?>&per_page=<?= $pagination['per_page'] ?><?= $filterQueryString ?>"
                            class="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 text-sm font-medium text-gray-500 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                            <span class="sr-only">Anterior</span>
                            <i class="fas fa-chevron-left"></i>
                        </a>
                    <?php else: ?>
                        <span class="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 dark:border-gray-600 bg-gray-100 dark:bg-gray-700 text-sm font-medium text-gray-300">
                            <i class="fas fa-chevron-left"></i>
                        </span>
                    <?php endif; ?>

                    <!-- Números de página -->
                    <?php
                    $start_page = max(1, $pagination['current_page'] - 2);
$end_page                       = min($pagination['total_pages'], $pagination['current_page'] + 2);

// Mostrar primera página si no está en el rango
if ($start_page > 1): ?>
                        <a href="?action=tasks&page=1&per_page=<?= $pagination['per_page'] ?><?= $filterQueryString ?>"
                            class="relative inline-flex items-center px-4 py-2 border border-gray-300 bg-white text-sm font-medium text-gray-700 hover:bg-gray-50">
                            1
                        </a>
                        <?php if ($start_page > 2): ?>
                            <span class="relative inline-flex items-center px-4 py-2 border border-gray-300 bg-white text-sm font-medium text-gray-700">
                                ...
                            </span>
                        <?php endif; ?>
                    <?php endif; ?>

                    <!-- Páginas en el rango actual -->
                    <?php for ($i = $start_page; $i <= $end_page; $i++): ?>
                        <?php if ($i == $pagination['current_page']): ?>
                            <span class="relative inline-flex items-center px-4 py-2 border border-gray-300 bg-blue-50 text-sm font-medium text-blue-600">
                                <?= $i ?>
                            </span>
                        <?php else: ?>
                            <a href="?action=tasks&page=<?= $i ?>&per_page=<?= $pagination['per_page'] ?><?= $filterQueryString ?>"
                                class="relative inline-flex items-center px-4 py-2 border border-gray-300 bg-white text-sm font-medium text-gray-700 hover:bg-gray-50">
                                <?= $i ?>
                            </a>
                        <?php endif; ?>
                    <?php endfor; ?>

                    <!-- Mostrar última página si no está en el rango -->
                    <?php if ($end_page < $pagination['total_pages']): ?>
                        <?php if ($end_page < $pagination['total_pages'] - 1): ?>
                            <span class="relative inline-flex items-center px-4 py-2 border border-gray-300 bg-white text-sm font-medium text-gray-700">
                                ...
                            </span>
                        <?php endif; ?>
                        <a href="?action=tasks&page=<?= $pagination['total_pages'] ?>&per_page=<?= $pagination['per_page'] ?><?= $filterQueryString ?>"
                            class="relative inline-flex items-center px-4 py-2 border border-gray-300 bg-white text-sm font-medium text-gray-700 hover:bg-gray-50">
                            <?= $pagination['total_pages'] ?>
                        </a>
                    <?php endif; ?>

                    <!-- Botón Siguiente -->
                    <?php if ($pagination['current_page'] < $pagination['total_pages']): ?>
                        <a href="?action=tasks&page=<?= $pagination['current_page'] + 1 ?>&per_page=<?= $pagination['per_page'] ?><?= $filterQueryString ?>"
                            class="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50">
                            <span class="sr-only">Siguiente</span>
                            <i class="fas fa-chevron-right"></i>
                        </a>
                    <?php else: ?>
                        <span class="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-gray-100 text-sm font-medium text-gray-300">
                            <i class="fas fa-chevron-right"></i>
                        </span>
                    <?php endif; ?>
                </nav>
            </div>
        </div>
    </div>
<?php endif; ?>
</div>

<!-- JavaScript para funcionalidad de paginación -->
<script>
    function changePerPage(perPage) {
        const url = new URL(window.location);
        url.searchParams.set('per_page', perPage);
        url.searchParams.set('page', 1); // Resetear a la primera página
        window.location.href = url.toString();
    }
</script>

<!-- Modal para Notas -->
<div id="notes-modal" class="fixed z-10 inset-0 overflow-y-auto hidden" aria-labelledby="modal-title" role="dialog" aria-modal="true">
    <div class="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
        <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" aria-hidden="true"></div>
        <span class="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>
        <div class="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
            <div class="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                <div class="sm:flex sm:items-start">
                    <div class="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-blue-100 sm:mx-0 sm:h-10 sm:w-10">
                        <i class="fas fa-sticky-note text-blue-600"></i>
                    </div>
                    <div class="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left">
                        <h3 class="text-lg leading-6 font-medium text-gray-900" id="modal-title">Notas para la Tarea</h3>
                        <p id="modal-task-title" class="text-sm text-gray-500"></p>
                        <div class="mt-4" id="notes-container">
                            <!-- Las notas se cargarán aquí -->
                        </div>
                        <div class="mt-4">
                            <form id="add-note-form">
                                <input type="hidden" name="task_id" id="note-task-id">
                                <textarea name="content" class="w-full border border-gray-300 rounded-md px-3 py-2" placeholder="Escribe una nueva nota..."></textarea>
                                <button type="submit" class="mt-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors">Agregar Nota</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
            <div class="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                <button type="button" class="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm" id="close-notes-modal">
                    Cerrar
                </button>
            </div>
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function () {
    const modal = document.getElementById('notes-modal');
    const closeButton = document.getElementById('close-notes-modal');
    const notesContainer = document.getElementById('notes-container');
    const modalTaskTitle = document.getElementById('modal-task-title');
    const addNoteForm = document.getElementById('add-note-form');
    const noteTaskIdInput = document.getElementById('note-task-id');

    document.querySelectorAll('.open-notes-modal').forEach(button => {
        button.addEventListener('click', function () {
            const taskId = this.dataset.taskId;
            const taskTitle = this.dataset.taskTitle;
            
            modalTaskTitle.textContent = taskTitle;
            noteTaskIdInput.value = taskId; // <-- Aquí está la corrección
            
            // Cargar notas
            loadNotes(taskId);

            modal.classList.remove('hidden');
        });
    });

    closeButton.addEventListener('click', function () {
        modal.classList.add('hidden');
        window.location.reload(); // <-- Recargar la página
    });

    function loadNotes(taskId) {
        fetch('notes_ajax.php?action=get_notes&task_id=' + taskId)
            .then(response => response.json())
            .then(data => {
                notesContainer.innerHTML = '';
                if (data.success && data.notes.length > 0) {
                    data.notes.forEach(note => {
                        const noteElement = document.createElement('div');
                        noteElement.classList.add('note-item', 'mb-2', 'p-2', 'bg-gray-100', 'rounded');
                        noteElement.innerHTML = `
                            <div class="flex justify-between items-start">
                                <p class="text-sm">${note.content}</p>
                                <div class="flex-shrink-0 ml-2">
                                    <button class="text-yellow-600 hover:text-yellow-900 edit-note" data-note-id="${note.id}" data-note-content="${note.content}"><i class="fas fa-edit"></i></button>
                                    <button class="text-red-600 hover:text-red-900 delete-note" data-note-id="${note.id}"><i class="fas fa-trash"></i></button>
                                </div>
                            </div>
                            <p class="text-xs text-gray-500">- ${note.user_name} en ${note.created_at}</p>
                        `;
                        notesContainer.appendChild(noteElement);
                    });
                } else {
                    notesContainer.innerHTML = '<p class="text-sm text-gray-500">No hay notas para esta tarea.</p>';
                }
            });
    }

    addNoteForm.addEventListener('submit', function (e) {
        e.preventDefault();
        const formData = new FormData(this);
        formData.append('action', 'add_note');

        fetch('notes_ajax.php', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                loadNotes(noteTaskIdInput.value);
                this.reset();
            } else {
                alert(data.message);
            }
        });
    });

    notesContainer.addEventListener('click', function (e) {
        if (e.target.closest('.edit-note')) {
            const button = e.target.closest('.edit-note');
            const noteId = button.dataset.noteId;
            const noteContent = button.dataset.noteContent;
            
            const editForm = `
                <form class="edit-note-form">
                    <input type="hidden" name="note_id" value="${noteId}">
                    <textarea name="content" class="w-full border border-gray-300 rounded-md px-3 py-2">${noteContent}</textarea>
                    <button type="submit" class="mt-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors">Guardar</button>
                    <button type="button" class="mt-2 bg-gray-500 hover:bg-gray-600 text-white px-4 py-2 rounded-lg transition-colors cancel-edit">Cancelar</button>
                </form>
            `;
            
            const noteItem = button.closest('.note-item');
            noteItem.innerHTML = editForm;
        }

        if (e.target.closest('.cancel-edit')) {
            loadNotes(noteTaskIdInput.value);
        }

        if (e.target.closest('.delete-note')) {
            const button = e.target.closest('.delete-note');
            const noteId = button.dataset.noteId;
            
            if (confirm('¿Estás seguro de que quieres eliminar esta nota?')) {
                fetch('notes_ajax.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: `action=delete_note&note_id=${noteId}`
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        loadNotes(noteTaskIdInput.value);
                    } else {
                        alert(data.message);
                    }
                });
            }
        }
    });

    notesContainer.addEventListener('submit', function (e) {
        if (e.target.classList.contains('edit-note-form')) {
            e.preventDefault();
            const formData = new FormData(e.target);
            formData.append('action', 'update_note');

            fetch('notes_ajax.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadNotes(noteTaskIdInput.value);
                } else {
                    alert(data.message);
                }
            });
        }
    });
});
</script>

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

    .note-count-badge {
        background-color: #3498db;
        color: white;
        border-radius: 50%;
        padding: 2px 6px;
        font-size: 10px;
        position: relative;
        top: -10px;
        right: 5px;
    }

    .has-notes .fa-sticky-note {
        color: #2980b9;
    }
</style>
