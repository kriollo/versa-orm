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
        <form method="GET" action="?action=tasks" id="filtersForm">
            <input type="hidden" name="action" value="tasks">
            <div class="grid grid-cols-1 md:grid-cols-5 gap-4">
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Estado</label>
                    <select name="status" class="w-full border border-gray-300 rounded-md px-3 py-2">
                        <option value="">Todos los estados</option>
                        <option value="todo" <?= ($filters['status'] ?? '') === 'todo' ? 'selected' : '' ?>>Por Hacer</option>
                        <option value="in_progress" <?= ($filters['status'] ?? '') === 'in_progress' ? 'selected' : '' ?>>En Progreso</option>
                        <option value="done" <?= ($filters['status'] ?? '') === 'done' ? 'selected' : '' ?>>Completadas</option>
                    </select>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Prioridad</label>
                    <select name="priority" class="w-full border border-gray-300 rounded-md px-3 py-2">
                        <option value="">Todas las prioridades</option>
                        <option value="urgent" <?= ($filters['priority'] ?? '') === 'urgent' ? 'selected' : '' ?>>Urgente</option>
                        <option value="high" <?= ($filters['priority'] ?? '') === 'high' ? 'selected' : '' ?>>Alta</option>
                        <option value="medium" <?= ($filters['priority'] ?? '') === 'medium' ? 'selected' : '' ?>>Media</option>
                        <option value="low" <?= ($filters['priority'] ?? '') === 'low' ? 'selected' : '' ?>>Baja</option>
                    </select>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Proyecto</label>
                    <select name="project_id" class="w-full border border-gray-300 rounded-md px-3 py-2">
                        <option value="">Todos los proyectos</option>
                        <?php foreach ($projects as $project): ?>
                            <option value="<?= $project['id'] ?>" <?= ($filters['project_id'] ?? '') == $project['id'] ? 'selected' : '' ?>>
                                <?= htmlspecialchars($project['name']) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-1">Asignado a</label>
                    <select name="user_id" class="w-full border border-gray-300 rounded-md px-3 py-2">
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
    <div class="bg-white shadow rounded-lg p-4 mb-6">
        <div class="flex flex-col md:flex-row md:items-center md:justify-between space-y-4 md:space-y-0">
            <div class="flex items-center space-x-4">
                <span class="text-sm text-gray-700">
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
                    <label class="text-sm text-gray-700">Por página:</label>
                    <select name="per_page" onchange="this.form.submit()" class="border border-gray-300 rounded px-2 py-1 text-sm">
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
                            class="px-3 py-2 bg-gray-200 text-gray-700 rounded hover:bg-gray-300 transition-colors">
                            <i class="fas fa-chevron-left"></i>
                        </a>
                    <?php endif; ?>

                    <span class="px-3 py-2 bg-blue-600 text-white rounded">
                        <?= $pagination['current_page'] ?? 1 ?> / <?= $pagination['total_pages'] ?? 1 ?>
                    </span>

                    <?php if ($pagination['has_next'] ?? false): ?>
                        <a href="?action=tasks&page=<?= $pagination['next_page'] ?>&per_page=<?= $pagination['per_page'] ?><?= !empty($filters['status']) ? '&status=' . urlencode($filters['status']) : '' ?><?= !empty($filters['priority']) ? '&priority=' . urlencode($filters['priority']) : '' ?><?= !empty($filters['project_id']) ? '&project_id=' . urlencode($filters['project_id']) : '' ?><?= !empty($filters['user_id']) ? '&user_id=' . urlencode($filters['user_id']) : '' ?>"
                            class="px-3 py-2 bg-gray-200 text-gray-700 rounded hover:bg-gray-300 transition-colors">
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
        $todoTasks = count(array_filter($tasks, fn($t) => $t['status'] === 'todo'));
        $inProgressTasks = count(array_filter($tasks, fn($t) => $t['status'] === 'in_progress'));
        $doneTasks = count(array_filter($tasks, fn($t) => $t['status'] === 'done'));
        ?>

        <div class="bg-white p-4 rounded-lg shadow">
            <div class="flex items-center">
                <div class="p-2 bg-gray-100 rounded-lg mr-3">
                    <i class="fas fa-tasks text-gray-600"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold"><?= $totalFiltered ?></p>
                    <p class="text-gray-600 text-sm">Total<?= !empty(array_filter($filters)) ? ' (Filtrado)' : '' ?></p>
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
                        $taskProject = array_filter($projects, fn($p) => $p['id'] == $task['project_id']);
                        $taskProject = !empty($taskProject) ? array_values($taskProject)[0] : null;

                        $taskUser = null;
                        if ($task['user_id']) {
                            $taskUser = array_filter($users, fn($u) => $u['id'] == $task['user_id']);
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

<!-- Controles de Paginación -->
<?php if (isset($pagination) && $pagination['total_pages'] > 1): ?>
    <div class="bg-white px-4 py-3 flex items-center justify-between border-t border-gray-200 sm:px-6 mt-4 rounded-lg shadow">
        <div class="flex-1 flex justify-between sm:hidden">
            <?php if ($pagination['current_page'] > 1): ?>
                <a href="?action=tasks&page=<?= $pagination['current_page'] - 1 ?>&per_page=<?= $pagination['per_page'] ?><?= $filterQueryString ?>"
                    class="relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                    Anterior
                </a>
            <?php endif; ?>
            <?php if ($pagination['current_page'] < $pagination['total_pages']): ?>
                <a href="?action=tasks&page=<?= $pagination['current_page'] + 1 ?>&per_page=<?= $pagination['per_page'] ?><?= $filterQueryString ?>"
                    class="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                    Siguiente
                </a>
            <?php endif; ?>
        </div>
        <div class="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
            <div>
                <p class="text-sm text-gray-700">
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
                <select onchange="changePerPage(this.value)" class="form-select border-gray-300 rounded-md text-sm">
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
                            class="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50">
                            <span class="sr-only">Anterior</span>
                            <i class="fas fa-chevron-left"></i>
                        </a>
                    <?php else: ?>
                        <span class="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-gray-100 text-sm font-medium text-gray-300">
                            <i class="fas fa-chevron-left"></i>
                        </span>
                    <?php endif; ?>

                    <!-- Números de página -->
                    <?php
                    $start_page = max(1, $pagination['current_page'] - 2);
                    $end_page = min($pagination['total_pages'], $pagination['current_page'] + 2);

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
