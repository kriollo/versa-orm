<?php
// Contraste para etiquetas en la tabla de tareas
if (!function_exists('isDark')) {
    function isDark($hex)
    {
        $hex = ltrim($hex, '#');
        if (strlen($hex) === 3) $hex = $hex[0] . $hex[0] . $hex[1] . $hex[1] . $hex[2] . $hex[2];
        $r = hexdec(substr($hex, 0, 2));
        $g = hexdec(substr($hex, 2, 2));
        $b = hexdec(substr($hex, 4, 2));
        return ($r * 0.299 + $g * 0.587 + $b * 0.114) < 150;
    }
}

/** @var array<string, mixed> $project */
/** @var array<int, array<string, mixed>> $tasks */
/** @var array<string, mixed>|null $user */
/** @var int $completedCount */
/** @var int $totalCount */
/** @var mixed $cacheStatus */
ob_start();
?>
<!-- Navegación de regreso -->
<div class="mb-6">
    <a href="?action=projects" class="inline-flex items-center text-blue-600 hover:text-blue-800 font-medium">
        <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
        </svg>
        Volver a proyectos
    </a>
</div>

<!-- Información del proyecto -->
<div class="bg-white shadow-lg rounded-lg overflow-hidden mb-8">
    <div class="bg-gradient-to-r from-blue-600 to-purple-600 px-6 py-6">
        <div class="flex items-center justify-between">
            <div>
                <h1 class="text-3xl font-bold text-white mb-2"><?= htmlspecialchars($project['name']) ?></h1>
                <p class="text-blue-100"><?= htmlspecialchars($project['description']) ?></p>
            </div>
            <div class="text-right">
                <div class="bg-white bg-opacity-20 rounded-lg px-4 py-2">
                    <div class="text-white text-sm font-medium">Progreso</div>
                    <div class="text-2xl font-bold text-white"><?= $totalCount > 0 ? round(($completedCount / $totalCount) * 100) : 0 ?>%</div>
                    <div class="text-blue-100 text-xs"><?= $completedCount ?> de <?= $totalCount ?> tareas</div>
                </div>
            </div>
        </div>
    </div>

    <div class="px-6 py-4">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <!-- Información del usuario -->
            <div class="bg-gray-50 rounded-lg p-4">
                <div class="flex items-center">
                    <svg class="w-8 h-8 text-gray-600 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                    </svg>
                    <div>
                        <h4 class="font-semibold text-gray-900">Usuario asignado</h4>
                        <p class="text-sm text-gray-600">
                            <?= $user ? htmlspecialchars($user['name']) : 'Sin asignar' ?>
                        </p>
                        <?php if ($user): ?>
                            <p class="text-xs text-gray-500"><?= htmlspecialchars($user['email']) ?></p>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Estadísticas de tareas -->
            <div class="bg-gray-50 rounded-lg p-4">
                <div class="flex items-center">
                    <svg class="w-8 h-8 text-green-600 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <div>
                        <h4 class="font-semibold text-gray-900">Tareas completadas</h4>
                        <p class="text-2xl font-bold text-green-600"><?= $completedCount ?></p>
                        <p class="text-xs text-gray-500">de <?= $totalCount ?> total</p>
                    </div>
                </div>
            </div>

            <!-- Fechas -->
            <div class="bg-gray-50 rounded-lg p-4">
                <div class="flex items-center">
                    <svg class="w-8 h-8 text-blue-600 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                    </svg>
                    <div>
                        <h4 class="font-semibold text-gray-900">Fechas</h4>
                        <p class="text-xs text-gray-600">Creado: <?= date('d/m/Y', strtotime($project['created_at'])) ?></p>
                        <p class="text-xs text-gray-600">Actualizado: <?= date('d/m/Y', strtotime($project['updated_at'])) ?></p>
                    </div>
                </div>
            </div>
        </div>

        <!-- Barra de progreso -->
        <div class="mb-6">
            <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-medium text-gray-700">Progreso del proyecto</span>
                <span class="text-sm text-gray-600"><?= $completedCount ?>/<?= $totalCount ?> tareas</span>
            </div>
            <div class="w-full bg-gray-200 rounded-full h-3">
                <div class="bg-gradient-to-r from-green-400 to-blue-500 h-3 rounded-full transition-all duration-300" style="width: <?= $totalCount > 0 ? ($completedCount / $totalCount) * 100 : 0 ?>%"></div>
            </div>
        </div>

        <!-- Acciones del proyecto -->
        <div class="flex flex-wrap gap-2">
            <a href="?action=new&project_id=<?= $project['id'] ?>" class="inline-flex items-center px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium rounded-md transition duration-150">
                <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                </svg>
                Nueva Tarea
            </a>
            <a href="?action=edit_project&id=<?= $project['id'] ?>" class="inline-flex items-center px-4 py-2 bg-yellow-500 hover:bg-yellow-600 text-white text-sm font-medium rounded-md transition duration-150">
                <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                </svg>
                Editar Proyecto
            </a>
            <a href="?action=complete_all_tasks&id=<?= $project['id'] ?>" class="inline-flex items-center px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm font-medium rounded-md transition duration-150" onclick="return confirm('¿Marcar todas las tareas como completadas?')">
                <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Completar Todas
            </a>
            <a href="?action=export_project_json&id=<?= $project['id'] ?>" class="inline-flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-md transition duration-150">
                <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                Exportar JSON
            </a>
            <button onclick="confirmDelete()" class="inline-flex items-center px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-medium rounded-md transition duration-150">
                <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
                Eliminar Proyecto
            </button>
        </div>

        <!-- Debug info (solo visible en modo debug) -->
        <?php if (isset($project['debug']) || (isset($cacheStatus) && $cacheStatus !== null)): ?>
            <div class="mt-4 p-3 bg-gray-100 rounded-lg">
                <h5 class="text-xs font-semibold text-gray-600 mb-1">Debug info:</h5>
                <span class="text-xs text-gray-500">Cache status: <?= is_array($cacheStatus) ? json_encode($cacheStatus) : $cacheStatus ?></span>
            </div>
        <?php endif; ?>
    </div>
</div>
<!-- Sección de tareas -->
<div class="bg-white shadow-lg rounded-lg overflow-hidden">
    <div class="bg-gradient-to-r from-indigo-600 to-purple-600 px-6 py-4">
        <div class="flex items-center justify-between">
            <h2 class="text-white text-xl font-semibold">Tareas del Proyecto</h2>
            <a href="?action=new&project_id=<?= $project['id'] ?>" class="bg-white bg-opacity-20 hover:bg-opacity-30 text-white px-4 py-2 rounded-md text-sm font-medium transition duration-150">
                <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                </svg>
                Nueva Tarea
            </a>
        </div>
    </div>

    <!-- Filtros -->
    <div class="bg-gray-50 px-6 py-4 border-b">
        <form method="get" class="flex flex-wrap gap-4 items-end">
            <input type="hidden" name="action" value="show_project">
            <input type="hidden" name="id" value="<?= $project['id'] ?>">

            <div class="flex-1 min-w-64">
                <label class="block text-sm font-medium text-gray-700 mb-1">Buscar tareas</label>
                <div class="relative">
                    <input type="text" name="search" value="<?= htmlspecialchars($_GET['search'] ?? '') ?>"
                        class="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-indigo-500 focus:border-indigo-500"
                        placeholder="Buscar por título o descripción...">
                    <svg class="absolute left-3 top-2.5 h-5 w-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                </div>
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">Estado</label>
                <select name="status" class="border border-gray-300 rounded-md px-3 py-2 focus:ring-indigo-500 focus:border-indigo-500">
                    <option value="">Todas</option>
                    <option value="1" <?= isset($_GET['status']) && $_GET['status'] === '1' ? 'selected' : '' ?>>Completadas</option>
                    <option value="0" <?= isset($_GET['status']) && $_GET['status'] === '0' ? 'selected' : '' ?>>Pendientes</option>
                </select>
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">Etiqueta</label>
                <select name="label_id" class="border border-gray-300 rounded-md px-3 py-2 focus:ring-indigo-500 focus:border-indigo-500">
                    <option value="">Todas las etiquetas</option>
                    <?php foreach (\Example\Models\Label::all() as $label): ?>
                        <option value="<?= is_object($label) ? $label->id : $label['id'] ?>" <?= isset($_GET['label_id']) && $_GET['label_id'] == (is_object($label) ? $label->id : $label['id']) ? 'selected' : '' ?>>
                            <?= htmlspecialchars(is_object($label) ? $label->name : $label['name']) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div>
                <label class="block text-sm font-medium text-gray-700 mb-1">Por página</label>
                <select name="perPage" class="border border-gray-300 rounded-md px-3 py-2 focus:ring-indigo-500 focus:border-indigo-500">
                    <?php foreach ([5, 10, 20, 50] as $n): ?>
                        <option value="<?= $n ?>" <?= (isset($_GET['perPage']) && $_GET['perPage'] == $n) ? 'selected' : '' ?>><?= $n ?></option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="flex space-x-2">
                <button type="submit" class="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-md font-medium transition duration-150">
                    Filtrar
                </button>
                <a href="?action=show_project&id=<?= $project['id'] ?>" class="bg-gray-500 hover:bg-gray-600 text-white px-4 py-2 rounded-md font-medium transition duration-150">
                    Limpiar
                </a>
            </div>
        </form>
    </div>
    <table class="min-w-full divide-y divide-gray-200">
        <tr>
            <th class="px-4 py-2 text-left">ID</th>
            <th class="px-4 py-2 text-left">Título</th>
            <th class="px-4 py-2 text-left">Descripción</th>
            <th class="px-4 py-2 text-left">Completada</th>
            <th class="px-4 py-2 text-left">Etiquetas</th>
            <th class="px-4 py-2 text-left">Acciones</th>
        </tr>
        </thead>
        <tbody class="bg-white divide-y divide-gray-100">
            <?php foreach ($tasksData as $task): ?>
                <tr>
                    <td class="px-4 py-2 font-mono text-sm text-gray-700">#<?= $task['id'] ?></td>
                    <td class="px-4 py-2 font-semibold text-blue-900"><?= htmlspecialchars($task['title']) ?></td>
                    <td class="px-4 py-2 text-gray-700"><?= htmlspecialchars($task['description']) ?></td>
                    <td class="px-4 py-2">
                        <span class="inline-block px-2 py-1 rounded text-xs <?= $task['completed'] ? 'bg-green-200 text-green-800' : 'bg-yellow-200 text-yellow-800' ?>">
                            <?= $task['completed'] ? 'Sí' : 'No' ?>
                        </span>
                    </td>
                    <td class="px-4 py-2 flex">
                        <div>
                        <?php
                        $taskObj = Example\Models\Task::find($task['id']);
                        $labels = $taskObj ? $taskObj->labelsArray() : [];
                        foreach ($labels as $label): ?>
                            <?php
                            $labelColor = $label['color'] ?? '#eee';
                            $textColor = isDark($labelColor) ? '#fff' : '#222';
                            ?>
                            <span style="background:<?= htmlspecialchars($labelColor) ?>;color:<?= htmlspecialchars($textColor) ?>;padding:2px 6px;border-radius:4px;font-size:11px;margin-right:2px;display:inline-block;">
                                <?= htmlspecialchars($label['name']) ?>
                            </span>
                        <?php endforeach; ?>
                        </div>
                        <a href="?view=task_labels_edit&task_id=<?= $task['id'] ?>" class="bg-purple-500 hover:bg-purple-600 text-white px-3 py-1 rounded ml-2">Etiquetas</a>
                    </td>
                    <td class="px-4 py-2">
                        <a href="?action=edit&id=<?= $task['id'] ?>" class="bg-yellow-400 hover:bg-yellow-500 text-white px-3 py-1 rounded ml-2">Editar</a>
                        <a href="?action=delete&id=<?= $task['id'] ?>" onclick="return confirm('¿Seguro que deseas eliminar esta tarea?');" class="bg-red-500 hover:bg-red-600 text-white px-3 py-1 rounded ml-2">Eliminar</a>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>
<?php if ($totalPages > 1): ?>
    <div class="flex justify-center mt-4">
        <nav class="inline-flex rounded-md shadow-sm items-center" aria-label="Paginación">
            <?php
            $prevPage = max(1, $page - 1);
            $nextPage = min($totalPages, $page + 1);
            $baseUrl = '?action=show_project&id=' . (int)$_GET['id']
                . (isset($_GET['perPage']) ? '&perPage=' . (int)$_GET['perPage'] : '')
                . (isset($_GET['label_id']) ? '&label_id=' . (int)$_GET['label_id'] : '')
                . (isset($_GET['status']) ? '&status=' . htmlspecialchars($_GET['status']) : '')
                . (isset($_GET['search']) ? '&search=' . urlencode($_GET['search']) : '');
            $range = 2;
            $start = max(1, $page - $range);
            $end = min($totalPages, $page + $range);
            ?>
            <a href="<?= $baseUrl . '&page=' . $prevPage ?>" class="px-3 py-1 border rounded-l <?= $page == 1 ? 'bg-gray-200 text-gray-400 cursor-not-allowed' : 'bg-white text-blue-700 hover:bg-blue-100' ?>">&laquo;</a>
            <?php if ($start > 1): ?>
                <a href="<?= $baseUrl . '&page=1' ?>" class="px-3 py-1 border bg-white text-blue-700 hover:bg-blue-100 mx-1 rounded">1</a>
                <?php if ($start > 2): ?><span class="px-2">...</span><?php endif; ?>
            <?php endif; ?>
            <?php for ($i = $start; $i <= $end; $i++): ?>
                <a href="<?= $baseUrl . '&page=' . $i ?>" class="px-3 py-1 border mx-1 rounded <?= $i == $page ? 'bg-blue-600 text-white' : 'bg-white text-blue-700 hover:bg-blue-100' ?>"><?= $i ?></a>
            <?php endfor; ?>
            <?php if ($end < $totalPages): ?>
                <?php if ($end < $totalPages - 1): ?><span class="px-2">...</span><?php endif; ?>
                <a href="<?= $baseUrl . '&page=' . $totalPages ?>" class="px-3 py-1 border bg-white text-blue-700 hover:bg-blue-100 mx-1 rounded"><?= $totalPages ?></a>
            <?php endif; ?>
            <a href="<?= $baseUrl . '&page=' . $nextPage ?>" class="px-3 py-1 border rounded-r <?= $page == $totalPages ? 'bg-gray-200 text-gray-400 cursor-not-allowed' : 'bg-white text-blue-700 hover:bg-blue-100' ?>">&raquo;</a>
        </nav>
    </div>
<?php endif; ?>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
