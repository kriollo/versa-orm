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
<div class="mb-6">
    <a href="?action=projects" class="text-blue-700 hover:underline">&larr; Volver a proyectos</a>
</div>
<div class="bg-white shadow rounded-lg p-6 mb-8">
    <h2 class="text-2xl font-bold text-blue-800 mb-2">Proyecto: <?= htmlspecialchars($project['name']) ?></h2>
    <p class="text-gray-700 mb-2">Descripción: <?= htmlspecialchars($project['description']) ?></p>
    <div class="text-xs text-gray-500 mb-2">Creado: <?= $project['created_at'] ?> | Actualizado: <?= $project['updated_at'] ?></div>
    <div class="mb-2">
        <span class="font-semibold text-gray-700">Usuario dueño:</span>
        <?= $user ? htmlspecialchars($user['name']) . ' (' . htmlspecialchars($user['email']) . ')' : '<span class="text-gray-400">Sin asignar</span>' ?>
    </div>
    <div class="mb-2">
        <span class="font-semibold text-gray-700">Tareas completadas:</span>
        <?= $completedCount ?> / <?= $totalCount ?>
    </div>
    <div class="mb-2">
        <span class="font-semibold text-gray-700">Estado de caché:</span>
        <span class="text-xs bg-gray-200 px-2 py-1 rounded"><?= is_array($cacheStatus) ? json_encode($cacheStatus) : $cacheStatus ?></span>
    </div>
    <div class="flex space-x-2 mt-4">
        <a href="?action=edit_project&id=<?= $project['id'] ?>" class="bg-yellow-400 hover:bg-yellow-500 text-white px-3 py-1 rounded">Editar Proyecto</a>
        <a href="?action=delete_project&id=<?= $project['id'] ?>" class="bg-red-500 hover:bg-red-600 text-white px-3 py-1 rounded">Eliminar Proyecto</a>
        <a href="?action=complete_all_tasks&id=<?= $project['id'] ?>" class="bg-green-700 hover:bg-green-800 text-white px-3 py-1 rounded">Marcar todas como completadas</a>
        <a href="?action=export_project_json&id=<?= $project['id'] ?>" class="bg-blue-700 hover:bg-blue-800 text-white px-3 py-1 rounded">Exportar JSON</a>
    </div>
</div>
<div class="flex items-center justify-between mb-4">
    <h3 class="text-xl font-bold text-blue-700">Tareas de este proyecto</h3>
    <a href="?action=new&project_id=<?= $project['id'] ?>" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded shadow">Nueva Tarea</a>
</div>
<form method="get" class="flex flex-wrap gap-2 mb-4 items-end bg-blue-50 p-4 rounded shadow">
    <input type="hidden" name="action" value="show_project">
    <input type="hidden" name="id" value="<?= $project['id'] ?>">
    <div>
        <label class="block text-xs font-semibold text-gray-700 mb-1">Etiqueta</label>
        <select name="label_id" class="border rounded px-2 py-1">
            <option value="">Todas</option>
            <?php foreach (\Example\Models\Label::all() as $label): ?>
                <option value="<?= is_object($label) ? $label->id : $label['id'] ?>" <?= isset($_GET['label_id']) && $_GET['label_id'] == (is_object($label) ? $label->id : $label['id']) ? 'selected' : '' ?>><?= htmlspecialchars(is_object($label) ? $label->name : $label['name']) ?></option>
            <?php endforeach; ?>
        </select>
    </div>
    <div>
        <label class="block text-xs font-semibold text-gray-700 mb-1">Estado</label>
        <select name="status" class="border rounded px-2 py-1">
            <option value="">Todos</option>
            <option value="1" <?= isset($_GET['status']) && $_GET['status'] === '1' ? 'selected' : '' ?>>Completadas</option>
            <option value="0" <?= isset($_GET['status']) && $_GET['status'] === '0' ? 'selected' : '' ?>>Pendientes</option>
        </select>
    </div>
    <div>
        <label class="block text-xs font-semibold text-gray-700 mb-1">Buscar</label>
        <input type="text" name="search" value="<?= htmlspecialchars($_GET['search'] ?? '') ?>" class="border rounded px-2 py-1" placeholder="Título o descripción...">
    </div>
    <div>
        <label class="block text-xs font-semibold text-gray-700 mb-1">Por página</label>
        <select name="perPage" class="border rounded px-2 py-1">
            <option value="1" <?= (isset($_GET['perPage']) && $_GET['perPage'] == 1) ? 'selected' : '' ?>>1</option>
            <?php foreach ([5, 10, 20, 50, 100] as $n): ?>
                <option value="<?= $n ?>" <?= (isset($_GET['perPage']) && $_GET['perPage'] == $n) ? 'selected' : '' ?>><?= $n ?></option>
            <?php endforeach; ?>
        </select>
    </div>
    <div>
        <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded">Filtrar</button>
    </div>
</form>
<div class="bg-white shadow rounded-lg overflow-hidden">
    <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-blue-100">
            <tr>
                <th class="px-4 py-2 text-left">ID</th>
                <th class="px-4 py-2 text-left">Título</th>
                <th class="px-4 py-2 text-left">Descripción</th>
                <th class="px-4 py-2 text-left">Completada</th>
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
                    <td class="px-4 py-2">
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
                        <a href="?view=task_labels_edit&task_id=<?= $task['id'] ?>" class="bg-purple-500 hover:bg-purple-600 text-white px-3 py-1 rounded ml-2">Etiquetas</a>
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
