<!-- views/list.php: Listado de tareas -->
<?php
// Vista: Listado de tareas (modernizada con TailwindCSS)
/** @var array<int, array<string, mixed>> $tasks */
ob_start();
?>
<div class="flex items-center justify-between mb-6">
    <h1 class="text-3xl font-bold text-blue-800">Tareas</h1>
    <a href="?action=new" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded shadow">Nueva Tarea
    </a>
</div>
<!-- Filtros y paginación para listado de tareas -->
<form method="get" class="flex flex-wrap gap-2 mb-4 items-end bg-blue-50 p-4 rounded shadow">
    <input type="hidden" name="action" value="list">
    <div>
        <label class="block text-xs font-semibold text-gray-700 mb-1">Proyecto</label>
        <select name="project_id" class="border rounded px-2 py-1">
            <option value="">Todos</option>
            <?php foreach ($allProjects as $proj): ?>
                <option value="<?= $proj['id'] ?>" <?= isset($_GET['project_id']) && $_GET['project_id'] == $proj['id'] ? 'selected' : '' ?>><?= htmlspecialchars($proj['name']) ?></option>
            <?php endforeach; ?>
        </select>
    </div>
    <div>
        <label class="block text-xs font-semibold text-gray-700 mb-1">Etiqueta</label>
        <select name="label_id" class="border rounded px-2 py-1">
            <option value="">Todas</option>
            <?php foreach ($allLabels as $label): ?>
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
                <th class="px-4 py-2 text-left">Creación</th>
                <th class="px-4 py-2 text-left">Actualización</th>
                <th class="px-4 py-2 text-left">Acciones</th>
            </tr>
        </thead>
        <tbody class="bg-white divide-y divide-gray-100">
            <?php foreach ($tasks as $task): ?>
                <tr>
                    <td class="px-4 py-2 font-mono text-sm text-gray-700">#<?= $task['id'] ?></td>
                    <td class="px-4 py-2 font-semibold text-blue-900"><?= htmlspecialchars($task['title']) ?></td>
                    <td class="px-4 py-2 text-gray-700"><?= htmlspecialchars($task['description']) ?></td>
                    <td class="px-4 py-2">
                        <span class="inline-block px-2 py-1 rounded text-xs <?= $task['completed'] ? 'bg-green-200 text-green-800' : 'bg-yellow-200 text-yellow-800' ?>">
                            <?= $task['completed'] ? 'Sí' : 'No' ?>
                        </span>
                    </td>
                    <td class="px-4 py-2 text-xs text-gray-500"><?= $task['created_at'] ?? '' ?></td>
                    <td class="px-4 py-2 text-xs text-gray-500"><?= $task['updated_at'] ?? '' ?></td>
                    <td class="px-4 py-2">
                        <?php
                        // Mostrar etiquetas de la tarea
                        $taskObj = Example\Models\Task::find($task['id']);
                        $labels = $taskObj ? $taskObj->labelsArray() : [];
                        foreach ($labels as $label): ?>
                            <span style="background:<?= htmlspecialchars($label['color'] ?? '#eee') ?>;color:#222;padding:2px 6px;border-radius:4px;font-size:11px;margin-right:2px;display:inline-block;">
                                <?= htmlspecialchars($label['name']) ?>
                            </span>
                        <?php endforeach; ?>
                        <a href="?action=edit&id=<?= $task['id'] ?>"
                            class="bg-yellow-400 hover:bg-yellow-500 text-white px-3 py-1 rounded mr-2">Editar</a>
                        <a href="?view=task_labels_edit&task_id=<?= $task['id'] ?>"
                            class="bg-purple-500 hover:bg-purple-600 text-white px-3 py-1 rounded">Etiquetas</a>
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
            $baseUrl = '?action=list'
                . (isset($_GET['perPage']) ? '&perPage=' . (int)$_GET['perPage'] : '')
                . (isset($_GET['project_id']) ? '&project_id=' . (int)$_GET['project_id'] : '')
                . (isset($_GET['label_id']) ? '&label_id=' . (int)$_GET['label_id'] : '')
                . (isset($_GET['status']) ? '&status=' . htmlspecialchars($_GET['status']) : '')
                . (isset($_GET['search']) ? '&search=' . urlencode($_GET['search']) : '');
            $range = 2; // Cuántos botones a la izquierda y derecha
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
