<?php
// Vista: Detalle de proyecto y gestión de tareas asociadas (avanzada)
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
                    <td class="px-4 py-2">
                        <?php
                        $taskObj = Example\Models\Task::find($task['id']);
                        $labels = $taskObj ? $taskObj->labelsArray() : [];
                        foreach ($labels as $label): ?>
                            <span style="background:<?= htmlspecialchars($label['color'] ?? '#eee') ?>;color:#222;padding:2px 6px;border-radius:4px;font-size:11px;margin-right:2px;display:inline-block;">
                                <?= htmlspecialchars($label['name']) ?>
                            </span>
                        <?php endforeach; ?>
                        <a href="?view=task_labels_edit&task_id=<?= $task['id'] ?>"
                            class="bg-purple-500 hover:bg-purple-600 text-white px-3 py-1 rounded ml-2">Etiquetas</a>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
