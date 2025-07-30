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
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
