<?php
// Vista: Listado de proyectos y tareas asociadas (pantalla principal)
/** @var array<int, array<string, mixed>> $projects */
/** @var array<string, array<int, array<string, mixed>>> $tasksByProject */
ob_start();
?>
<div class="flex items-center justify-between mb-6">
    <h1 class="text-3xl font-bold text-blue-800">Proyectos y Tareas</h1>
    <a href="?action=new_project" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded shadow">Nuevo Proyecto</a>
</div>
<div class="bg-white shadow rounded-lg overflow-hidden mb-8">
    <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-blue-100">
            <tr>
                <th class="px-4 py-2 text-left">ID</th>
                <th class="px-4 py-2 text-left">Nombre</th>
                <th class="px-4 py-2 text-left">Descripción</th>
                <th class="px-4 py-2 text-left">Tareas</th>
                <th class="px-4 py-2 text-left">Acciones</th>
            </tr>
        </thead>
        <tbody class="bg-white divide-y divide-gray-100">
            <?php foreach ($projects as $project): ?>
                <tr>
                    <td class="px-4 py-2 font-mono text-sm text-gray-700">#<?= $project['id'] ?></td>
                    <td class="px-4 py-2 font-semibold text-blue-900"><?= htmlspecialchars($project['name']) ?></td>
                    <td class="px-4 py-2 text-gray-700"><?= htmlspecialchars($project['description']) ?></td>
                    <td class="px-4 py-2">
                        <span class="inline-block bg-blue-200 text-blue-800 px-2 py-1 rounded text-xs font-semibold">
                            <?= count($tasksByProject[$project['id']] ?? []) ?> tareas
                        </span>
                    </td>
                    <td class="px-4 py-2">
                        <a href="?action=show_project&id=<?= $project['id'] ?>" class="bg-blue-500 hover:bg-blue-600 text-white px-3 py-1 rounded mr-2">Ver</a>
                        <a href="?action=edit_project&id=<?= $project['id'] ?>" class="bg-yellow-400 hover:bg-yellow-500 text-white px-3 py-1 rounded mr-2">Editar</a>
                        <a href="?action=delete_project&id=<?= $project['id'] ?>" class="bg-red-500 hover:bg-red-600 text-white px-3 py-1 rounded">Eliminar</a>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
