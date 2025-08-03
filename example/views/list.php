<!-- views/list.php: Listado de tareas estilo Trello -->
<?php
/** @var array<int, array<string, mixed>> $tasks */
// Agrupar tareas por estado
$pendientes = array_filter($tasks, fn($t) => !isset($t['completed']) || !$t['completed']);
$completadas = array_filter($tasks, fn($t) => isset($t['completed']) && $t['completed']);
?>
<div class="flex items-center justify-between mb-6">
    <h1 class="text-3xl font-bold text-blue-800">Tablero de Tareas (Trello Style)</h1>
    <a href="?action=new" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded shadow">Nueva Tarea
    </a>
</div>
<div class="overflow-x-auto pb-8">
    <div class="flex space-x-8 min-w-full">
        <!-- Columna Pendientes -->
        <div class="bg-white rounded-lg shadow-lg min-w-[320px] w-96 flex-shrink-0 flex flex-col">
            <div class="bg-gradient-to-r from-yellow-400 to-yellow-600 px-4 py-3 rounded-t-lg">
                <h2 class="text-white text-lg font-semibold">Pendientes</h2>
            </div>
            <div class="p-4 flex-1 flex flex-col gap-3">
                <?php if (empty($pendientes)): ?>
                    <div class="text-gray-400 text-center py-8">Sin tareas pendientes</div>
                <?php else: ?>
                    <?php foreach ($pendientes as $task): ?>
                        <div class="bg-gray-50 rounded shadow p-4 flex flex-col gap-2 border-l-4 border-yellow-400">
                            <span class="font-semibold text-gray-800 text-base"> <?= htmlspecialchars($task['title']) ?> </span>
                            <div class="flex flex-wrap gap-2 items-center">
                                <?php if (!empty($task['labels'])): ?>
                                    <?php foreach ($task['labels'] as $label): ?>
                                        <span class="px-2 py-1 rounded text-xs font-semibold"
                                            style="background:<?= htmlspecialchars($label['color'] ?? '#eee') ?>;color:#222;">
                                            <?= htmlspecialchars($label['name']) ?>
                                        </span>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                                <?php if (!empty($task['user'])): ?>
                                    <span class="ml-2 text-xs text-blue-700 font-medium">👤 <?= htmlspecialchars($task['user']['name']) ?></span>
                                <?php endif; ?>
                            </div>
                            <div class="flex justify-end gap-2 mt-2">
                                <a href="?action=edit&id=<?= $task['id'] ?>" class="text-indigo-600 hover:underline text-xs">Editar</a>
                                <a href="?action=trash&id=<?= $task['id'] ?>" class="text-red-500 hover:underline text-xs">Eliminar</a>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            <div class="bg-gray-100 px-4 py-2 rounded-b-lg text-right">
                <a href="?action=new" class="text-blue-600 hover:underline text-xs font-semibold">+ Añadir tarea</a>
            </div>
        </div>
        <!-- Columna Completadas -->
        <div class="bg-white rounded-lg shadow-lg min-w-[320px] w-96 flex-shrink-0 flex flex-col">
            <div class="bg-gradient-to-r from-green-400 to-green-600 px-4 py-3 rounded-t-lg">
                <h2 class="text-white text-lg font-semibold">Completadas</h2>
            </div>
            <div class="p-4 flex-1 flex flex-col gap-3">
                <?php if (empty($completadas)): ?>
                    <div class="text-gray-400 text-center py-8">Sin tareas completadas</div>
                <?php else: ?>
                    <?php foreach ($completadas as $task): ?>
                        <div class="bg-gray-50 rounded shadow p-4 flex flex-col gap-2 border-l-4 border-green-400">
                            <span class="font-semibold text-gray-800 text-base"> <?= htmlspecialchars($task['title']) ?> </span>
                            <div class="flex flex-wrap gap-2 items-center">
                                <?php if (!empty($task['labels'])): ?>
                                    <?php foreach ($task['labels'] as $label): ?>
                                        <span class="px-2 py-1 rounded text-xs font-semibold"
                                            style="background:<?= htmlspecialchars($label['color'] ?? '#eee') ?>;color:#222;">
                                            <?= htmlspecialchars($label['name']) ?>
                                        </span>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                                <?php if (!empty($task['user'])): ?>
                                    <span class="ml-2 text-xs text-blue-700 font-medium">👤 <?= htmlspecialchars($task['user']['name']) ?></span>
                                <?php endif; ?>
                            </div>
                            <div class="flex justify-end gap-2 mt-2">
                                <a href="?action=edit&id=<?= $task['id'] ?>" class="text-indigo-600 hover:underline text-xs">Editar</a>
                                <a href="?action=trash&id=<?= $task['id'] ?>" class="text-red-500 hover:underline text-xs">Eliminar</a>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>
<?php $content = ob_get_clean(); ?>
