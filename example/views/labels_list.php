<?php
// Vista Trello: Listado de etiquetas y tareas asociadas
// Los datos ya vienen del controlador: $labels, $selectedLabelId, $tareas
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

<div class="flex items-center justify-between mb-6">
    <h1 class="text-3xl font-bold text-purple-800 flex items-center">
        <svg class="w-8 h-8 mr-3 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
        </svg>
        Tablero de Etiquetas (Trello Style)
    </h1>
    <a href="?view=label_new" class="inline-flex items-center px-6 py-3 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium transition duration-200 shadow-lg">
        <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
        </svg>
        Nueva Etiqueta
    </a>
</div>

<div class="overflow-x-auto pb-8">
    <div class="flex space-x-6 min-w-full">
        <?php foreach ($labels as $label): ?>
            <div class="bg-white rounded-lg shadow-lg min-w-[320px] w-96 flex-shrink-0 flex flex-col">
                <div class="px-4 py-3 rounded-t-lg flex items-center justify-between" style="background:<?= htmlspecialchars($label['color'] ?? '#eee') ?>;">
                    <h2 class="text-lg font-semibold" style="color:#222;"> <?= htmlspecialchars($label['name']) ?> </h2>
                    <a href="?view=label_edit&id=<?= $label['id'] ?>" class="ml-2 text-xs text-blue-700 hover:underline">Editar</a>
                </div>
                <div class="p-4 flex-1 flex flex-col gap-3">
                    <?php $tasks = $tareasPorEtiqueta[$label['id']] ?? []; ?>
                    <?php if (empty($tasks)): ?>
                        <div class="text-gray-400 text-center py-8">Sin tareas con esta etiqueta</div>
                    <?php else: ?>
                        <?php foreach ($tasks as $task): ?>
                            <div class="bg-gray-50 rounded shadow p-4 flex flex-col gap-2 border-l-4 border-purple-400">
                                <span class="font-semibold text-gray-800 text-base"> <?= htmlspecialchars($task['title']) ?> </span>
                                <div class="flex flex-wrap gap-2 items-center">
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
        <?php endforeach; ?>
        <!-- Columna para crear nueva etiqueta -->
        <div class="bg-gradient-to-r from-purple-400 to-blue-400 rounded-lg shadow-lg min-w-[320px] w-96 flex-shrink-0 flex flex-col items-center justify-center p-6">
            <a href="?view=label_new" class="text-white font-bold text-lg hover:underline">+ Nueva Etiqueta</a>
        </div>
    </div>
</div>
<?php $content = ob_get_clean(); ?>
