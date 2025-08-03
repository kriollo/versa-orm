<?php
// Vista Trello: Tablero de proyectos y tareas
/** @var array<int, array<string, mixed>> $projects */
/** @var array<string, array<int, array<string, mixed>>> $tasksByProject */
?>
<div class="flex items-center justify-between mb-6">
    <div>
        <h1 class="text-3xl font-bold text-blue-800">Tablero de Proyectos (Trello Style)</h1>
        <p class="text-gray-600 mt-1">Visualiza y gestiona tus proyectos y tareas como columnas y tarjetas</p>
    </div>
    <div class="flex space-x-3">
        <a href="?action=new" class="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded shadow transition duration-200">
            <svg class="w-4 h-4 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
            </svg>
            Nueva Tarea
        </a>
        <a href="?action=new_project" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded shadow transition duration-200">
            <svg class="w-4 h-4 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
            </svg>
            Nuevo Proyecto
        </a>
        <a href="?action=new_user" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded shadow transition duration-200">
            <svg class="w-4 h-4 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
            </svg>
            Nuevo Usuario
        </a>
    </div>
</div>
<div class="overflow-x-auto pb-8">
    <div class="flex space-x-6 min-w-full">
        <?php foreach ($projects as $project): ?>
            <div class="bg-white rounded-lg shadow-lg min-w-[320px] w-96 flex-shrink-0 flex flex-col">
                <div class="bg-gradient-to-r from-blue-600 to-purple-600 px-4 py-3 rounded-t-lg flex items-center justify-between">
                    <h2 class="text-white text-lg font-semibold flex-1"> <?= htmlspecialchars($project['name']) ?> </h2>
                    <a href="?action=project_show&id=<?= $project['id'] ?>" class="ml-2 text-white hover:underline text-xs">Ver</a>
                </div>
                <div class="p-4 flex-1 flex flex-col gap-3">
                    <?php if (empty($tasksByProject[$project['id']])): ?>
                        <div class="text-gray-400 text-center py-8">
                            <svg class="w-10 h-10 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                            </svg>
                            Sin tareas en este proyecto
                        </div>
                    <?php else: ?>
                        <?php foreach ($tasksByProject[$project['id']] as $task): ?>
                            <div class="bg-gray-50 rounded shadow p-4 flex flex-col gap-2 border-l-4 border-blue-400">
                                <div class="flex items-center justify-between">
                                    <span class="font-semibold text-gray-800 text-base"> <?= htmlspecialchars($task['title']) ?> </span>
                                    <?php if (isset($task['completed']) && $task['completed']): ?>
                                        <span class="text-green-600 text-xs font-bold">✔ Completada</span>
                                    <?php else: ?>
                                        <span class="text-yellow-600 text-xs font-bold">⏳ Pendiente</span>
                                    <?php endif; ?>
                                </div>
                                <div class="flex flex-wrap gap-2 items-center">
                                    <?php if (!empty($task['labels'])): ?>
                                        <?php foreach ($task['labels'] as $label): ?>
                                            <span class="px-2 py-1 rounded text-xs font-semibold" style="background:<?= htmlspecialchars($label['color'] ?? '#eee') ?>;color:#222;">
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
                    <a href="?action=new&project_id=<?= $project['id'] ?>" class="text-blue-600 hover:underline text-xs font-semibold">+ Añadir tarea</a>
                </div>
            </div>
        <?php endforeach; ?>
        <!-- Columna para crear nuevo proyecto -->
        <div class="bg-gradient-to-r from-green-400 to-blue-400 rounded-lg shadow-lg min-w-[320px] w-96 flex-shrink-0 flex flex-col items-center justify-center p-6">
            <a href="?action=new_project" class="text-white font-bold text-lg hover:underline">+ Nuevo Proyecto</a>
        </div>
    </div>
</div>
