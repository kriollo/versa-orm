<?php

/**
 * Vista para mostrar detalles de un proyecto
 */
?>

<div class="max-w-6xl mx-auto">
    <!-- Header del proyecto -->
    <div class="bg-white shadow rounded-lg mb-6">
        <div class="h-32" style="background: linear-gradient(135deg, <?= htmlspecialchars($project->color) ?>, <?= htmlspecialchars($project->color) ?>80);">
            <div class="p-6 h-full flex items-end">
                <div class="flex-1">
                    <h1 class="text-white text-3xl font-bold mb-2"><?= htmlspecialchars($project->name) ?></h1>
                    <?php if ($project->description): ?>
                        <p class="text-white/90"><?= htmlspecialchars($project->description) ?></p>
                    <?php endif; ?>
                </div>
                <div class="flex items-center space-x-3">
                    <a href="?action=project_edit&id=<?= $project->id ?>" class="bg-white/20 hover:bg-white/30 text-white px-4 py-2 rounded-lg transition-colors">
                        <i class="fas fa-edit mr-2"></i>
                        Editar
                    </a>
                    <a href="?action=projects" class="bg-white/20 hover:bg-white/30 text-white px-4 py-2 rounded-lg transition-colors">
                        <i class="fas fa-arrow-left mr-2"></i>
                        Volver
                    </a>
                </div>
            </div>
        </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Información del proyecto -->
        <div class="lg:col-span-1">
            <div class="bg-white shadow rounded-lg p-6 mb-6">
                <h3 class="text-lg font-semibold mb-4">Información del Proyecto</h3>

                <div class="space-y-3">
                    <div>
                        <label class="text-sm font-medium text-gray-500">Propietario</label>
                        <div class="flex items-center mt-1">
                            <?php if ($owner): ?>
                                <div class="avatar mr-2" style="background-color: <?= htmlspecialchars($owner['avatar_color']) ?>">
                                    <?= strtoupper(substr($owner['name'], 0, 2)) ?>
                                </div>
                                <span><?= htmlspecialchars($owner['name']) ?></span>
                            <?php else: ?>
                                <span class="text-gray-400">Sin propietario</span>
                            <?php endif; ?>
                        </div>
                    </div>

                    <div>
                        <label class="text-sm font-medium text-gray-500">Fecha de creación</label>
                        <p class="mt-1"><?= date('d/m/Y H:i', strtotime($project->created_at)) ?></p>
                    </div>

                    <div>
                        <label class="text-sm font-medium text-gray-500">Última actualización</label>
                        <p class="mt-1"><?= date('d/m/Y H:i', strtotime($project->updated_at)) ?></p>
                    </div>
                </div>
            </div>

            <!-- Miembros del proyecto -->
            <div class="bg-white shadow rounded-lg p-6">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-semibold">Miembros (<?= count($members) ?>)</h3>
                    <button class="text-blue-600 hover:text-blue-800 text-sm font-medium">
                        <i class="fas fa-plus mr-1"></i>
                        Agregar
                    </button>
                </div>

                <?php if (!empty($members)): ?>
                    <div class="space-y-2">
                        <?php foreach ($members as $member): ?>
                            <div class="flex items-center justify-between p-2 hover:bg-gray-50 rounded">
                                <div class="flex items-center">
                                    <div class="avatar mr-3" style="background-color: <?= htmlspecialchars($member['avatar_color']) ?>">
                                        <?= strtoupper(substr($member['name'], 0, 2)) ?>
                                    </div>
                                    <div>
                                        <p class="font-medium"><?= htmlspecialchars($member['name']) ?></p>
                                        <p class="text-sm text-gray-500"><?= htmlspecialchars($member['email']) ?></p>
                                    </div>
                                </div>
                                <button class="text-red-500 hover:text-red-700 opacity-0 hover:opacity-100 transition-opacity">
                                    <i class="fas fa-times"></i>
                                </button>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <p class="text-gray-500 text-center py-4">No hay miembros asignados</p>
                <?php endif; ?>
            </div>
        </div>

        <!-- Tareas del proyecto -->
        <div class="lg:col-span-2">
            <div class="bg-white shadow rounded-lg p-6">
                <div class="flex items-center justify-between mb-6">
                    <h3 class="text-lg font-semibold">Tareas (<?= count($tasks) ?>)</h3>
                    <a href="?action=task_create&project_id=<?= $project->id ?>" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors">
                        <i class="fas fa-plus mr-2"></i>
                        Nueva Tarea
                    </a>
                </div>

                <!-- Progreso general -->
                <?php if (count($tasks) > 0): ?>
                    <?php
                    $completedTasks = array_filter($tasks, fn($t) => $t['status'] === 'done');
                    $progressPercent = (count($completedTasks) / count($tasks)) * 100;
                    ?>
                    <div class="mb-6">
                        <div class="flex justify-between text-sm text-gray-600 mb-2">
                            <span>Progreso del proyecto</span>
                            <span><?= count($completedTasks) ?>/<?= count($tasks) ?> tareas completadas</span>
                        </div>
                        <div class="w-full bg-gray-200 rounded-full h-3">
                            <div class="bg-green-600 h-3 rounded-full transition-all duration-300" style="width: <?= $progressPercent ?>%"></div>
                        </div>
                    </div>
                <?php endif; ?>

                <!-- Lista de tareas por estado -->
                <?php
                $tasksByStatus = [
                    'todo' => array_filter($tasks, fn($t) => $t['status'] === 'todo'),
                    'in_progress' => array_filter($tasks, fn($t) => $t['status'] === 'in_progress'),
                    'done' => array_filter($tasks, fn($t) => $t['status'] === 'done')
                ];
                $statusNames = [
                    'todo' => 'Por Hacer',
                    'in_progress' => 'En Progreso',
                    'done' => 'Completadas'
                ];
                $statusColors = [
                    'todo' => 'bg-gray-100 text-gray-800',
                    'in_progress' => 'bg-blue-100 text-blue-800',
                    'done' => 'bg-green-100 text-green-800'
                ];
                ?>

                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <?php foreach ($tasksByStatus as $status => $statusTasks): ?>
                        <div class="border border-gray-200 rounded-lg p-4">
                            <h4 class="font-medium mb-3 flex items-center">
                                <span class="inline-block w-3 h-3 rounded-full mr-2 <?= $statusColors[$status] ?>"></span>
                                <?= $statusNames[$status] ?> (<?= count($statusTasks) ?>)
                            </h4>

                            <?php if (!empty($statusTasks)): ?>
                                <div class="space-y-2">
                                    <?php foreach ($statusTasks as $task): ?>
                                        <div class="bg-gray-50 p-3 rounded border">
                                            <div class="flex items-start justify-between">
                                                <div class="flex-1">
                                                    <h5 class="font-medium text-sm mb-1"><?= htmlspecialchars($task['title']) ?></h5>
                                                    <?php if ($task['description']): ?>
                                                        <p class="text-xs text-gray-600 mb-2"><?= htmlspecialchars(substr($task['description'], 0, 80)) ?><?= strlen($task['description']) > 80 ? '...' : '' ?></p>
                                                    <?php endif; ?>

                                                    <div class="flex items-center justify-between">
                                                        <span class="text-xs px-2 py-1 rounded <?= getPriorityClass($task['priority']) ?>">
                                                            <?= ucfirst($task['priority']) ?>
                                                        </span>
                                                        <?php if ($task['due_date']): ?>
                                                            <span class="text-xs text-gray-500">
                                                                <?= date('d/m', strtotime($task['due_date'])) ?>
                                                            </span>
                                                        <?php endif; ?>
                                                    </div>
                                                </div>
                                                <a href="?action=task_edit&id=<?= $task['id'] ?>" class="text-gray-400 hover:text-gray-600 ml-2">
                                                    <i class="fas fa-edit text-xs"></i>
                                                </a>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            <?php else: ?>
                                <p class="text-gray-400 text-sm text-center py-4">No hay tareas</p>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
    </div>
</div>

<?php
function getPriorityClass($priority)
{
    switch ($priority) {
        case 'urgent':
            return 'bg-red-100 text-red-800';
        case 'high':
            return 'bg-orange-100 text-orange-800';
        case 'medium':
            return 'bg-yellow-100 text-yellow-800';
        case 'low':
            return 'bg-green-100 text-green-800';
        default:
            return 'bg-gray-100 text-gray-800';
    }
}
?>
