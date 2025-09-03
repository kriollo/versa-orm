<?php $title = 'Proyectos - VersaORM Trello Demo'; ?>

<div class="flex justify-between items-center mb-8">
    <div>
        <h1 class="text-3xl font-bold text-gray-900 dark:text-white mb-2">Proyectos</h1>
        <p class="text-gray-600 dark:text-gray-400">Gestiona todos los proyectos de tu organización</p>
    </div>

    <a href="?action=project_create" class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 dark:bg-blue-600 dark:hover:bg-blue-500">
        <i class="fas fa-plus mr-2"></i>
        Nuevo Proyecto
    </a>
</div>

<?php if (empty($projects)) { ?>
    <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-12 text-center">
        <i class="fas fa-folder-open text-6xl text-gray-300 dark:text-gray-600 mb-4"></i>
        <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-2">No hay proyectos</h3>
        <p class="text-gray-500 dark:text-gray-400 mb-6">Comienza creando tu primer proyecto para organizar las tareas.</p>
        <a href="?action=project_create" class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 dark:bg-blue-600 dark:hover:bg-blue-500">
            <i class="fas fa-plus mr-2"></i>
            Crear Primer Proyecto
        </a>
    </div>

<?php } else { ?>
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <?php foreach ($projects as $project) { ?>
            <div class="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden hover:shadow-lg transition-shadow transition-colors">
                <!-- Header del proyecto con color -->
                <div class="h-24" style="background: linear-gradient(135deg, <?php echo
                    htmlspecialchars($project->color)
            ; ?>, <?php echo htmlspecialchars($project->color); ?>80);">
                    <div class="p-4 h-full flex items-end">
                        <h3 class="text-white font-bold text-lg truncate"><?php echo htmlspecialchars($project->name); ?></h3>
                    </div>
                </div>

                <!-- Contenido del proyecto -->
                <div class="p-4">
                    <?php if ($project->description) { ?>
                        <p class="text-gray-600 dark:text-gray-300 text-sm mb-4 line-clamp-2">
                            <?php echo htmlspecialchars($project->description); ?>
                        </p>
                    <?php } ?>

                    <!-- Estadísticas del proyecto -->
                    <?php
                // Usar directamente el modelo de proyecto ya provisto (instancia), evitando llamadas estáticas
                $tasks = $project->tasks()->findAll();
            $members = $project->members()->findAll();
            $completedTasks = array_filter($tasks, static fn ($t): bool => $t->status === 'done');
            ?>

                    <div class="flex items-center justify-between text-sm text-gray-500 dark:text-gray-400 mb-4">
                        <div class="flex items-center space-x-4">
                            <span class="flex items-center">
                                <i class="fas fa-tasks mr-1"></i>
                                <?php echo count($tasks); ?> tareas
                            </span>
                            <span class="flex items-center">
                                <i class="fas fa-users mr-1"></i>
                                <?php echo count($members); ?> miembros
                            </span>
                        </div>
                        <span class="text-xs">
                            <?php echo isset($project->created_at) ? safe_date('M Y', $project->created_at) : ''; ?>
                        </span>
                    </div>

                    <!-- Progreso -->
                    <?php if (count($tasks) > 0) { ?>
                        <div class="mb-4">
                            <div class="flex justify-between text-xs text-gray-600 dark:text-gray-300 mb-1">
                                <span>Progreso</span>
                                <span><?php echo count($completedTasks); ?>/<?php echo count($tasks); ?></span>
                            </div>
                            <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                                <div class="bg-green-600 h-2 rounded-full" style="width: <?php echo
                            count($tasks) > 0 ? (count($completedTasks) / count($tasks)) * 100 : 0
                        ; ?>%"></div>
                            </div>
                        </div>

                    <?php } ?>

                    <!-- Miembros (avatares) -->
                    <?php if (!empty($members)) { ?>
                        <div class="flex items-center mb-4">
                            <span class="text-xs text-gray-500 dark:text-gray-400 mr-2">Miembros:</span>
                            <div class="flex -space-x-2">
                                <?php foreach (array_slice($members, 0, 3) as $member) { ?>
                                    <div class="avatar border-2 border-white dark:border-gray-800" style="background-color: <?php echo
                                htmlspecialchars($member->avatar_color)
                                    ; ?>" title="<?php echo htmlspecialchars($member->name); ?>">
                                        <?php echo strtoupper(substr($member->name, 0, 2)); ?>
                                    </div>
                                <?php } ?>
                                <?php if (count($members) > 3) { ?>
                                    <div class="avatar bg-gray-500 border-2 border-white dark:border-gray-800" title="<?php echo
                                        count($members) - 3
                                    ; ?> más">
                                        +<?php echo count($members) - 3; ?>
                                    </div>
                                <?php } ?>
                            </div>
                        </div>

                    <?php } ?>

                    <!-- Acciones -->
                    <div class="flex items-center justify-between pt-2 border-t border-gray-100 dark:border-gray-700">
                        <a href="?action=project_show&id=<?php echo $project->id; ?>" class="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 text-sm font-medium">
                            <i class="fas fa-eye mr-1"></i>
                            Ver detalles
                        </a>
                        <div class="flex items-center space-x-2">

                            <a href="?action=project_edit&id=<?php echo $project->id; ?>" class="text-yellow-600 hover:text-yellow-800 dark:text-yellow-400 dark:hover:text-yellow-300" title="Editar">
                                <i class="fas fa-edit"></i>
                            </a>
                            <a href="?action=project_delete&id=<?php echo $project->id; ?>"
                                onclick="return confirm('¿Estás seguro de que quieres eliminar este proyecto?')"
                                class="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300" title="Eliminar">
                                <i class="fas fa-trash"></i>
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        <?php } ?>
    </div>
<?php }
