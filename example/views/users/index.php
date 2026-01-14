<?php

/**
 * Vista para listar todos los usuarios.
 */
?>

<div class="max-w-6xl mx-auto">
    <!-- Header -->
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900 dark:text-white transition-colors duration-200">Usuarios</h1>
            <p class="text-gray-600 dark:text-gray-300 transition-colors duration-200">Gestiona los usuarios del sistema</p>
        </div>
        <a href="?action=user_create" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors dark:bg-blue-600 dark:hover:bg-blue-500">
            <i class="fas fa-plus mr-2"></i>
            Nuevo Usuario
        </a>
    </div>

    <!-- Estadísticas -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div class="bg-white dark:bg-gray-800 p-4 rounded-lg shadow transition-colors duration-200">
            <div class="flex items-center">
                <div class="p-2 bg-blue-100 dark:bg-blue-900/40 rounded-lg mr-3 transition-colors duration-200">
                    <i class="fas fa-users text-blue-600 dark:text-blue-400"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold text-gray-900 dark:text-white transition-colors duration-200"><?php echo
                        count($users)
                    ; ?></p>
                    <p class="text-gray-600 dark:text-gray-300 text-sm transition-colors duration-200">Total Usuarios</p>
                </div>
            </div>
        </div>

        <div class="bg-white dark:bg-gray-800 p-4 rounded-lg shadow transition-colors duration-200">
            <div class="flex items-center">
                <div class="p-2 bg-green-100 dark:bg-green-900/40 rounded-lg mr-3 transition-colors duration-200">
                    <i class="fas fa-user-check text-green-600 dark:text-green-400"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold text-gray-900 dark:text-white transition-colors duration-200"><?php echo
                        count($users)
                    ; ?></p>
                    <p class="text-gray-600 dark:text-gray-300 text-sm transition-colors duration-200">Usuarios Activos</p>
                </div>
            </div>
        </div>

        <div class="bg-white dark:bg-gray-800 p-4 rounded-lg shadow transition-colors duration-200">
            <div class="flex items-center">
                <div class="p-2 bg-yellow-100 dark:bg-yellow-900/40 rounded-lg mr-3 transition-colors duration-200">
                    <i class="fas fa-clock text-yellow-600 dark:text-yellow-400"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold text-gray-900 dark:text-white transition-colors duration-200"><?php echo
                        count(array_filter(
                            $users,
                            static fn($u): bool => safe_strtotime($u->created_at) > strtotime('-30 days'),
                        ))
                    ; ?></p>
                    <p class="text-gray-600 dark:text-gray-300 text-sm transition-colors duration-200">Nuevos (30 días)</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Lista de usuarios -->
    <?php if (!empty($users)) { ?>
        <div class="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden transition-colors duration-200">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 p-6">
                <?php foreach ($users as $user) { ?>
                    <?php

                    // Obtener estadísticas reales del usuario usando el método optimizado
                    $stats = $user->getStats();

                    // Extraer datos para facilitar el uso en la vista
                    $userProjects = [];
                    $userTasks = $stats['tasks'];
                    $completedTasks = $stats['completed_tasks'];

                    // Procesar proyectos para mostrar en badges
                    foreach ($stats['projects'] as $project) {
                        $userProjects[] = [
                            'name' => $project['name'] ?? 'Sin nombre',
                            'color' => $project['color'] ?? '#6c5ce7',
                        ];
                    }
                    ?>
                    <div class="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-6 hover:shadow-lg transition-shadow transition-colors duration-200">
                        <!-- Avatar y información básica -->
                        <div class="flex items-center mb-4">
                            <div class="avatar-lg mr-4" style="background-color: <?php echo
                                htmlspecialchars($user->avatar_color ?? '#6c5ce7')
                            ; ?>">
                                <?php echo strtoupper(substr($user->name ?? 'NN', 0, 2)); ?>
                            </div>
                            <div class="flex-1">
                                <h3 class="font-semibold text-lg text-gray-900 dark:text-white transition-colors duration-200"><?php echo
                                    htmlspecialchars($user->name ?? 'Sin nombre')
                                ; ?></h3>
                                <p class="text-gray-600 dark:text-gray-300 text-sm transition-colors duration-200"><?php echo
                                    htmlspecialchars($user->email ?? 'Sin email')
                                ; ?></p>
                                <p class="text-gray-500 dark:text-gray-400 text-xs mt-1 transition-colors duration-200">
                                    Miembro desde <?php echo
                                        isset($user->created_at)
                                            ? safe_date('M Y', $user->created_at)
                                            : 'Fecha desconocida'
                                    ; ?>
                                </p>
                            </div>
                        </div>

                        <!-- Estadísticas del usuario -->
                        <div class="grid grid-cols-3 gap-4 mb-4">
                            <div class="text-center">
                                <p class="text-2xl font-semibold text-blue-600"><?php echo count($userProjects); ?></p>
                                <p class="text-xs text-gray-500 dark:text-gray-400 transition-colors duration-200">Proyectos</p>
                            </div>
                            <div class="text-center">
                                <p class="text-2xl font-semibold text-green-600"><?php echo count($userTasks); ?></p>
                                <p class="text-xs text-gray-500 dark:text-gray-400 transition-colors duration-200">Tareas</p>
                            </div>
                            <div class="text-center">
                                <p class="text-2xl font-semibold text-orange-600"><?php echo count($completedTasks); ?></p>
                                <p class="text-xs text-gray-500 dark:text-gray-400 transition-colors duration-200">Completadas</p>
                            </div>
                        </div>

                        <!-- Progreso de tareas -->
                        <?php if (count($userTasks) > 0) { ?>
                            <div class="mb-4">
                                <div class="flex justify-between text-xs text-gray-600 dark:text-gray-300 mb-1 transition-colors duration-200">
                                    <span>Progreso</span>
                                    <span><?php echo count($completedTasks); ?>/<?php echo count($userTasks); ?></span>
                                </div>
                                <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 transition-colors duration-200">
                                    <div class="bg-green-600 h-2 rounded-full" style="width: <?php echo
                                        count($userTasks) > 0 ? (count($completedTasks) / count($userTasks)) * 100 : 0
                                    ; ?>%"></div>
                                </div>
                            </div>
                        <?php } ?>

                        <!-- Proyectos recientes -->
                        <?php if ($userProjects !== []) { ?>
                            <div class="mb-4">
                                <p class="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2 transition-colors duration-200">Proyectos activos:</p>
                                <div class="flex flex-wrap gap-1">
                                    <?php foreach (array_slice($userProjects, 0, 3) as $project) { ?>
                                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium dark:ring-1 dark:ring-white/10 transition-colors"
                                            style="background-color: <?php echo htmlspecialchars($project['color']); ?>20; color: <?php echo
                                                htmlspecialchars($project['color'])
                                            ; ?>">
                                            <?php echo htmlspecialchars($project['name']); ?>
                                        </span>
                                    <?php } ?>
                                    <?php if (count($userProjects) > 3) { ?>
                                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 transition-colors duration-200">
                                            +<?php echo count($userProjects) - 3; ?> más
                                        </span>
                                    <?php } ?>
                                </div>
                            </div>
                        <?php } ?>

                        <!-- Acciones -->
                        <div class="flex items-center justify-between pt-4 border-t border-gray-100 dark:border-gray-700 transition-colors duration-200">
                            <div class="flex items-center space-x-2 text-xs text-gray-500 dark:text-gray-400 transition-colors duration-200">
                                <span class="flex items-center">
                                    <i class="fas fa-clock mr-1"></i>
                                    <?php echo
                                        isset($user->updated_at) ? safe_date('d/m/Y', $user->updated_at) : 'Sin fecha'
                                    ; ?>
                                </span>
                            </div>
                            <div class="flex items-center space-x-2">
                                <a href="?action=user_edit&id=<?php echo $user->id ?? 0; ?>"
                                    class="text-yellow-600 hover:text-yellow-800 dark:text-yellow-400 dark:hover:text-yellow-300 transition-colors duration-200"
                                    title="Editar usuario">
                                    <i class="fas fa-edit"></i>
                                </a>
                                <a href="?action=user_delete&id=<?php echo $user->id ?? 0; ?>"
                                    onclick="return confirm('¿Estás seguro de que quieres eliminar este usuario?')"
                                    class="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 transition-colors duration-200"
                                    title="Eliminar usuario">
                                    <i class="fas fa-trash"></i>
                                </a>
                            </div>
                        </div>
                    </div>
                <?php } ?>
            </div>
        </div>
    <?php } else { ?>
        <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-12 text-center transition-colors duration-200">
            <i class="fas fa-users text-4xl text-gray-300 dark:text-gray-500 mb-4 transition-colors duration-200"></i>
            <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-2 transition-colors duration-200">No hay usuarios</h3>
            <p class="text-gray-500 dark:text-gray-300 mb-4 transition-colors duration-200">Comienza agregando el primer usuario al sistema</p>
            <a href="?action=user_create" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors">
                <i class="fas fa-plus mr-2"></i>
                Crear Usuario
            </a>
        </div>
    <?php } ?>
</div>

<style>
    .avatar-lg {
        width: 60px;
        height: 60px;
        border-radius: 50%;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        font-size: 20px;
        font-weight: 600;
        color: white;
    }
</style>
