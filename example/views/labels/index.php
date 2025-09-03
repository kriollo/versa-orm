<?php

/**
 * Vista para listar todas las etiquetas.
 */
?>

<div class="max-w-6xl mx-auto">
    <!-- Header -->
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Etiquetas</h1>
            <p class="text-gray-600 dark:text-gray-400">Gestiona las etiquetas del sistema para organizar tareas</p>
        </div>
        <a href="?action=label_create" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors">
            <i class="fas fa-plus mr-2"></i>
            Nueva Etiqueta
        </a>
    </div>

    <!-- Estadísticas -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div class="bg-white dark:bg-gray-800 p-4 rounded-lg shadow transition-colors">
            <div class="flex items-center">
                <div class="p-2 bg-blue-100 dark:bg-blue-900/30 rounded-lg mr-3 transition-colors">
                    <i class="fas fa-tags text-blue-600"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold text-gray-900 dark:text-white transition-colors"><?php echo
                        count($labels)
                    ; ?></p>
                    <p class="text-gray-600 dark:text-gray-400 text-sm transition-colors">Total Etiquetas</p>
                </div>
            </div>
        </div>

        <div class="bg-white dark:bg-gray-800 p-4 rounded-lg shadow transition-colors">
            <div class="flex items-center">
                <div class="p-2 bg-green-100 dark:bg-green-900/30 rounded-lg mr-3 transition-colors">
                    <i class="fas fa-check-circle text-green-600"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold text-gray-900 dark:text-white transition-colors"><?php echo
                        count(array_filter(
                            $labels,
                            static fn($l): bool => !empty($l->tasks_count) && $l->tasks_count > 0,
                        ))
                    ; ?></p>
                    <p class="text-gray-600 dark:text-gray-400 text-sm transition-colors">En Uso</p>
                </div>
            </div>
        </div>

        <div class="bg-white dark:bg-gray-800 p-4 rounded-lg shadow transition-colors">
            <div class="flex items-center">
                <div class="p-2 bg-yellow-100 dark:bg-yellow-900/30 rounded-lg mr-3 transition-colors">
                    <i class="fas fa-tasks text-yellow-600"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold text-gray-900 dark:text-white transition-colors"><?php echo
                        array_sum(array_column($labels, 'tasks_count'))
                    ; ?></p>
                    <p class="text-gray-600 dark:text-gray-400 text-sm transition-colors">Asignaciones</p>
                </div>
            </div>
        </div>

        <div class="bg-white dark:bg-gray-800 p-4 rounded-lg shadow transition-colors">
            <div class="flex items-center">
                <div class="p-2 bg-purple-100 dark:bg-purple-900/30 rounded-lg mr-3 transition-colors">
                    <i class="fas fa-palette text-purple-600"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold text-gray-900 dark:text-white transition-colors"><?php echo
                        count(array_unique(array_column($labels, 'color')))
                    ; ?></p>
                    <p class="text-gray-600 dark:text-gray-400 text-sm transition-colors">Colores Únicos</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Lista de etiquetas -->
    <?php if (!empty($labels)) { ?>
        <div class="bg-white dark:bg-gray-800 shadow rounded-lg overflow-hidden transition-colors">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 p-6">
                <?php foreach ($labels as $label) { ?>
                    <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition-shadow transition-colors">
                        <!-- Header de la etiqueta -->
                        <div class="flex items-center justify-between mb-3">
                            <div class="flex items-center flex-1">
                                <div class="w-4 h-4 rounded-full mr-3" style="background-color: <?php echo
                                    htmlspecialchars($label->color)
                                ; ?>"></div>
                                <h3 class="font-semibold text-gray-900 dark:text-white truncate transition-colors"><?php echo
                                    htmlspecialchars($label->name)
                                ; ?></h3>
                            </div>
                            <div class="flex items-center space-x-1">
                                <a href="?action=label_edit&id=<?php echo $label->id; ?>" class="text-yellow-600 hover:text-yellow-800 dark:text-yellow-400 dark:hover:text-yellow-300 transition-colors" title="Editar">
                                    <i class="fas fa-edit text-sm"></i>
                                </a>
                                <a href="?action=label_delete&id=<?php echo $label->id; ?>"
                                    onclick="return confirm('¿Estás seguro de que quieres eliminar esta etiqueta?')"
                                    class="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 transition-colors" title="Eliminar">
                                    <i class="fas fa-trash text-sm"></i>
                                </a>
                            </div>
                        </div>

                        <!-- Descripción -->
                        <?php if ($label->description) { ?>
                            <p class="text-gray-600 dark:text-gray-300 text-sm mb-3 line-clamp-2 transition-colors">
                                <?php echo htmlspecialchars($label->description); ?>
                            </p>
                        <?php } else { ?>
                            <p class="text-gray-400 dark:text-gray-500 text-sm mb-3 italic transition-colors">Sin descripción</p>
                        <?php } ?>

                        <!-- Estadísticas de la etiqueta -->
                        <div class="flex items-center justify-between text-sm">
                            <div class="flex items-center space-x-3">
                                <span class="flex items-center text-gray-500 dark:text-gray-400 transition-colors">
                                    <i class="fas fa-tasks mr-1"></i>
                                    <span class="task-count-clickable cursor-pointer text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 underline transition-colors"
                                        data-label-id="<?php echo $label->id; ?>"
                                        data-label-name="<?php echo htmlspecialchars($label->name); ?>"
                                        title="Haz clic para ver las tareas asociadas">
                                        <?php echo $label->tasks_count ?? 0; ?> tareas
                                    </span>
                                </span>
                            </div>
                            <span class="text-xs text-gray-400 dark:text-gray-500 transition-colors">
                                <?php echo isset($label->created_at) ? safe_date('d/m/Y', $label->created_at) : ''; ?>
                            </span>
                        </div>

                        <!-- Vista previa de la etiqueta -->
                        <div class="mt-3 pt-3 border-t border-gray-100 dark:border-gray-700 transition-colors">
                            <div class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ring-1 ring-current/20 transition-colors"
                                style="background-color: <?php echo htmlspecialchars($label->color); ?>20; color: <?php echo
                                    htmlspecialchars($label->color)
                                ; ?>">
                                <div class="w-2 h-2 rounded-full mr-2" style="background-color: <?php echo
                                    htmlspecialchars($label->color)
                                ; ?>"></div>
                                <?php echo htmlspecialchars($label->name); ?>
                            </div>
                        </div>
                    </div>
                <?php } ?>
            </div>
        </div>

        <!-- Paleta de colores más usados -->
        <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6 mt-6 transition-colors">
            <h3 class="text-lg font-semibold mb-4 text-gray-900 dark:text-white transition-colors">Paleta de Colores</h3>
            <div class="flex flex-wrap gap-2">
                <?php
                $colors = array_unique(array_column($labels, 'color'));

                foreach ($colors as $color) { ?>
                    <div class="flex items-center space-x-2 bg-gray-50 dark:bg-gray-700 px-3 py-2 rounded-lg transition-colors">
                        <div class="w-4 h-4 rounded-full" style="background-color: <?php echo htmlspecialchars($color); ?>"></div>
                        <span class="text-sm font-mono text-gray-600 dark:text-gray-300 transition-colors"><?php echo
                            htmlspecialchars($color)
                        ; ?></span>
                        <span class="text-xs text-gray-500 dark:text-gray-400 transition-colors">
                            (<?php echo count(array_filter($labels, static fn($l): bool => $l->color === $color)); ?> etiquetas)
                        </span>
                    </div>
                <?php } ?>
            </div>
        </div>

    <?php } else { ?>
        <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-12 text-center transition-colors">
            <i class="fas fa-tags text-4xl text-gray-300 dark:text-gray-600 mb-4 transition-colors"></i>
            <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-2 transition-colors">No hay etiquetas</h3>
            <p class="text-gray-500 dark:text-gray-400 mb-4 transition-colors">Las etiquetas te ayudan a organizar y categorizar tus tareas</p>
            <a href="?action=label_create" class="bg-blue-600 hover:bg-blue-700 dark:hover:bg-blue-500 text-white px-4 py-2 rounded-lg transition-colors">
                <i class="fas fa-plus mr-2"></i>
                Crear Primera Etiqueta
            </a>
        </div>
    <?php } ?>
</div>

<!-- Modal para mostrar tareas asociadas -->
<div id="tasksModal" class="fixed inset-0 bg-black/50 hidden z-50">
    <div class="flex items-center justify-center min-h-screen p-4">
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-4xl w-full max-h-96 overflow-hidden transition-colors">
            <div class="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700 transition-colors">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white transition-colors">
                    <i class="fas fa-tasks mr-2 text-blue-600"></i>
                    Tareas asociadas a <span id="modalLabelName" class="text-blue-600 dark:text-blue-400 transition-colors"></span>
                </h3>
                <button id="closeModal" class="text-gray-400 hover:text-gray-300 dark:hover:text-gray-200 text-xl transition-colors">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="p-4 overflow-y-auto max-h-80">
                <div id="modalTasksContainer">
                    <!-- Las tareas se cargarán aquí -->
                    <div class="text-center py-8">
                        <i class="fas fa-spinner fa-spin text-blue-600 text-2xl"></i>
                        <p class="text-gray-600 dark:text-gray-400 mt-2 transition-colors">Cargando tareas...</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
    .line-clamp-2 {
        display: -webkit-box;
        -webkit-line-clamp: 2;
        line-clamp: 2;
        -webkit-box-orient: vertical;
        overflow: hidden;
    }
</style>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        // Elementos de la modal
        const modal = document.getElementById('tasksModal');
        const modalLabelName = document.getElementById('modalLabelName');
        const modalTasksContainer = document.getElementById('modalTasksContainer');
        const closeModalBtn = document.getElementById('closeModal');

        // Manejar clics en los contadores de tareas
        const taskCountElements = document.querySelectorAll('.task-count-clickable');

        taskCountElements.forEach(element => {
            element.addEventListener('click', function() {
                const labelId = this.getAttribute('data-label-id');
                const labelName = this.getAttribute('data-label-name');

                // Configurar modal
                modalLabelName.textContent = labelName;

                // Mostrar modal
                modal.classList.remove('hidden');

                // Cargar las tareas
                loadTasksForModal(labelId);
            });
        });

        // Cerrar modal
        closeModalBtn.addEventListener('click', function() {
            modal.classList.add('hidden');
        });

        // Cerrar modal al hacer clic en el fondo
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                modal.classList.add('hidden');
            }
        });

        // Cerrar modal con Escape
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && !modal.classList.contains('hidden')) {
                modal.classList.add('hidden');
            }
        });
    });

    function loadTasksForModal(labelId) {
        const modalTasksContainer = document.getElementById('modalTasksContainer');

        // Mostrar indicador de carga
        modalTasksContainer.innerHTML = `
        <div class="text-center py-8">
            <i class="fas fa-spinner fa-spin text-blue-600 text-2xl"></i>
            <p class="text-gray-600 dark:text-gray-400 mt-2 transition-colors">Cargando tareas...</p>
        </div>
    `;

        // Realizar la petición AJAX
        fetch('?action=label_tasks&label_id=' + labelId)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    modalTasksContainer.innerHTML = `
                    <div class="text-center py-8">
                        <i class="fas fa-exclamation-triangle text-red-500 text-2xl"></i>
                        <p class="text-red-600 mt-2">Error: ${data.error}</p>
                    </div>
                `;
                    return;
                }

                if (data.length === 0) {
                    modalTasksContainer.innerHTML = `
                    <div class="text-center py-8">
                        <i class="fas fa-info-circle text-gray-400 text-2xl"></i>
                        <p class="text-gray-500 mt-2">No hay tareas asociadas a esta etiqueta</p>
                    </div>
                `;
                    return;
                }

                // Mostrar las tareas en una tabla
                let tasksHtml = `
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700 transition-colors">
                        <thead class="bg-gray-50 dark:bg-gray-700 transition-colors">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider transition-colors">Tarea</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider transition-colors">Estado</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider transition-colors">Prioridad</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider transition-colors">Proyecto</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider transition-colors">Usuario</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider transition-colors">Acciones</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700 transition-colors">
            `;

                data.forEach(task => {
                    const statusBadge = getStatusBadge(task.status);
                    const priorityBadge = getPriorityBadge(task.priority);

                    tasksHtml += `
                    <tr class="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                        <td class="px-6 py-4 whitespace-nowrap">
                            <div class="text-sm font-medium text-gray-900 dark:text-gray-100 transition-colors">${escapeHtml(task.title)}</div>
                            ${task.description ? `<div class="text-sm text-gray-500 dark:text-gray-400 transition-colors">${escapeHtml(task.description.substring(0, 60))}${task.description.length > 60 ? '...' : ''}</div>` : ''}
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap">${statusBadge}</td>
                        <td class="px-6 py-4 whitespace-nowrap">${priorityBadge}</td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100 transition-colors">
                            ${task.project_name ? escapeHtml(task.project_name) : '<span class="text-gray-400 dark:text-gray-500 italic transition-colors">Sin proyecto</span>'}
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100 transition-colors">
                            ${task.user_name ? escapeHtml(task.user_name) : '<span class="text-gray-400 dark:text-gray-500 italic transition-colors">Sin asignar</span>'}
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                            <a href="?action=task_edit&id=${task.id}" class="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300 mr-3 transition-colors">
                                <i class="fas fa-edit"></i> Editar
                            </a>
                        </td>
                    </tr>
                `;
                });

                tasksHtml += `
                        </tbody>
                    </table>
                </div>
            `;

                modalTasksContainer.innerHTML = tasksHtml;
            })
            .catch(error => {
                console.error('Error loading tasks:', error);
                modalTasksContainer.innerHTML = `
                <div class="text-center py-8">
                    <i class="fas fa-exclamation-triangle text-red-500 text-2xl"></i>
                    <p class="text-red-600 dark:text-red-400 mt-2 transition-colors">Error al cargar las tareas</p>
                </div>
            `;
            });
    }

    function getStatusBadge(status) {
        const statusClasses = {
            'pendiente': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
            'en_progreso': 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
            'completada': 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
            'cancelada': 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'
        };

        const statusLabels = {
            'pendiente': 'Pendiente',
            'en_progreso': 'En Progreso',
            'completada': 'Completada',
            'cancelada': 'Cancelada'
        };

        const className = statusClasses[status] || 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
        const label = statusLabels[status] || status;

        return `<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${className}">${label}</span>`;
    }

    function getPriorityBadge(priority) {
        const priorityClasses = {
            'alta': 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
            'media': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
            'baja': 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
        };

        const priorityLabels = {
            'alta': 'Alta',
            'media': 'Media',
            'baja': 'Baja'
        };

        const className = priorityClasses[priority] || 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
        const label = priorityLabels[priority] || priority;

        return `<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${className}">${label}</span>`;
    }

    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
</script>
