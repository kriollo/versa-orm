<?php

/**
 * Vista para editar una tarea existente.
 */
?>

<div class="max-w-4xl mx-auto">
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900 dark:text-white transition-colors">Editar Tarea</h1>
            <p class="text-gray-600 dark:text-gray-300 transition-colors">Modifica la información de la tarea seleccionada</p>
        </div>
        <a href="?action=tasks" class="text-gray-600 hover:text-gray-800 dark:text-gray-300 dark:hover:text-white transition-colors">
            <i class="fas fa-arrow-left mr-2"></i>
            Volver a Tareas
        </a>
    </div>

    <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6 border border-transparent dark:border-gray-700 transition-colors">
        <form method="POST" action="?action=task_edit&id=<?php echo $task->id; ?>">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <!-- Información básica -->
                <div class="md:col-span-2">
                    <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4 transition-colors">Información Básica</h3>
                </div>

                <div class="md:col-span-2">
                    <label for="title" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">
                        Título <span class="text-red-500">*</span>
                    </label>
                    <input type="text"
                        id="title"
                        name="title"
                        required
                        value="<?php echo htmlspecialchars($task->title); ?>"
                        class="w-full border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                        placeholder="Ingresa el título de la tarea">
                </div>

                <div class="md:col-span-2">
                    <label for="description" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">Descripción</label>
                    <textarea id="description"
                        name="description"
                        rows="4"
                        class="w-full border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                        placeholder="Describe los detalles de la tarea"><?php echo
                            htmlspecialchars($task->description ?? '')
                        ; ?></textarea>
                </div>

                <!-- Asignación y configuración -->
                <div class="md:col-span-2">
                    <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4 mt-6 transition-colors">Asignación y Configuración</h3>
                </div>

                <div>
                    <label for="project_id" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">
                        Proyecto <span class="text-red-500">*</span>
                    </label>
                    <select id="project_id"
                        name="project_id"
                        required
                        class="w-full border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors">
                        <option value="">Selecciona un proyecto</option>
                        <?php foreach ($projects as $project) { ?>
                            <option value="<?php echo $project['id']; ?>" <?php echo
                                $task->project_id === $project['id'] ? 'selected' : ''
                            ; ?>>
                                <?php echo htmlspecialchars($project['name']); ?>
                            </option>
                        <?php } ?>
                    </select>
                </div>

                <div>
                    <label for="user_id" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">Asignar a</label>
                    <select id="user_id"
                        name="user_id"
                        class="w-full border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors">
                        <option value="">Sin asignar</option>
                        <?php foreach ($users as $user) { ?>
                            <option value="<?php echo $user['id']; ?>" <?php echo
                                $task->user_id === $user['id'] ? 'selected' : ''
                            ; ?>>
                                <?php echo htmlspecialchars($user['name']); ?> (<?php echo
                                    htmlspecialchars($user['email'])
                                ; ?>)
                            </option>
                        <?php } ?>
                    </select>
                </div>

                <div>
                    <label for="status" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">Estado</label>
                    <select id="status"
                        name="status"
                        class="w-full border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors">
                        <option value="todo" <?php echo $task->status === 'todo' ? 'selected' : ''; ?>>Por Hacer</option>
                        <option value="in_progress" <?php echo $task->status === 'in_progress' ? 'selected' : ''; ?>>En Progreso</option>
                        <option value="done" <?php echo $task->status === 'done' ? 'selected' : ''; ?>>Completada</option>
                    </select>
                </div>

                <div>
                    <label for="priority" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">Prioridad</label>
                    <select id="priority"
                        name="priority"
                        class="w-full border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors">
                        <option value="low" <?php echo $task->priority === 'low' ? 'selected' : ''; ?>>Baja</option>
                        <option value="medium" <?php echo $task->priority === 'medium' ? 'selected' : ''; ?>>Media</option>
                        <option value="high" <?php echo $task->priority === 'high' ? 'selected' : ''; ?>>Alta</option>
                        <option value="urgent" <?php echo $task->priority === 'urgent' ? 'selected' : ''; ?>>Urgente</option>
                    </select>
                </div>

                <div>
                    <label for="due_date" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">Fecha de vencimiento</label>
                    <input type="date"
                        id="due_date"
                        name="due_date"
                        value="<?php echo $task->due_date ? safe_date('Y-m-d', $task->due_date) : ''; ?>"
                        class="w-full border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors">
                </div>

                <!-- Etiquetas -->
                <div class="md:col-span-2">
                    <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4 mt-6 transition-colors">Etiquetas</h3>
                    <p class="text-sm text-gray-600 dark:text-gray-400 mb-4 transition-colors">Selecciona las etiquetas que se aplicarán a esta tarea</p>

                    <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                        <?php foreach ($labels as $label) { ?>
                            <label class="flex items-center p-3 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer transition-colors">
                                <input type="checkbox"
                                    name="labels[]"
                                    value="<?php echo $label['id']; ?>"
                                    <?php echo in_array($label['id'], $taskLabels ?? [], true) ? 'checked' : ''; ?>
                                    class="mr-3 text-blue-600 focus:ring-blue-500 border-gray-300 dark:border-gray-600 rounded">
                                <div class="flex items-center flex-1">
                                    <div class="w-3 h-3 rounded-full mr-2" style="background-color: <?php echo
                                        htmlspecialchars($label['color'])
                                    ; ?>"></div>
                                    <span class="text-sm font-medium text-gray-800 dark:text-gray-200 transition-colors"><?php echo
                                        htmlspecialchars($label['name'])
                                    ; ?></span>
                                </div>
                            </label>
                        <?php } ?>
                    </div>
                </div>
            </div>

            <!-- Información adicional -->
            <div class="mt-8 pt-6 border-t border-gray-200 dark:border-gray-700 transition-colors">
                <div class="grid grid-cols-2 gap-4 text-sm text-gray-500 dark:text-gray-400">
                    <div>
                        <strong>Creada:</strong> <?php echo
                            isset($task->created_at) ? safe_date('d/m/Y H:i', $task->created_at) : ''
                        ; ?>
                    </div>
                    <div>
                        <strong>Actualizada:</strong> <?php echo
                            isset($task->updated_at) ? safe_date('d/m/Y H:i', $task->updated_at) : ''
                        ; ?>
                    </div>
                </div>
            </div>

            <!-- Botones de acción -->
            <div class="flex items-center justify-end space-x-3 mt-6">
                <a href="?action=tasks" class="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    Cancelar
                </a>
                <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 dark:hover:bg-blue-500 transition-colors">
                    <i class="fas fa-save mr-2"></i>
                    Guardar Cambios
                </button>
            </div>
        </form>
    </div>
</div>

<script>
    // Previsualización de etiquetas seleccionadas
    document.addEventListener('change', function(e) {
        if (e.target.type === 'checkbox' && e.target.name === 'labels[]') {
            updateSelectedLabels();
        }
    });

    function updateSelectedLabels() {
        const checkboxes = document.querySelectorAll('input[name="labels[]"]:checked');
        const selectedCount = checkboxes.length;

        // Aquí podrías agregar lógica para mostrar las etiquetas seleccionadas
        console.log(`${selectedCount} etiquetas seleccionadas`);
    }

    // Confirmar cambios si hay modificaciones
    let originalData = {};
    document.addEventListener('DOMContentLoaded', function() {
        // Capturar datos originales para detectar cambios
        const form = document.querySelector('form');
        const formData = new FormData(form);
        for (let [key, value] of formData.entries()) {
            originalData[key] = value;
        }
    });

    function hasChanges() {
        const form = document.querySelector('form');
        const formData = new FormData(form);
        for (let [key, value] of formData.entries()) {
            if (originalData[key] !== value) {
                return true;
            }
        }
        return false;
    }
</script>
