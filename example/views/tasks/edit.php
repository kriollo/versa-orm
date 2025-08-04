<?php

/**
 * Vista para editar una tarea existente.
 */
?>

<div class="max-w-4xl mx-auto">
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Editar Tarea</h1>
            <p class="text-gray-600">Modifica los detalles de la tarea</p>
        </div>
        <a href="?action=tasks" class="text-gray-600 hover:text-gray-800">
            <i class="fas fa-arrow-left mr-2"></i>
            Volver a Tareas
        </a>
    </div>

    <div class="bg-white shadow rounded-lg p-6">
        <form method="POST" action="?action=task_edit&id=<?= $task->id ?>">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <!-- Información básica -->
                <div class="md:col-span-2">
                    <h3 class="text-lg font-medium text-gray-900 mb-4">Información Básica</h3>
                </div>

                <div class="md:col-span-2">
                    <label for="title" class="block text-sm font-medium text-gray-700 mb-2">
                        Título <span class="text-red-500">*</span>
                    </label>
                    <input type="text"
                        id="title"
                        name="title"
                        required
                        value="<?= htmlspecialchars($task->title) ?>"
                        class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        placeholder="Ingresa el título de la tarea">
                </div>

                <div class="md:col-span-2">
                    <label for="description" class="block text-sm font-medium text-gray-700 mb-2">Descripción</label>
                    <textarea id="description"
                        name="description"
                        rows="4"
                        class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        placeholder="Describe los detalles de la tarea"><?= htmlspecialchars($task->description ?? '') ?></textarea>
                </div>

                <!-- Asignación y configuración -->
                <div class="md:col-span-2">
                    <h3 class="text-lg font-medium text-gray-900 mb-4 mt-6">Asignación y Configuración</h3>
                </div>

                <div>
                    <label for="project_id" class="block text-sm font-medium text-gray-700 mb-2">
                        Proyecto <span class="text-red-500">*</span>
                    </label>
                    <select id="project_id"
                        name="project_id"
                        required
                        class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                        <option value="">Selecciona un proyecto</option>
                        <?php foreach ($projects as $project): ?>
                            <option value="<?= $project->id ?>" <?= $task->project_id == $project->id ? 'selected' : '' ?>>
                                <?= htmlspecialchars($project->name) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div>
                    <label for="user_id" class="block text-sm font-medium text-gray-700 mb-2">Asignar a</label>
                    <select id="user_id"
                        name="user_id"
                        class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                        <option value="">Sin asignar</option>
                        <?php foreach ($users as $user): ?>
                            <option value="<?= $user->id ?>" <?= $task->user_id == $user->id ? 'selected' : '' ?>>
                                <?= htmlspecialchars($user->name) ?> (<?= htmlspecialchars($user->email) ?>)
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div>
                    <label for="status" class="block text-sm font-medium text-gray-700 mb-2">Estado</label>
                    <select id="status"
                        name="status"
                        class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                        <option value="todo" <?= $task->status === 'todo' ? 'selected' : '' ?>>Por Hacer</option>
                        <option value="in_progress" <?= $task->status === 'in_progress' ? 'selected' : '' ?>>En Progreso</option>
                        <option value="done" <?= $task->status === 'done' ? 'selected' : '' ?>>Completada</option>
                    </select>
                </div>

                <div>
                    <label for="priority" class="block text-sm font-medium text-gray-700 mb-2">Prioridad</label>
                    <select id="priority"
                        name="priority"
                        class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                        <option value="low" <?= $task->priority === 'low' ? 'selected' : '' ?>>Baja</option>
                        <option value="medium" <?= $task->priority === 'medium' ? 'selected' : '' ?>>Media</option>
                        <option value="high" <?= $task->priority === 'high' ? 'selected' : '' ?>>Alta</option>
                        <option value="urgent" <?= $task->priority === 'urgent' ? 'selected' : '' ?>>Urgente</option>
                    </select>
                </div>

                <div>
                    <label for="due_date" class="block text-sm font-medium text-gray-700 mb-2">Fecha de vencimiento</label>
                    <input type="date"
                        id="due_date"
                        name="due_date"
                        value="<?= $task->due_date ? date('Y-m-d', strtotime($task->due_date)) : '' ?>"
                        class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                </div>

                <!-- Etiquetas -->
                <div class="md:col-span-2">
                    <h3 class="text-lg font-medium text-gray-900 mb-4 mt-6">Etiquetas</h3>
                    <p class="text-sm text-gray-600 mb-4">Selecciona las etiquetas que se aplicarán a esta tarea</p>

                    <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                        <?php foreach ($labels as $label): ?>
                            <label class="flex items-center p-3 border border-gray-200 rounded-lg hover:bg-gray-50 cursor-pointer">
                                <input type="checkbox"
                                    name="labels[]"
                                    value="<?= $label->id ?>"
                                    <?= in_array($label->id, $taskLabels ?? []) ? 'checked' : '' ?>
                                    class="mr-3 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                                <div class="flex items-center flex-1">
                                    <div class="w-3 h-3 rounded-full mr-2" style="background-color: <?= htmlspecialchars($label->color) ?>"></div>
                                    <span class="text-sm font-medium"><?= htmlspecialchars($label->name) ?></span>
                                </div>
                            </label>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>

            <!-- Información adicional -->
            <div class="mt-8 pt-6 border-t border-gray-200">
                <div class="grid grid-cols-2 gap-4 text-sm text-gray-500">
                    <div>
                        <strong>Creada:</strong> <?= date('d/m/Y H:i', strtotime($task->created_at)) ?>
                    </div>
                    <div>
                        <strong>Actualizada:</strong> <?= date('d/m/Y H:i', strtotime($task->updated_at)) ?>
                    </div>
                </div>
            </div>

            <!-- Botones de acción -->
            <div class="flex items-center justify-end space-x-3 mt-6">
                <a href="?action=tasks" class="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50 transition-colors">
                    Cancelar
                </a>
                <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
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
