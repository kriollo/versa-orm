<?php
// Vista: Editar tarea
ob_start();
?>
<!-- Navegación de regreso -->
<div class="mb-6">
    <a href="?action=list" class="inline-flex items-center text-blue-600 hover:text-blue-800 font-medium">
        <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
        </svg>
        Volver a tareas
    </a>
</div>

<div class="max-w-2xl mx-auto">
    <div class="bg-white shadow-xl rounded-lg overflow-hidden">
        <!-- Header -->
        <div class="bg-gradient-to-r from-green-600 to-emerald-600 px-6 py-6">
            <h1 class="text-3xl font-bold text-white flex items-center">
                <svg class="w-8 h-8 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                </svg>
                Editar Tarea
            </h1>
            <p class="text-green-100 mt-2">Modifica los detalles de la tarea</p>
        </div>

        <!-- Formulario principal -->
        <form method="post" action="?action=update" class="p-6 space-y-6">
            <input type="hidden" name="id" value="<?= is_array($task) ? $task['id'] : $task->id ?>" />

            <!-- Título -->
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">
                    <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 8h10M7 12h4m1 8l-4-4H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-3l-4 4z" />
                    </svg>
                    Título de la tarea *
                </label>
                <input type="text" name="title"
                    value="<?= htmlspecialchars(is_array($task) ? $task['title'] : $task->title) ?>"
                    required
                    class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-green-500 transition duration-200"
                    placeholder="Ingresa el título de la tarea"
                    maxlength="255">
            </div>

            <!-- Descripción -->
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">
                    <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    Descripción
                </label>
                <textarea name="description" rows="4"
                    class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-green-500 transition duration-200 resize-none"
                    placeholder="Describe los detalles de la tarea..."><?= htmlspecialchars(is_array($task) ? $task['description'] : $task->description) ?></textarea>
                <p class="text-xs text-gray-500 mt-1">Proporciona detalles adicionales sobre la tarea (opcional)</p>
            </div>

            <!-- Estado de completitud -->
            <div class="bg-gray-50 rounded-lg p-4">
                <label class="flex items-center cursor-pointer">
                    <div class="relative">
                        <input type="checkbox" name="completed" id="completed"
                            <?= (is_array($task) ? $task['completed'] : $task->completed) ? 'checked' : '' ?>
                            class="sr-only">
                        <div class="toggle-bg bg-gray-200 border-2 border-gray-200 w-9 h-5 rounded-full"></div>
                        <div class="toggle-dot absolute w-4 h-4 bg-white rounded-full shadow transition-transform duration-300 ease-in-out top-0.5 left-0.5"></div>
                    </div>
                    <div class="ml-3">
                        <span class="text-sm font-medium text-gray-900">Estado de la tarea</span>
                        <div class="text-xs text-gray-500">
                            <span class="incomplete-text">Marcar como completada</span>
                            <span class="complete-text hidden">Tarea completada</span>
                        </div>
                    </div>
                </label>
            </div>

            <!-- Botones de acción -->
            <div class="flex justify-between items-center pt-6 border-t border-gray-200">
                <div>
                    <a href="?view=task_labels_edit&task_id=<?= is_array($task) ? $task['id'] : $task->id ?>"
                        class="inline-flex items-center px-4 py-2 bg-purple-100 hover:bg-purple-200 text-purple-700 rounded-lg font-medium transition duration-200">
                        <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
                        </svg>
                        Gestionar Etiquetas
                    </a>
                </div>
                <div class="flex space-x-3">
                    <a href="?action=list" class="inline-flex items-center px-6 py-3 border border-gray-300 rounded-lg text-gray-700 bg-white hover:bg-gray-50 font-medium transition duration-200">
                        <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                        Cancelar
                    </a>
                    <button type="submit" class="inline-flex items-center px-6 py-3 bg-green-600 hover:bg-green-700 text-white rounded-lg font-medium transition duration-200 shadow-lg">
                        <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                        </svg>
                        Actualizar Tarea
                    </button>
                </div>
            </div>
        </form>
    </div>

    <!-- Panel de información -->
    <div class="mt-6 bg-green-50 border border-green-200 rounded-lg p-4">
        <div class="flex items-start">
            <svg class="w-5 h-5 text-green-600 mt-0.5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
                <h3 class="text-sm font-medium text-green-900">Opciones de edición</h3>
                <div class="text-sm text-green-700 mt-1">
                    <p>• Usa "Gestionar Etiquetas" para organizar tu tarea con etiquetas</p>
                    <p>• Marca como completada cuando hayas terminado la tarea</p>
                    <p>• La descripción es opcional pero ayuda a recordar detalles importantes</p>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
    /* Toggle switch styling */
    input:checked+.toggle-bg {
        @apply bg-green-500 border-green-500;
    }

    input:checked+.toggle-bg .toggle-dot {
        @apply transform translate-x-4;
    }

    /* Conditional text display */
    input:checked~* .incomplete-text {
        @apply hidden;
    }

    input:checked~* .complete-text {
        @apply block;
    }

    input:not(:checked)~* .complete-text {
        @apply hidden;
    }

    input:not(:checked)~* .incomplete-text {
        @apply block;
    }
</style>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        const titleInput = document.querySelector('input[name="title"]');
        const toggleCheckbox = document.getElementById('completed');
        const form = document.querySelector('form');

        // Focus automático en el título
        if (titleInput) {
            titleInput.focus();
            titleInput.setSelectionRange(titleInput.value.length, titleInput.value.length);
        }

        // Manejar el toggle switch visual
        function updateToggleState() {
            const toggleBg = document.querySelector('.toggle-bg');
            const toggleDot = document.querySelector('.toggle-dot');
            const incompleteText = document.querySelector('.incomplete-text');
            const completeText = document.querySelector('.complete-text');

            if (toggleCheckbox.checked) {
                toggleBg.classList.add('bg-green-500', 'border-green-500');
                toggleBg.classList.remove('bg-gray-200', 'border-gray-200');
                toggleDot.classList.add('translate-x-4');
                incompleteText.classList.add('hidden');
                completeText.classList.remove('hidden');
            } else {
                toggleBg.classList.remove('bg-green-500', 'border-green-500');
                toggleBg.classList.add('bg-gray-200', 'border-gray-200');
                toggleDot.classList.remove('translate-x-4');
                completeText.classList.add('hidden');
                incompleteText.classList.remove('hidden');
            }
        }

        // Inicializar estado del toggle
        updateToggleState();

        // Escuchar cambios en el checkbox
        toggleCheckbox.addEventListener('change', updateToggleState);

        // Click en el área del toggle
        document.querySelector('.toggle-bg').addEventListener('click', function() {
            toggleCheckbox.checked = !toggleCheckbox.checked;
            updateToggleState();
        });

        // Validación antes del envío
        form.addEventListener('submit', function(e) {
            const title = titleInput.value.trim();

            if (!title) {
                e.preventDefault();
                titleInput.classList.add('border-red-500');
                titleInput.focus();
                return;
            }

            titleInput.classList.remove('border-red-500');
        });
    });
</script>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
