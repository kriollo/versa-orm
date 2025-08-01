<?php
// Vista: Editar proyecto
ob_start();
?>
<!-- Navegación de regreso -->
<div class="mb-6">
    <a href="?action=show_project&id=<?= is_array($project) ? $project['id'] : $project->id ?>" class="inline-flex items-center text-blue-600 hover:text-blue-800 font-medium">
        <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
        </svg>
        Volver al proyecto
    </a>
</div>

<div class="max-w-2xl mx-auto">
    <div class="bg-white shadow-xl rounded-lg overflow-hidden">
        <!-- Header -->
        <div class="bg-gradient-to-r from-blue-600 to-purple-600 px-6 py-6">
            <h1 class="text-3xl font-bold text-white flex items-center">
                <svg class="w-8 h-8 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                </svg>
                Editar Proyecto
            </h1>
            <p class="text-blue-100 mt-2">Modifica la información del proyecto</p>
        </div>

        <!-- Formulario -->
        <form method="post" action="?action=update_project" class="p-6 space-y-6">
            <input type="hidden" name="id" value="<?= is_array($project) ? $project['id'] : $project->id ?>" />

            <!-- Nombre del proyecto -->
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">
                    <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
                    </svg>
                    Nombre del proyecto *
                </label>
                <input type="text" name="name"
                    value="<?= htmlspecialchars(is_array($project) ? $project['name'] : $project->name) ?>"
                    required
                    class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-200"
                    placeholder="Nombre descriptivo del proyecto"
                    maxlength="255">
                <p class="text-xs text-gray-500 mt-1">Elige un nombre claro e identificativo</p>
            </div>

            <!-- Descripción -->
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">
                    <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    Descripción del proyecto
                </label>
                <textarea name="description" rows="4"
                    class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-200 resize-none"
                    placeholder="Describe los objetivos y alcance del proyecto..."><?= htmlspecialchars(is_array($project) ? $project['description'] : $project->description) ?></textarea>
                <p class="text-xs text-gray-500 mt-1">Información adicional sobre el proyecto (opcional)</p>
            </div>

            <!-- Selección de responsable -->
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">
                    <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                    </svg>
                    Responsable del proyecto
                </label>
                <div class="relative">
                    <select name="user_id" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-200 appearance-none">
                        <option value="">-- Selecciona un responsable --</option>
                        <?php foreach (($users ?? []) as $user): ?>
                            <option value="<?= $user['id'] ?>" <?= (isset($project->user_id) && $project->user_id == $user['id']) ? 'selected' : '' ?>>
                                <?= htmlspecialchars($user['name']) ?> (<?= htmlspecialchars($user['email']) ?>)
                            </option>
                        <?php endforeach; ?>
                    </select>
                    <div class="absolute inset-y-0 right-0 flex items-center px-2 pointer-events-none">
                        <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l4-4 4 4m0 6l-4 4-4-4" />
                        </svg>
                    </div>
                </div>
                <div class="mt-2">
                    <a href="?action=new_user" class="inline-flex items-center text-sm text-blue-600 hover:text-blue-800 font-medium">
                        <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                        </svg>
                        Crear nuevo usuario
                    </a>
                </div>
            </div>

            <!-- Información del proyecto -->
            <div class="bg-gray-50 rounded-lg p-4">
                <h3 class="text-sm font-medium text-gray-900 mb-2 flex items-center">
                    <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    Estado del proyecto
                </h3>
                <div class="text-sm text-gray-600">
                    <p>• El proyecto mantendrá su historial de tareas existentes</p>
                    <p>• Cambiar el responsable notificará al nuevo usuario asignado</p>
                    <p>• Todas las tareas asociadas permanecerán vinculadas al proyecto</p>
                </div>
            </div>

            <!-- Botones de acción -->
            <div class="flex justify-end space-x-3 pt-6 border-t border-gray-200">
                <a href="?action=show_project&id=<?= is_array($project) ? $project['id'] : $project->id ?>" class="inline-flex items-center px-6 py-3 border border-gray-300 rounded-lg text-gray-700 bg-white hover:bg-gray-50 font-medium transition duration-200">
                    <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                    Cancelar
                </a>
                <button type="submit" class="inline-flex items-center px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition duration-200 shadow-lg">
                    <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                    </svg>
                    Actualizar Proyecto
                </button>
            </div>
        </form>
    </div>

    <!-- Panel de ayuda -->
    <div class="mt-6 bg-blue-50 border border-blue-200 rounded-lg p-4">
        <div class="flex items-start">
            <svg class="w-5 h-5 text-blue-600 mt-0.5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
            <div>
                <h3 class="text-sm font-medium text-blue-900">Consejos para gestionar proyectos</h3>
                <div class="text-sm text-blue-700 mt-1">
                    <p>• Asigna un responsable que supervise el progreso del proyecto</p>
                    <p>• Usa descripciones claras para que todo el equipo comprenda los objetivos</p>
                    <p>• Los cambios se aplicarán inmediatamente tras la actualización</p>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        const nameInput = document.querySelector('input[name="name"]');
        const userSelect = document.querySelector('select[name="user_id"]');
        const form = document.querySelector('form');

        // Focus automático en el nombre
        if (nameInput) {
            nameInput.focus();
            nameInput.setSelectionRange(nameInput.value.length, nameInput.value.length);
        }

        // Mejorar el select con búsqueda visual
        userSelect.addEventListener('focus', function() {
            this.classList.add('ring-2', 'ring-blue-500', 'border-blue-500');
        });

        userSelect.addEventListener('blur', function() {
            this.classList.remove('ring-2', 'ring-blue-500', 'border-blue-500');
        });

        // Validación del formulario
        form.addEventListener('submit', function(e) {
            const name = nameInput.value.trim();

            if (!name) {
                e.preventDefault();
                nameInput.classList.add('border-red-500');
                nameInput.focus();

                // Mostrar mensaje de error temporal
                const errorMsg = document.createElement('p');
                errorMsg.className = 'text-red-500 text-xs mt-1';
                errorMsg.textContent = 'El nombre del proyecto es requerido';

                const existingError = nameInput.parentNode.querySelector('.text-red-500');
                if (!existingError) {
                    nameInput.parentNode.appendChild(errorMsg);
                    setTimeout(() => errorMsg.remove(), 3000);
                }

                return;
            }

            nameInput.classList.remove('border-red-500');
        });

        // Limpiar errores al escribir
        nameInput.addEventListener('input', function() {
            this.classList.remove('border-red-500');
            const errorMsg = this.parentNode.querySelector('.text-red-500');
            if (errorMsg) errorMsg.remove();
        });
    });
</script>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
