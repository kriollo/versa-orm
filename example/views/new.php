<?php
// Vista: Crear nueva tarea
ob_start();
?>
<!-- Navegación de regreso -->
<div class="mb-6">
    <?php if (isset($_GET['project_id'])): ?>
        <a href="?action=show_project&id=<?= htmlspecialchars($_GET['project_id']) ?>" class="inline-flex items-center text-blue-600 hover:text-blue-800 font-medium">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
            </svg>
            Volver al proyecto
        </a>
    <?php else: ?>
        <a href="?action=projects" class="inline-flex items-center text-blue-600 hover:text-blue-800 font-medium">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
            </svg>
            Volver a proyectos
        </a>
    <?php endif; ?>
</div>

<div class="max-w-2xl mx-auto">
    <div class="bg-white shadow-xl rounded-lg overflow-hidden">
        <!-- Header -->
        <div class="bg-gradient-to-r from-indigo-600 to-purple-600 px-6 py-6">
            <h1 class="text-3xl font-bold text-white flex items-center">
                <svg class="w-8 h-8 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
                </svg>
                Crear Nueva Tarea
            </h1>
            <p class="text-indigo-100 mt-2">
                <?php if (isset($_GET['project_id'])): ?>
                    Añade una nueva tarea a este proyecto
                <?php else: ?>
                    Organiza tu trabajo creando una nueva tarea
                <?php endif; ?>
            </p>
        </div>

        <!-- Formulario -->
        <form method="post" action="?action=create" class="p-6 space-y-6">
            <?php if (isset($_GET['project_id'])): ?>
                <input type="hidden" name="project_id" value="<?= htmlspecialchars($_GET['project_id']) ?>">
                <!-- Mostrar información del proyecto -->
                <div class="bg-blue-50 border-l-4 border-blue-500 p-4 mb-4">
                    <div class="flex items-center">
                        <svg class="w-5 h-5 text-blue-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                        </svg>
                        <span class="text-sm font-medium text-blue-800">Esta tarea será añadida al proyecto seleccionado</span>
                    </div>
                </div>
            <?php else: ?>
                <!-- Selector de proyecto -->
                <div>
                    <label class="block text-sm font-medium text-gray-700 mb-2">
                        <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                        </svg>
                        Proyecto (Opcional)
                    </label>
                    <select name="project_id" class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition duration-200">
                        <option value="">-- Sin proyecto asignado --</option>
                        <?php
                        // Obtener proyectos disponibles
                        try {
                            $projects = \Example\Models\Project::allArray();
                            foreach ($projects as $project): ?>
                                <option value="<?= $project['id'] ?>"><?= htmlspecialchars($project['name']) ?></option>
                        <?php endforeach;
                        } catch (Exception $e) {
                            // Si no hay proyectos o hay error, no mostrar nada
                        }
                        ?>
                    </select>
                    <p class="text-xs text-gray-500 mt-1">Puedes crear tareas sin asignar a un proyecto específico</p>
                </div>
            <?php endif; ?>

            <!-- Título de la tarea -->
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">
                    <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
                    </svg>
                    Título de la Tarea *
                </label>
                <input type="text" name="title" required
                    class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition duration-200"
                    placeholder="Ej: Implementar sistema de autenticación"
                    maxlength="255">
                <p class="text-xs text-gray-500 mt-1">Sé específico y descriptivo</p>
            </div>

            <!-- Descripción -->
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">
                    <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    Descripción Detallada
                </label>
                <textarea name="description" rows="4"
                    class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition duration-200"
                    placeholder="Describe los pasos, requisitos o detalles importantes de esta tarea..."></textarea>
                <p class="text-xs text-gray-500 mt-1">Opcional - Los detalles ayudan a recordar el contexto</p>
            </div>

            <!-- Estado de completado -->
            <div class="bg-gray-50 rounded-lg p-4">
                <div class="flex items-center">
                    <input type="checkbox" name="completed" id="completed"
                        class="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded">
                    <label for="completed" class="ml-3 block text-sm font-medium text-gray-700">
                        <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        Marcar como completada
                    </label>
                </div>
                <p class="text-xs text-gray-500 mt-1 ml-7">Generalmente las tareas se crean como pendientes</p>
            </div>

            <!-- Botones de acción -->
            <div class="flex justify-end space-x-3 pt-6 border-t border-gray-200">
                <?php if (isset($_GET['project_id'])): ?>
                    <a href="?action=show_project&id=<?= htmlspecialchars($_GET['project_id']) ?>" class="inline-flex items-center px-6 py-3 border border-gray-300 rounded-lg text-gray-700 bg-white hover:bg-gray-50 font-medium transition duration-200">
                        <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                        Cancelar
                    </a>
                <?php else: ?>
                    <a href="?action=projects" class="inline-flex items-center px-6 py-3 border border-gray-300 rounded-lg text-gray-700 bg-white hover:bg-gray-50 font-medium transition duration-200">
                        <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                        Cancelar
                    </a>
                <?php endif; ?>
                <button type="submit" class="inline-flex items-center px-6 py-3 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg font-medium transition duration-200 shadow-lg">
                    <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                    </svg>
                    Crear Tarea
                </button>
            </div>
        </form>
    </div>

    <!-- Tips -->
    <div class="mt-6 bg-indigo-50 border border-indigo-200 rounded-lg p-4">
        <div class="flex items-start">
            <svg class="w-5 h-5 text-indigo-600 mt-0.5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
                <h3 class="text-sm font-medium text-indigo-900">Consejos para crear buenas tareas</h3>
                <ul class="text-sm text-indigo-700 mt-1 space-y-1">
                    <li>• Usa títulos claros y específicos</li>
                    <li>• Divide tareas grandes en subtareas más pequeñas</li>
                    <li>• Incluye detalles importantes en la descripción</li>
                    <li>• Asigna tareas a proyectos para mejor organización</li>
                </ul>
            </div>
        </div>
    </div>
</div>

<script>
    // Agregar funcionalidad adicional si es necesaria
    document.addEventListener('DOMContentLoaded', function() {
        const titleInput = document.querySelector('input[name="title"]');
        const form = document.querySelector('form');

        // Focus automático en el título
        if (titleInput) {
            titleInput.focus();
        }

        // Prevenir envío con título vacío
        form.addEventListener('submit', function(e) {
            if (!titleInput.value.trim()) {
                e.preventDefault();
                titleInput.focus();
                titleInput.classList.add('border-red-500');
                setTimeout(() => titleInput.classList.remove('border-red-500'), 3000);
            }
        });
    });

    function confirmDelete() {
        return confirm('¿Estás seguro de que quieres eliminar este proyecto?\n\nEsta acción no se puede deshacer y eliminará todas las tareas asociadas.');
    }
</script>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
