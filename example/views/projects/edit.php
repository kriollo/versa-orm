<?php

use VersaORM\VersaORMException;

// Vista para editar un proyecto existente.

// Verifica que $project esté definido y es un objeto válido
if (!isset($project) || !is_object($project)) {
    throw new VersaORMException(
        'El proyecto no está definido. Asegúrate de cargar el modelo antes de mostrar la vista.',
    );
}
?>

<div class="max-w-4xl mx-auto">
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900 dark:text-white transition-colors">Editar Proyecto</h1>
            <p class="text-gray-600 dark:text-gray-300 transition-colors">Modifica la información del proyecto</p>
        </div>
        <a href="?action=project_show&id=<?php echo $project->id; ?>" class="text-gray-600 hover:text-gray-800 dark:text-gray-300 dark:hover:text-gray-100 transition-colors">
            <i class="fas fa-arrow-left mr-2"></i>
            Volver al Proyecto
        </a>
    </div>

    <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6 border border-transparent dark:border-gray-700 transition-colors">
        <form method="POST" action="?action=project_edit&id=<?php echo $project->id; ?>">
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <!-- Información del proyecto -->
                <div class="lg:col-span-2 space-y-6">
                    <div>
                        <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4 transition-colors">Información del Proyecto</h3>

                        <div class="space-y-4">
                            <div>
                                <label for="name" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">
                                    Nombre del proyecto <span class="text-red-500">*</span>
                                </label>
                                <input type="text"
                                    id="name"
                                    name="name"
                                    required
                                    value="<?php echo htmlspecialchars($project->name); ?>"
                                    class="w-full border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                                    placeholder="Ingresa el nombre del proyecto">
                            </div>

                            <div>
                                <label for="description" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">Descripción</label>
                                <textarea id="description"
                                    name="description"
                                    rows="4"
                                    class="w-full border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                                    placeholder="Describe el propósito y objetivos del proyecto..."><?php echo
                                        htmlspecialchars($project->description ?? '')
                                    ; ?></textarea>
                            </div>
                        </div>
                    </div>

                    <!-- Color del proyecto -->
                    <div>
                        <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4 transition-colors">Personalización</h3>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-3 transition-colors">Color del proyecto</label>
                            <div class="flex flex-wrap gap-3" x-data="{ selectedColor: '<?php echo $project->color; ?>' }">

                                <?php

                                $colors = [
                                    '#3498db',
                                    '#e74c3c',
                                    '#2ecc71',
                                    '#f39c12',
                                    '#9b59b6',
                                    '#1abc9c',
                                    '#34495e',
                                    '#e67e22',
                                    '#95a5a6',
                                    '#f1c40f',
                                ];

                                foreach ($colors as $color) { ?>
                                    <label class="cursor-pointer">
                                        <input type="radio"
                                            name="color"
                                            value="<?php echo $color; ?>"
                                            <?php echo $project->color === $color ? 'checked' : ''; ?>
                                            class="sr-only peer"
                                            x-model="selectedColor">
                                        <div class="w-8 h-8 rounded-full border-2 border-transparent peer-checked:border-gray-400 peer-checked:ring-2 peer-checked:ring-blue-500 hover:scale-110 transition-transform dark:hover:border-gray-500"
                                            style="background-color: <?php echo $color; ?>"></div>
                                    </label>
                                <?php } ?>
                            </div>
                        </div>
                    </div>

                    <!-- Propietario -->
                    <div>
                        <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4 transition-colors">Asignación</h3>

                        <div>
                            <label for="owner_id" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">
                                Propietario del proyecto <span class="text-red-500">*</span>
                            </label>
                            <select id="owner_id"
                                name="owner_id"
                                required
                                class="w-full border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors">
                                <option value="">Selecciona un propietario</option>

                                <?php foreach ($users as $user) { ?>
                                    <option value="<?php echo $user->id; ?>" <?php echo
                                        $project->owner_id === $user->id ? 'selected' : ''
                                    ; ?>>
                                        <?php echo htmlspecialchars($user->name); ?> (<?php echo
                                            htmlspecialchars($user->email)
                                        ; ?>)
                                    </option>
                                <?php } ?>
                            </select>
                        </div>
                    </div>
                </div>

                <!-- Vista previa -->
                <div class="lg:col-span-1">
                    <div class="sticky top-6">
                        <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4 transition-colors">Vista Previa</h3>
                        <div x-data="{ previewName: '<?php echo htmlspecialchars($project->name); ?>', previewColor: '<?php echo
                            $project->color
                        ; ?>' }">
                            <div class="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6 transition-colors bg-white dark:bg-gray-900">
                                <div class="flex items-center mb-4">
                                    <div class="w-4 h-4 rounded-full mr-3"
                                        :style="'background-color: ' + previewColor"></div>
                                    <h4 class="font-semibold text-gray-900 dark:text-gray-100 transition-colors" x-text="previewName || 'Nombre del Proyecto'"></h4>
                                </div>
                                <div class="text-sm text-gray-500 dark:text-gray-400 space-y-2 transition-colors">
                                    <p><i class="fas fa-user mr-2"></i>Propietario:

                                        <?php

                                        $owner = array_filter(
                                            $users,
                                            static fn($u): bool => $u->id === $project->owner_id,
                                        );
                                        echo $owner !== [] ? htmlspecialchars(current($owner)->name) : 'Sin asignar';
                                        ?>
                                    </p>
                                    <p><i class="fas fa-calendar mr-2"></i>Creado: <?php echo
                                        isset($project->created_at) ? safe_date('M Y', $project->created_at) : ''
                                    ; ?></p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Información adicional -->
            <div class="mt-8 pt-6 border-t border-gray-200 dark:border-gray-700 transition-colors">
                <div class="grid grid-cols-3 gap-4 text-sm text-gray-500 dark:text-gray-400 transition-colors">

                    <div>
                        <strong>Creado:</strong> <?php echo
                            isset($project->created_at) ? safe_date('d/m/Y H:i', $project->created_at) : ''
                        ; ?>
                    </div>
                    <div>
                        <strong>Actualizado:</strong> <?php echo
                            isset($project->updated_at) ? safe_date('d/m/Y H:i', $project->updated_at) : ''
                        ; ?>
                    </div>
                    <div>
                        <strong>ID:</strong> #<?php echo $project->id; ?>
                    </div>
                </div>
            </div>

            <!-- Botones de acción -->
            <div class="mt-8 flex items-center justify-between">
                <button type="button"
                    onclick="if(confirm('¿Estás seguro de que quieres eliminar este proyecto? Esta acción eliminará también todas las tareas asociadas.')) { window.location.href = '?action=project_delete&id=<?php echo
                        $project->id
                    ; ?>'; }"
                    class="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700 dark:hover:bg-red-500 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 transition-colors">
                    <i class="fas fa-trash mr-2"></i>
                    Eliminar Proyecto
                </button>

                <div class="flex items-center space-x-3">
                    <a href="?action=project_show&id=<?php echo $project->id; ?>"
                        class="px-4 py-2 rounded-md border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition-colors">
                        Cancelar
                    </a>
                    <button type="submit"
                        class="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700 dark:hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors">
                        <i class="fas fa-save mr-2"></i>
                        Guardar Cambios
                    </button>
                </div>
            </div>
        </form>
    </div>
</div>

<script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js"></script>
