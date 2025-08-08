<?php

/**
 * Vista para editar un proyecto existente.
 */

// Verifica que $project esté definido y es un objeto válido
if (!isset($project) || !is_object($project)) {
    throw new \VersaORM\VersaORMException('El proyecto no está definido. Asegúrate de cargar el modelo antes de mostrar la vista.');
}
?>

<div class="max-w-4xl mx-auto">
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Editar Proyecto</h1>
            <p class="text-gray-600">Modifica la información del proyecto</p>
        </div>
        <a href="?action=project_show&id=<?= $project->id ?>" class="text-gray-600 hover:text-gray-800">
            <i class="fas fa-arrow-left mr-2"></i>
            Volver al Proyecto
        </a>
    </div>

    <div class="bg-white shadow rounded-lg p-6">
        <form method="POST" action="?action=project_edit&id=<?= $project->id ?>">
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <!-- Información del proyecto -->
                <div class="lg:col-span-2 space-y-6">
                    <div>
                        <h3 class="text-lg font-medium text-gray-900 mb-4">Información del Proyecto</h3>

                        <div class="space-y-4">
                            <div>
                                <label for="name" class="block text-sm font-medium text-gray-700 mb-2">
                                    Nombre del proyecto <span class="text-red-500">*</span>
                                </label>
                                <input type="text"
                                    id="name"
                                    name="name"
                                    required
                                    value="<?= htmlspecialchars($project->name) ?>"
                                    class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                    placeholder="Ingresa el nombre del proyecto">
                            </div>

                            <div>
                                <label for="description" class="block text-sm font-medium text-gray-700 mb-2">Descripción</label>
                                <textarea id="description"
                                    name="description"
                                    rows="4"
                                    class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                    placeholder="Describe el propósito y objetivos del proyecto..."><?= htmlspecialchars($project->description ?? '') ?></textarea>
                            </div>
                        </div>
                    </div>

                    <!-- Color del proyecto -->
                    <div>
                        <h3 class="text-lg font-medium text-gray-900 mb-4">Personalización</h3>

                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-3">Color del proyecto</label>
                            <div class="flex flex-wrap gap-3" x-data="{ selectedColor: '<?= $project->color ?>' }">
                                <?php
                                $colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c', '#34495e', '#e67e22', '#95a5a6', '#f1c40f'];
foreach ($colors as $color):
    ?>
                                    <label class="cursor-pointer">
                                        <input type="radio"
                                            name="color"
                                            value="<?= $color ?>"
                                            <?= $project->color === $color ? 'checked' : '' ?>
                                            class="sr-only peer"
                                            x-model="selectedColor">
                                        <div class="w-8 h-8 rounded-full border-2 border-transparent peer-checked:border-gray-400 peer-checked:ring-2 peer-checked:ring-blue-500 hover:scale-110 transition-transform"
                                            style="background-color: <?= $color ?>"></div>
                                    </label>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    </div>

                    <!-- Propietario -->
                    <div>
                        <h3 class="text-lg font-medium text-gray-900 mb-4">Asignación</h3>

                        <div>
                            <label for="owner_id" class="block text-sm font-medium text-gray-700 mb-2">
                                Propietario del proyecto <span class="text-red-500">*</span>
                            </label>
                            <select id="owner_id"
                                name="owner_id"
                                required
                                class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                                <option value="">Selecciona un propietario</option>
                                <?php foreach ($users as $user): ?>
                                    <option value="<?= $user->id ?>" <?= $project->owner_id == $user->id ? 'selected' : '' ?>>
                                        <?= htmlspecialchars($user->name) ?> (<?= htmlspecialchars($user->email) ?>)
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>
                </div>

                <!-- Vista previa -->
                <div class="lg:col-span-1">
                    <div class="sticky top-6">
                        <h3 class="text-lg font-medium text-gray-900 mb-4">Vista Previa</h3>
                        <div x-data="{ previewName: '<?= htmlspecialchars($project->name) ?>', previewColor: '<?= $project->color ?>' }">
                            <div class="border-2 border-dashed border-gray-300 rounded-lg p-6">
                                <div class="flex items-center mb-4">
                                    <div class="w-4 h-4 rounded-full mr-3"
                                        :style="'background-color: ' + previewColor"></div>
                                    <h4 class="font-semibold text-gray-900" x-text="previewName || 'Nombre del Proyecto'"></h4>
                                </div>
                                <div class="text-sm text-gray-500 space-y-2">
                                    <p><i class="fas fa-user mr-2"></i>Propietario:
                                        <?php
            $owner = array_filter($users, fn ($u) => $u->id == $project->owner_id);
echo $owner ? htmlspecialchars(current($owner)->name) : 'Sin asignar';
?>
                                    </p>
                                    <p><i class="fas fa-calendar mr-2"></i>Creado: <?= isset($project->created_at) ? safe_date('M Y', $project->created_at) : '' ?></p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Información adicional -->
            <div class="mt-8 pt-6 border-t border-gray-200">
                <div class="grid grid-cols-3 gap-4 text-sm text-gray-500">
                    <div>
                        <strong>Creado:</strong> <?= isset($project->created_at) ? safe_date('d/m/Y H:i', $project->created_at) : '' ?>
                    </div>
                    <div>
                        <strong>Actualizado:</strong> <?= isset($project->updated_at) ? safe_date('d/m/Y H:i', $project->updated_at) : '' ?>
                    </div>
                    <div>
                        <strong>ID:</strong> #<?= $project->id ?>
                    </div>
                </div>
            </div>

            <!-- Botones de acción -->
            <div class="mt-8 flex items-center justify-between">
                <button type="button"
                    onclick="if(confirm('¿Estás seguro de que quieres eliminar este proyecto? Esta acción eliminará también todas las tareas asociadas.')) { window.location.href = '?action=project_delete&id=<?= $project->id ?>'; }"
                    class="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 transition duration-200">
                    <i class="fas fa-trash mr-2"></i>
                    Eliminar Proyecto
                </button>

                <div class="flex items-center space-x-3">
                    <a href="?action=project_show&id=<?= $project->id ?>"
                        class="bg-gray-300 text-gray-700 px-4 py-2 rounded-md hover:bg-gray-400 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition duration-200">
                        Cancelar
                    </a>
                    <button type="submit"
                        class="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition duration-200">
                        <i class="fas fa-save mr-2"></i>
                        Guardar Cambios
                    </button>
                </div>
            </div>
        </form>
    </div>
</div>

<script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js"></script>
