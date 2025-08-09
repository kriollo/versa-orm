<?php $title = 'Crear Proyecto - VersaORM Trello Demo'; ?>

<div class="max-w-2xl mx-auto">
    <div class="mb-8">
        <a href="?action=projects" class="inline-flex items-center text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium mb-4 transition-colors">
            <i class="fas fa-arrow-left mr-2"></i>
            Volver a proyectos
        </a>

        <h1 class="text-3xl font-bold text-gray-900 dark:text-white mb-2 transition-colors">Crear Nuevo Proyecto</h1>
        <p class="text-gray-600 dark:text-gray-300 transition-colors">Configura los detalles de tu nuevo proyecto</p>
    </div>

    <div class="bg-white dark:bg-gray-800 shadow rounded-lg border border-transparent dark:border-gray-700 transition-colors">
        <form method="POST" class="p-6 space-y-6">
            <!-- Nombre del proyecto -->
            <div>
                <label for="name" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">
                    Nombre del Proyecto *
                </label>
                <input type="text"
                    name="name"
                    id="name"
                    required
                    class="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                    placeholder="Ej: Sistema de Gestión"
                    value="<?= htmlspecialchars($_POST['name'] ?? '') ?>">
            </div>

            <!-- Descripción -->
            <div>
                <label for="description" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">
                    Descripción
                </label>
                <textarea name="description"
                    id="description"
                    rows="4"
                    class="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                    placeholder="Describe el propósito y objetivos del proyecto..."><?= htmlspecialchars($_POST['description'] ?? '') ?></textarea>
            </div>

            <!-- Color del proyecto -->
            <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">
                    Color del Proyecto
                </label>
                <div class="flex flex-wrap gap-3" x-data="{ selectedColor: '<?= $_POST['color'] ?? '#3498db' ?>' }">
                    <?php
                    $colors = [
                        '#e74c3c' => 'Rojo',
                        '#3498db' => 'Azul',
                        '#2ecc71' => 'Verde',
                        '#f39c12' => 'Naranja',
                        '#9b59b6' => 'Púrpura',
                        '#1abc9c' => 'Turquesa',
                        '#e67e22' => 'Naranja oscuro',
                        '#34495e' => 'Gris oscuro',
                        '#95a5a6' => 'Gris',
                        '#16a085' => 'Verde mar',
                    ];
                    ?>
                    <?php foreach ($colors as $color => $name): ?>
                        <label class="flex items-center cursor-pointer">
                            <input type="radio"
                                name="color"
                                value="<?= $color ?>"
                                <?= ($_POST['color'] ?? '#3498db') === $color ? 'checked' : '' ?>
                                class="sr-only"
                                x-model="selectedColor">
                            <div class="w-8 h-8 rounded-full border-2 border-transparent hover:border-gray-300 dark:hover:border-gray-500 transition-colors"
                                style="background-color: <?= $color ?>"
                                :class="selectedColor === '<?= $color ?>' ? 'ring-2 ring-offset-2 ring-gray-400' : ''"
                                title="<?= $name ?>">
                            </div>
                        </label>
                    <?php endforeach; ?>
                </div>
            </div>

            <!-- Propietario del proyecto -->
            <div>
                <label for="owner_id" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">
                    Propietario del Proyecto *
                </label>
                <select name="owner_id"
                    id="owner_id"
                    required
                    class="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors">
                    <option value="">Selecciona un propietario</option>
                    <?php foreach ($users as $user): ?>
                        <option value="<?= $user->id ?>" <?= ($_POST['owner_id'] ?? '') == $user->id ? 'selected' : '' ?>>
                            <?= htmlspecialchars($user->name) ?> (<?= htmlspecialchars($user->email) ?>)
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <!-- Vista previa -->
            <div x-data="{ previewName: '<?= htmlspecialchars($_POST['name'] ?? 'Nombre del Proyecto') ?>', previewColor: '<?= $_POST['color'] ?? '#3498db' ?>' }">
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">
                    Vista Previa
                </label>
                <div class="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden transition-colors">
                    <div class="h-16" :style="`background: linear-gradient(135deg, ${previewColor}, ${previewColor}80)`">
                        <div class="p-4 h-full flex items-end">
                            <h3 class="text-white font-bold text-lg" x-text="previewName || 'Nombre del Proyecto'"></h3>
                        </div>
                    </div>
                    <div class="p-4 bg-gray-50 dark:bg-gray-900 transition-colors">
                        <p class="text-sm text-gray-600 dark:text-gray-400 transition-colors">Vista previa del proyecto</p>
                    </div>
                </div>
            </div>

            <!-- Botones de acción -->
            <div class="flex items-center justify-between pt-6 border-t border-gray-200 dark:border-gray-700 transition-colors">
                <div class="text-sm text-gray-500 dark:text-gray-400">
                    * Campos requeridos
                </div>
                <div class="flex items-center space-x-3">
                    <a href="?action=projects" class="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                        Cancelar
                    </a>
                    <button type="submit" class="px-6 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 dark:hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors">
                        <i class="fas fa-plus mr-2"></i>
                        Crear Proyecto
                    </button>
                </div>
            </div>
        </form>
    </div>
</div>

<script>
    // Actualizar vista previa en tiempo real
    document.addEventListener('DOMContentLoaded', function() {
        const nameInput = document.getElementById('name');
        const colorInputs = document.querySelectorAll('input[name="color"]');

        nameInput.addEventListener('input', function() {
            const previewName = document.querySelector('[x-text]');
            if (previewName) {
                previewName.textContent = this.value || 'Nombre del Proyecto';
            }
        });

        colorInputs.forEach(input => {
            input.addEventListener('change', function() {
                const preview = document.querySelector('[x-bind\\:style]');
                if (preview && this.checked) {
                    preview.style.background = `linear-gradient(135deg, ${this.value}, ${this.value}80)`;
                }
            });
        });
    });
</script>
