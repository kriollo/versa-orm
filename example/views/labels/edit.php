<?php

/**
 * Vista para editar una etiqueta existente.
 */
?>

<div class="max-w-2xl mx-auto">
    <!-- Header -->
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900 dark:text-white transition-colors">Editar Etiqueta</h1>
            <p class="text-gray-600 dark:text-gray-300 transition-colors">Modifica la información de la etiqueta</p>
        </div>
        <a href="?action=labels" class="text-gray-600 hover:text-gray-800 dark:text-gray-300 dark:hover:text-gray-100 transition-colors">
            <i class="fas fa-arrow-left mr-2"></i>
            Volver a Etiquetas
        </a>
    </div>

    <!-- Formulario -->
    <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6 border border-transparent dark:border-gray-700 transition-colors">
        <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700 transition-colors">
            <h2 class="text-lg font-semibold text-gray-900 dark:text-white transition-colors">Información de la Etiqueta</h2>
        </div>

        <form method="POST" action="?action=label_edit&id=<?php echo $label->id; ?>" class="p-6">
            <!-- Nombre -->
            <div class="mb-6">
                <label for="name" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">
                    Nombre <span class="text-red-500">*</span>
                </label>
                <input
                    type="text"
                    id="name"
                    name="name"
                    value="<?php echo htmlspecialchars($label->name ?? ''); ?>"
                    class="w-full border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                    required
                    maxlength="50"
                    placeholder="Ej: Urgente, Backend, Frontend, etc.">
                <p class="mt-1 text-sm text-gray-500 dark:text-gray-400 transition-colors">Máximo 50 caracteres</p>
            </div>

            <!-- Color -->
            <div class="mb-6">
                <label for="color" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">
                    Color <span class="text-red-500">*</span>
                </label>
                <div class="flex items-center space-x-4">
                    <input
                        type="color"
                        id="color"
                        name="color"
                        value="<?php echo htmlspecialchars($label->color ?? '#3498db'); ?>"
                        class="h-10 w-20 border border-gray-300 dark:border-gray-600 rounded cursor-pointer bg-white dark:bg-gray-700 transition-colors"
                        required>
                    <div class="flex-1">
                        <div class="flex items-center space-x-3">
                            <span
                                id="color-preview"
                                class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium"
                                style="background-color: <?php echo htmlspecialchars($label->color ?? '#3498db'); ?>20; color: <?php echo htmlspecialchars($label->color ?? '#3498db'); ?>">
                                <div class="w-2 h-2 rounded-full mr-2" style="background-color: <?php echo htmlspecialchars($label->color ?? '#3498db'); ?>"></div>
                                <span id="preview-text"><?php echo htmlspecialchars($label->name ?? 'Vista previa'); ?></span>
                            </span>
                            <p class="mt-1 text-sm text-gray-500 dark:text-gray-400 transition-colors">Vista previa de cómo se verá la etiqueta</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Colores predefinidos -->
            <div class="mb-6">
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-3 transition-colors">Colores Sugeridos</label>
                <div class="grid grid-cols-8 gap-2">
                    <?php
                    $suggestedColors = [
                        '#E74C3C',
                        '#E67E22',
                        '#F39C12',
                        '#F1C40F',
                        '#2ECC71',
                        '#1ABC9C',
                        '#3498DB',
                        '#9B59B6',
                        '#34495E',
                        '#95A5A6',
                        '#E91E63',
                        '#FF5722',
                    ];

foreach ($suggestedColors as $suggestedColor) {
    ?>
                        <button
                            type="button"
                            class="w-8 h-8 rounded border-2 border-gray-300 dark:border-gray-600 hover:border-gray-400 dark:hover:border-gray-500 transition-colors"
                            style="background-color: <?php echo $suggestedColor; ?>"
                            onclick="selectColor('<?php echo $suggestedColor; ?>')"
                            title="<?php echo $suggestedColor; ?>"></button>
                    <?php } ?>
                </div>
            </div>

            <!-- Descripción -->
            <div class="mb-6">
                <label for="description" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">
                    Descripción
                </label>
                <textarea
                    id="description"
                    name="description"
                    rows="3"
                    class="w-full border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                    placeholder="Descripción opcional de la etiqueta..."><?php echo htmlspecialchars($label->description ?? ''); ?></textarea>
                <p class="mt-1 text-sm text-gray-500 dark:text-gray-400 transition-colors">Opcional: describe el propósito de esta etiqueta</p>
            </div>

            <!-- Información del sistema -->
            <div class="mb-6 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 transition-colors">
                <h3 class="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">Información del Sistema</h3>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-gray-600 dark:text-gray-400 transition-colors">
                    <div>
                        <span class="font-medium">ID:</span> <?php echo $label->id; ?>
                    </div>
                    <div>
                        <span class="font-medium">Tareas asignadas:</span> <?php echo $label->tasks_count ?? 0; ?>
                    </div>
                    <div>
                        <span class="font-medium">Creada:</span>
                        <?php echo safe_date_format($label->created_at, 'd/m/Y H:i'); ?>
                    </div>
                    <div>
                        <span class="font-medium">Actualizada:</span>
                        <?php echo safe_date_format($label->updated_at, 'd/m/Y H:i'); ?>
                    </div>
                </div>
            </div>

            <!-- Botones -->
            <div class="flex items-center justify-between pt-6 border-t border-gray-200 dark:border-gray-700 transition-colors">
                <div>
                    <a href="?action=label_delete&id=<?php echo $label->id; ?>"
                        class="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded dark:hover:bg-red-500 transition-colors"
                        onclick="return confirm('¿Estás seguro de que deseas eliminar esta etiqueta? Esta acción no se puede deshacer.')">
                        <i class="fas fa-trash mr-2"></i>Eliminar Etiqueta
                    </a>
                </div>
                <div class="flex space-x-3">
                    <a href="?action=labels"
                        class="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded dark:hover:bg-gray-600 transition-colors">
                        Cancelar
                    </a>
                    <button type="submit"
                        class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded dark:hover:bg-blue-500 transition-colors">
                        <i class="fas fa-save mr-2"></i>Guardar Cambios
                    </button>
                </div>
            </div>
        </form>
    </div>
</div>

<script>
    // Función para seleccionar color predefinido
    function selectColor(color) {
        const colorInput = document.getElementById('color');
        colorInput.value = color;
        updatePreview();
    }

    // Actualizar vista previa en tiempo real
    function updatePreview() {
        const color = document.getElementById('color').value;
        const name = document.getElementById('name').value || 'Vista previa';
        const preview = document.getElementById('color-preview');
        const previewText = document.getElementById('preview-text');
        const colorDot = preview.querySelector('.w-2');

        if (preview && colorDot && previewText) {
            preview.style.backgroundColor = color + '20';
            preview.style.color = color;
            colorDot.style.backgroundColor = color;
            previewText.textContent = name;
        }
    }

    // Event listeners
    document.getElementById('color').addEventListener('input', updatePreview);
    document.getElementById('name').addEventListener('input', updatePreview);

    // Inicializar vista previa
    document.addEventListener('DOMContentLoaded', updatePreview);
</script>
