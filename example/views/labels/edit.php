<?php

/**
 * Vista para editar una etiqueta existente.
 */
?>

<div class="max-w-2xl mx-auto">
    <!-- Header -->
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Editar Etiqueta</h1>
            <p class="text-gray-600">Modifica la información de la etiqueta</p>
        </div>
        <a href="?action=labels" class="text-gray-600 hover:text-gray-800">
            <i class="fas fa-arrow-left mr-2"></i>
            Volver a Etiquetas
        </a>
    </div>

    <!-- Formulario -->
    <div class="bg-white shadow rounded-lg">
        <div class="px-6 py-4 border-b border-gray-200">
            <h2 class="text-lg font-semibold text-gray-900">Información de la Etiqueta</h2>
        </div>

        <form method="POST" action="?action=label_edit&id=<?= $label->id ?>" class="p-6">
            <!-- Nombre -->
            <div class="mb-6">
                <label for="name" class="block text-sm font-medium text-gray-700 mb-2">
                    Nombre <span class="text-red-500">*</span>
                </label>
                <input
                    type="text"
                    id="name"
                    name="name"
                    value="<?= htmlspecialchars($label->name ?? '') ?>"
                    class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    required
                    maxlength="50"
                    placeholder="Ej: Urgente, Backend, Frontend, etc.">
                <p class="mt-1 text-sm text-gray-500">Máximo 50 caracteres</p>
            </div>

            <!-- Color -->
            <div class="mb-6">
                <label for="color" class="block text-sm font-medium text-gray-700 mb-2">
                    Color <span class="text-red-500">*</span>
                </label>
                <div class="flex items-center space-x-4">
                    <input
                        type="color"
                        id="color"
                        name="color"
                        value="<?= htmlspecialchars($label->color ?? '#3498db') ?>"
                        class="h-10 w-20 border border-gray-300 rounded cursor-pointer"
                        required>
                    <div class="flex-1">
                        <div class="flex items-center space-x-3">
                            <span
                                id="color-preview"
                                class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium"
                                style="background-color: <?= htmlspecialchars($label->color ?? '#3498db') ?>20; color: <?= htmlspecialchars($label->color ?? '#3498db') ?>">
                                <div class="w-2 h-2 rounded-full mr-2" style="background-color: <?= htmlspecialchars($label->color ?? '#3498db') ?>"></div>
                                <span id="preview-text"><?= htmlspecialchars($label->name ?? 'Vista previa') ?></span>
                            </span>
                        </div>
                        <p class="mt-1 text-sm text-gray-500">Vista previa de cómo se verá la etiqueta</p>
                    </div>
                </div>
            </div>

            <!-- Colores predefinidos -->
            <div class="mb-6">
                <label class="block text-sm font-medium text-gray-700 mb-3">Colores Sugeridos</label>
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
                        '#FF5722'
                    ];
                    foreach ($suggestedColors as $suggestedColor):
                    ?>
                        <button
                            type="button"
                            class="w-8 h-8 rounded border-2 border-white shadow hover:scale-110 transition-transform"
                            style="background-color: <?= $suggestedColor ?>"
                            onclick="selectColor('<?= $suggestedColor ?>')"
                            title="<?= $suggestedColor ?>"></button>
                    <?php endforeach; ?>
                </div>
            </div>

            <!-- Descripción -->
            <div class="mb-6">
                <label for="description" class="block text-sm font-medium text-gray-700 mb-2">
                    Descripción
                </label>
                <textarea
                    id="description"
                    name="description"
                    rows="3"
                    class="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Descripción opcional de la etiqueta..."><?= htmlspecialchars($label->description ?? '') ?></textarea>
                <p class="mt-1 text-sm text-gray-500">Opcional: describe el propósito de esta etiqueta</p>
            </div>

            <!-- Información del sistema -->
            <div class="mb-6 p-4 bg-gray-50 rounded-lg">
                <h3 class="text-sm font-medium text-gray-700 mb-2">Información del Sistema</h3>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-gray-600">
                    <div>
                        <span class="font-medium">ID:</span> <?= $label->id ?>
                    </div>
                    <div>
                        <span class="font-medium">Tareas asignadas:</span> <?= $label->tasks_count ?? 0 ?>
                    </div>
                    <div>
                        <span class="font-medium">Creada:</span>
                        <?= safe_date_format($label->created_at, 'd/m/Y H:i') ?>
                    </div>
                    <div>
                        <span class="font-medium">Actualizada:</span>
                        <?= safe_date_format($label->updated_at, 'd/m/Y H:i') ?>
                    </div>
                </div>
            </div>

            <!-- Botones -->
            <div class="flex items-center justify-between pt-6 border-t border-gray-200">
                <div>
                    <a href="?action=label_delete&id=<?= $label->id ?>"
                        class="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded"
                        onclick="return confirm('¿Estás seguro de que deseas eliminar esta etiqueta? Esta acción no se puede deshacer.')">
                        <i class="fas fa-trash mr-2"></i>Eliminar Etiqueta
                    </a>
                </div>
                <div class="flex space-x-3">
                    <a href="?action=labels"
                        class="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded">
                        Cancelar
                    </a>
                    <button type="submit"
                        class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
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
