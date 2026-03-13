<?php

declare(strict_types=1);

/**
 * Vista para crear una nueva etiqueta.
 */
?>

<div class="max-w-2xl mx-auto">
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900 dark:text-white transition-colors">Nueva Etiqueta</h1>
            <p class="text-gray-600 dark:text-gray-300 transition-colors">Crea una nueva etiqueta para organizar tus tareas</p>
        </div>
        <a href="?action=labels" class="text-gray-600 hover:text-gray-800 dark:text-gray-300 dark:hover:text-gray-100 transition-colors">
            <i class="fas fa-arrow-left mr-2"></i>
            Volver a Etiquetas
        </a>
    </div>

    <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6 border border-transparent dark:border-gray-700 transition-colors">
        <form method="POST" action="?action=label_create">
            <div class="space-y-6">
                <!-- Información básica -->
                <div>
                    <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4 transition-colors">Información Básica</h3>
                </div>

                <div>
                    <label for="name" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">
                        Nombre de la etiqueta <span class="text-red-500">*</span>
                    </label>
                    <input type="text"
                        id="name"
                        name="name"
                        required
                        maxlength="50"
                        class="w-full border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                        placeholder="Ej: Bug, Feature, Urgente, etc.">
                    <p class="text-sm text-gray-500 dark:text-gray-400 mt-1 transition-colors">Máximo 50 caracteres</p>
                </div>

                <div>
                    <label for="description" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">Descripción</label>
                    <textarea id="description"
                        name="description"
                        rows="3"
                        class="w-full border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                        placeholder="Describe para qué se usa esta etiqueta (opcional)"></textarea>
                </div>

                <!-- Personalización visual -->
                <div>
                    <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4 mt-8 transition-colors">Personalización Visual</h3>
                </div>

                <div>
                    <label for="color" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">Color de la etiqueta</label>
                    <div class="flex items-center space-x-4">
                        <input type="color"
                            id="color"
                            name="color"
                            value="#6c757d"
                            class="h-10 w-20 border border-gray-300 dark:border-gray-600 rounded cursor-pointer bg-white dark:bg-gray-700 transition-colors">
                        <div class="flex items-center">
                            <div id="label-preview" class="label-preview" style="background-color: #6c757d20; color: #6c757d;">
                                <div class="label-dot" style="background-color: #6c757d;"></div>
                                <span id="label-text">Ejemplo</span>
                            </div>
                            <span class="text-sm text-gray-600 dark:text-gray-400 ml-3 transition-colors">Vista previa</span>
                        </div>
                    </div>
                </div>

                <!-- Colores predefinidos -->
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">Colores predefinidos</label>
                    <div class="grid grid-cols-8 gap-2">
                        <?php

                        $predefinedColors = [
                            '#e74c3c',
                            '#3498db',
                            '#2ecc71',
                            '#f39c12',
                            '#9b59b6',
                            '#1abc9c',
                            '#e67e22',
                            '#34495e',
                            '#f1c40f',
                            '#e91e63',
                            '#8e44ad',
                            '#6c757d',
                            '#fd7e14',
                            '#20c997',
                            '#6f42c1',
                            '#dc3545',
                        ];

                        foreach ($predefinedColors as $color) { ?>
                            <button type="button"
                                class="color-option w-8 h-8 rounded-full border-2 border-gray-300 dark:border-gray-600 hover:border-gray-400 dark:hover:border-gray-500 transition-colors"
                                style="background-color: <?php echo $color; ?>"
                                data-color="<?php echo $color; ?>"
                                title="<?php echo $color; ?>"></button>
                        <?php } ?>
                    </div>
                </div>

                <!-- Colores por categoría -->
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">Colores sugeridos por categoría</label>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div class="space-y-2">
                            <h4 class="text-sm font-medium text-gray-600 dark:text-gray-400 transition-colors">Estados y Prioridades</h4>
                            <div class="flex flex-wrap gap-2">
                                <button type="button" class="category-color" data-color="#e74c3c" title="Urgente/Crítico">#e74c3c</button>
                                <button type="button" class="category-color" data-color="#f39c12" title="Importante">#f39c12</button>
                                <button type="button" class="category-color" data-color="#2ecc71" title="Completado">#2ecc71</button>
                                <button type="button" class="category-color" data-color="#3498db" title="En progreso">#3498db</button>
                            </div>
                        </div>
                        <div class="space-y-2">
                            <h4 class="text-sm font-medium text-gray-600 dark:text-gray-400 transition-colors">Tipos de Tarea</h4>
                            <div class="flex flex-wrap gap-2">
                                <button type="button" class="category-color" data-color="#9b59b6" title="Diseño">#9b59b6</button>
                                <button type="button" class="category-color" data-color="#1abc9c" title="Desarrollo">#1abc9c</button>
                                <button type="button" class="category-color" data-color="#e67e22" title="Testing">#e67e22</button>
                                <button type="button" class="category-color" data-color="#34495e" title="Documentación">#34495e</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Botones de acción -->
            <div class="flex items-center justify-end space-x-3 mt-8 pt-6 border-t border-gray-200 dark:border-gray-700 transition-colors">
                <a href="?action=labels" class="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    Cancelar
                </a>
                <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 dark:hover:bg-blue-500 transition-colors">
                    <i class="fas fa-plus mr-2"></i>
                    Crear Etiqueta
                </button>
            </div>
        </form>
    </div>
</div>

<style>
    .label-preview {
        display: inline-flex;
        align-items: center;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 14px;
        font-weight: 500;
    }

    .label-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        margin-right: 6px;
    }

    .color-option:hover {
        transform: scale(1.1);
    }

    .color-option.active {
        border-color: #374151;
        border-width: 3px;
    }

    .category-color {
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-family: monospace;
        color: white;
        border: none;
        cursor: pointer;
        transition: opacity 0.2s;
    }

    .category-color:hover {
        opacity: 0.8;
    }
</style>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        const nameInput = document.getElementById('name');
        const colorInput = document.getElementById('color');
        const labelPreview = document.getElementById('label-preview');
        const labelText = document.getElementById('label-text');
        const colorOptions = document.querySelectorAll('.color-option');
        const categoryColors = document.querySelectorAll('.category-color');

        // Actualizar texto de vista previa cuando cambie el nombre
        nameInput.addEventListener('input', function() {
            const name = this.value.trim() || 'Ejemplo';
            labelText.textContent = name;
        });

        // Actualizar color cuando cambie el selector de color
        colorInput.addEventListener('input', function() {
            updateLabelColor(this.value);
        });

        // Manejar clicks en colores predefinidos
        colorOptions.forEach(option => {
            option.addEventListener('click', function() {
                const color = this.dataset.color;
                selectColor(color);
            });
        });

        // Manejar clicks en colores por categoría
        categoryColors.forEach(button => {
            const color = button.dataset.color;
            button.style.backgroundColor = color;

            button.addEventListener('click', function() {
                selectColor(color);
            });
        });

        function selectColor(color) {
            colorInput.value = color;
            updateLabelColor(color);

            // Actualizar estado activo en colores predefinidos
            colorOptions.forEach(opt => {
                opt.classList.toggle('active', opt.dataset.color === color);
            });
        }

        function updateLabelColor(color) {
            const backgroundColor = color + '20'; // Agregar transparencia
            labelPreview.style.backgroundColor = backgroundColor;
            labelPreview.style.color = color;
            labelPreview.querySelector('.label-dot').style.backgroundColor = color;
        }

        // Inicializar con color por defecto
        updateLabelColor('#6c757d');

        // Establecer color inicial en categorías
        categoryColors.forEach(button => {
            const color = button.dataset.color;
            button.style.backgroundColor = color;
        });
    });
</script>
