<?php

/**
 * Vista para crear un nuevo usuario.
 */
?>

<div class="max-w-2xl mx-auto">
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900 dark:text-white transition-colors">Nuevo Usuario</h1>
            <p class="text-gray-600 dark:text-gray-300 transition-colors">Agrega un nuevo usuario al sistema</p>
        </div>
        <a href="?action=users" class="text-gray-600 hover:text-gray-800 dark:text-gray-300 dark:hover:text-gray-100 transition-colors">
            <i class="fas fa-arrow-left mr-2"></i>
            Volver a Usuarios
        </a>
    </div>

    <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6 border border-transparent dark:border-gray-700 transition-colors">
        <form method="POST" action="?action=user_create">
            <div class="space-y-6">
                <!-- Información básica -->
                <div>
                    <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4 transition-colors">Información Básica</h3>
                </div>

                <div>
                    <label for="name" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">
                        Nombre completo <span class="text-red-500">*</span>
                    </label>
                    <input type="text"
                        id="name"
                        name="name"
                        required
                        class="w-full border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                        placeholder="Ingresa el nombre completo del usuario">
                </div>

                <div>
                    <label for="email" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">
                        Correo electrónico <span class="text-red-500">*</span>
                    </label>
                    <input type="email"
                        id="email"
                        name="email"
                        required
                        class="w-full border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
                        placeholder="usuario@ejemplo.com">
                </div>

                <!-- Personalización -->
                <div>
                    <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-4 mt-8 transition-colors">Personalización</h3>
                </div>

                <div>
                    <label for="avatar_color" class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">Color del avatar</label>
                    <div class="flex items-center space-x-4">
                        <input type="color"
                            id="avatar_color"
                            name="avatar_color"
                            value="#3498db"
                            class="h-10 w-20 border border-gray-300 dark:border-gray-600 rounded cursor-pointer bg-white dark:bg-gray-700 transition-colors">
                        <div class="flex items-center">
                            <div id="avatar-preview" class="avatar mr-3" style="background-color: #3498db;">
                                <span id="avatar-initials">JD</span>
                            </div>
                            <span class="text-sm text-gray-600 dark:text-gray-400 transition-colors">Vista previa del avatar</span>
                        </div>
                    </div>
                    <p class="text-sm text-gray-500 dark:text-gray-400 mt-1 transition-colors">Este color se usará para el avatar del usuario en toda la aplicación</p>
                </div>

                <!-- Colores predefinidos -->
                <div>
                    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2 transition-colors">Colores predefinidos</label>
                    <div class="grid grid-cols-8 gap-2">

                        <?php
                        $predefinedColors = [
                            '#3498db',
                            '#e74c3c',
                            '#2ecc71',
                            '#f39c12',
                            '#9b59b6',
                            '#1abc9c',
                            '#e67e22',
                            '#34495e',
                            '#f1c40f',
                            '#e91e63',
                            '#8e44ad',
                            '#16a085',
                        ];
foreach ($predefinedColors as $color): ?>
                            <button type="button"
                                class="color-option w-8 h-8 rounded-full border-2 border-gray-300 dark:border-gray-600 hover:border-gray-400 dark:hover:border-gray-500 transition-colors"
                                style="background-color: <?= $color ?>"
                                data-color="<?= $color ?>"
                                title="<?= $color ?>"></button>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>

            <!-- Botones de acción -->
            <div class="flex items-center justify-end space-x-3 mt-8 pt-6 border-t border-gray-200 dark:border-gray-700 transition-colors">
                <a href="?action=users" class="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    Cancelar
                </a>
                <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 dark:hover:bg-blue-500 transition-colors">
                    <i class="fas fa-plus mr-2"></i>
                    Crear Usuario
                </button>
            </div>
        </form>
    </div>
</div>

<style>
    .avatar {
        width: 40px;
        height: 40px;
        border-radius: 50%;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        font-size: 14px;
        font-weight: 600;
        color: white;
    }

    .color-option:hover {
        transform: scale(1.1);
    }

    .color-option.active {
        border-color: #374151;
        border-width: 3px;
    }
</style>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        const nameInput = document.getElementById('name');
        const colorInput = document.getElementById('avatar_color');
        const avatarPreview = document.getElementById('avatar-preview');
        const avatarInitials = document.getElementById('avatar-initials');
        const colorOptions = document.querySelectorAll('.color-option');

        // Actualizar iniciales cuando cambie el nombre
        nameInput.addEventListener('input', function() {
            updateInitials();
        });

        // Actualizar color cuando cambie el selector de color
        colorInput.addEventListener('input', function() {
            updateAvatarColor(this.value);
        });

        // Manejar clicks en colores predefinidos
        colorOptions.forEach(option => {
            option.addEventListener('click', function() {
                const color = this.dataset.color;
                colorInput.value = color;
                updateAvatarColor(color);

                // Actualizar estado activo
                colorOptions.forEach(opt => opt.classList.remove('active'));
                this.classList.add('active');
            });
        });

        function updateInitials() {
            const name = nameInput.value.trim();
            let initials = 'JD';

            if (name) {
                const words = name.split(' ').filter(word => word.length > 0);
                if (words.length >= 2) {
                    initials = words[0][0].toUpperCase() + words[1][0].toUpperCase();
                } else if (words.length === 1) {
                    initials = words[0].substring(0, 2).toUpperCase();
                }
            }

            avatarInitials.textContent = initials;
        }

        function updateAvatarColor(color) {
            avatarPreview.style.backgroundColor = color;

            // Actualizar el color activo
            colorOptions.forEach(option => {
                option.classList.toggle('active', option.dataset.color === color);
            });
        }

        // Inicializar con color por defecto
        updateAvatarColor('#3498db');
        colorOptions[0].classList.add('active');
    });
</script>
