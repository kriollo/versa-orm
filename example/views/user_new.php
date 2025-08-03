<?php
// Vista: Crear nuevo usuario
?>
<!-- Navegación de regreso -->
<div class="mb-6">
    <a href="?action=projects" class="inline-flex items-center text-blue-600 hover:text-blue-800 font-medium">
        <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
        </svg>
        Volver a proyectos
    </a>
</div>

<div class="max-w-xl mx-auto">
    <div class="bg-white shadow-xl rounded-lg overflow-hidden">
        <!-- Header -->
        <div class="bg-gradient-to-r from-blue-600 to-indigo-600 px-6 py-6">
            <h1 class="text-3xl font-bold text-white flex items-center">
                <svg class="w-8 h-8 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                </svg>
                Crear Nuevo Usuario
            </h1>
            <p class="text-blue-100 mt-2">Añade un nuevo miembro al equipo</p>
        </div>

        <!-- Formulario -->
        <form method="post" action="?action=create_user" class="p-6 space-y-6">
            <!-- Nombre completo -->
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">
                    <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                    </svg>
                    Nombre Completo *
                </label>
                <input type="text" name="name" required
                    class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-200"
                    placeholder="Ej: Juan Pérez López"
                    maxlength="255">
                <p class="text-xs text-gray-500 mt-1">Nombre y apellidos del usuario</p>
            </div>

            <!-- Email -->
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-2">
                    <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 12a4 4 0 10-8 0 4 4 0 008 0zm0 0v1.5a2.5 2.5 0 005 0V12a9 9 0 10-9 9m4.5-1.206a8.959 8.959 0 01-4.5 1.207" />
                    </svg>
                    Correo Electrónico *
                </label>
                <input type="email" name="email" required
                    class="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition duration-200"
                    placeholder="usuario@ejemplo.com"
                    maxlength="255">
                <p class="text-xs text-gray-500 mt-1">Debe ser una dirección de email válida y única</p>
            </div>

            <!-- Estado del usuario -->
            <div class="bg-gray-50 rounded-lg p-4">
                <div class="flex items-center">
                    <input type="hidden" name="status" value="active">
                    <div class="flex items-center">
                        <div class="flex-shrink-0">
                            <div class="h-3 w-3 bg-green-400 rounded-full"></div>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm font-medium text-gray-900">Usuario activo</p>
                            <p class="text-xs text-gray-500">El usuario podrá acceder y ser asignado a proyectos</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Botones de acción -->
            <div class="flex justify-end space-x-3 pt-6 border-t border-gray-200">
                <a href="?action=projects" class="inline-flex items-center px-6 py-3 border border-gray-300 rounded-lg text-gray-700 bg-white hover:bg-gray-50 font-medium transition duration-200">
                    <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                    Cancelar
                </a>
                <button type="submit" class="inline-flex items-center px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition duration-200 shadow-lg">
                    <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                    </svg>
                    Crear Usuario
                </button>
            </div>
        </form>
    </div>

    <!-- Información adicional -->
    <div class="mt-6 bg-blue-50 border border-blue-200 rounded-lg p-4">
        <div class="flex items-start">
            <svg class="w-5 h-5 text-blue-600 mt-0.5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
                <h3 class="text-sm font-medium text-blue-900">Información importante</h3>
                <ul class="text-sm text-blue-700 mt-1 space-y-1">
                    <li>• El email debe ser único en el sistema</li>
                    <li>• Los usuarios pueden ser asignados como responsables de proyectos</li>
                    <li>• Todos los usuarios se crean con estado "activo" por defecto</li>
                </ul>
            </div>
        </div>
    </div>
</div>

<script>
    document.addEventListener('DOMContentLoaded', function() {
        const nameInput = document.querySelector('input[name="name"]');
        const emailInput = document.querySelector('input[name="email"]');
        const form = document.querySelector('form');

        // Focus automático en el nombre
        if (nameInput) {
            nameInput.focus();
        }

        // Validación en tiempo real del email
        emailInput.addEventListener('blur', function() {
            const email = this.value;
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

            if (email && !emailRegex.test(email)) {
                this.classList.add('border-red-500');
                this.classList.remove('border-gray-300');
            } else {
                this.classList.remove('border-red-500');
                this.classList.add('border-gray-300');
            }
        });

        // Validación antes del envío
        form.addEventListener('submit', function(e) {
            let hasErrors = false;

            if (!nameInput.value.trim()) {
                nameInput.classList.add('border-red-500');
                hasErrors = true;
            }

            if (!emailInput.value.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailInput.value)) {
                emailInput.classList.add('border-red-500');
                hasErrors = true;
            }

            if (hasErrors) {
                e.preventDefault();
                nameInput.focus();
            }
        });
    });
</script>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
