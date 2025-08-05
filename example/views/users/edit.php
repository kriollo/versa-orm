<?php

/**
 * Vista para editar un usuario existente.
 */
?>

<div class="max-w-2xl mx-auto">
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Editar Usuario</h1>
            <p class="text-gray-600">Modifica la información del usuario</p>
        </div>
        <a href="?action=users" class="text-gray-600 hover:text-gray-800">
            <i class="fas fa-arrow-left mr-2"></i>
            Volver a Usuarios
        </a>
    </div>

    <div class="bg-white shadow rounded-lg p-6">
        <form method="POST" action="?action=user_edit&id=<?= $user->id ?>">
            <div class="space-y-6">
                <!-- Información básica -->
                <div>
                    <h3 class="text-lg font-medium text-gray-900 mb-4">Información Personal</h3>

                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label for="name" class="block text-sm font-medium text-gray-700 mb-2">
                                Nombre completo <span class="text-red-500">*</span>
                            </label>
                            <input type="text"
                                id="name"
                                name="name"
                                required
                                value="<?= htmlspecialchars($user->name) ?>"
                                class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                placeholder="Ingresa el nombre completo">
                        </div>

                        <div>
                            <label for="email" class="block text-sm font-medium text-gray-700 mb-2">
                                Correo electrónico <span class="text-red-500">*</span>
                            </label>
                            <input type="email"
                                id="email"
                                name="email"
                                required
                                value="<?= htmlspecialchars($user->email) ?>"
                                class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                                placeholder="usuario@ejemplo.com">
                        </div>
                    </div>
                </div>

                <!-- Avatar -->
                <div>
                    <h3 class="text-lg font-medium text-gray-900 mb-4">Avatar</h3>

                    <div class="flex items-center space-x-4">
                        <div class="avatar-lg" style="background-color: <?= htmlspecialchars($user->avatar_color) ?>">
                            <?= strtoupper(substr($user->name, 0, 2)) ?>
                        </div>

                        <div class="flex-1">
                            <label for="avatar_color" class="block text-sm font-medium text-gray-700 mb-2">
                                Color del avatar
                            </label>
                            <div class="flex items-center space-x-3">
                                <input type="color"
                                    id="avatar_color"
                                    name="avatar_color"
                                    value="<?= htmlspecialchars($user->avatar_color) ?>"
                                    class="w-12 h-10 border border-gray-300 rounded cursor-pointer">
                                <span class="text-sm text-gray-500">Selecciona un color para el avatar</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Estado -->
                <div>
                    <h3 class="text-lg font-medium text-gray-900 mb-4">Estado de la cuenta</h3>

                    <div class="flex items-center">
                        <input type="checkbox"
                            id="active"
                            name="active"
                            value="1"
                            <?= isset($user->active) && $user->active ? 'checked' : '' ?>
                            class="mr-3 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                        <label for="active" class="text-sm font-medium text-gray-700">
                            Usuario activo
                        </label>
                    </div>
                    <p class="text-sm text-gray-500 mt-1">Los usuarios inactivos no pueden acceder al sistema</p>
                </div>
            </div>

            <!-- Información adicional -->
            <div class="mt-8 pt-6 border-t border-gray-200">
                <div class="grid grid-cols-2 gap-4 text-sm text-gray-500">
                    <div>
                        <strong>Creado:</strong> <?= isset($user->created_at) ? safe_date_format($user->created_at, 'd/m/Y H:i') : 'N/A' ?>
                    </div>
                    <div>
                        <strong>Actualizado:</strong> <?= isset($user->updated_at) ? safe_date_format($user->updated_at, 'd/m/Y H:i') : 'N/A' ?>
                    </div>
                </div>
            </div>

            <!-- Botones de acción -->
            <div class="mt-8 flex items-center justify-between">
                <button type="button"
                    onclick="if(confirm('¿Estás seguro de que quieres eliminar este usuario?')) { window.location.href = '?action=user_delete&id=<?= $user->id ?>'; }"
                    class="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 transition duration-200">
                    <i class="fas fa-trash mr-2"></i>
                    Eliminar Usuario
                </button>

                <div class="flex items-center space-x-3">
                    <a href="?action=users"
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
