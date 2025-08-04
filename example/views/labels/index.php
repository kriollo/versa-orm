<?php

/**
 * Vista para listar todas las etiquetas.
 */
?>

<div class="max-w-6xl mx-auto">
    <!-- Header -->
    <div class="flex items-center justify-between mb-6">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Etiquetas</h1>
            <p class="text-gray-600">Gestiona las etiquetas del sistema para organizar tareas</p>
        </div>
        <a href="?action=label_create" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors">
            <i class="fas fa-plus mr-2"></i>
            Nueva Etiqueta
        </a>
    </div>

    <!-- Estadísticas -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div class="bg-white p-4 rounded-lg shadow">
            <div class="flex items-center">
                <div class="p-2 bg-blue-100 rounded-lg mr-3">
                    <i class="fas fa-tags text-blue-600"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold"><?= count($labels) ?></p>
                    <p class="text-gray-600 text-sm">Total Etiquetas</p>
                </div>
            </div>
        </div>

        <div class="bg-white p-4 rounded-lg shadow">
            <div class="flex items-center">
                <div class="p-2 bg-green-100 rounded-lg mr-3">
                    <i class="fas fa-check-circle text-green-600"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold"><?= count(array_filter($labels, fn ($l) => !empty($l->tasks_count) && $l->tasks_count > 0)) ?></p>
                    <p class="text-gray-600 text-sm">En Uso</p>
                </div>
            </div>
        </div>

        <div class="bg-white p-4 rounded-lg shadow">
            <div class="flex items-center">
                <div class="p-2 bg-yellow-100 rounded-lg mr-3">
                    <i class="fas fa-tasks text-yellow-600"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold"><?= array_sum(array_column($labels, 'tasks_count')) ?></p>
                    <p class="text-gray-600 text-sm">Asignaciones</p>
                </div>
            </div>
        </div>

        <div class="bg-white p-4 rounded-lg shadow">
            <div class="flex items-center">
                <div class="p-2 bg-purple-100 rounded-lg mr-3">
                    <i class="fas fa-palette text-purple-600"></i>
                </div>
                <div>
                    <p class="text-2xl font-semibold"><?= count(array_unique(array_column($labels, 'color'))) ?></p>
                    <p class="text-gray-600 text-sm">Colores Únicos</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Lista de etiquetas -->
    <?php if (!empty($labels)): ?>
        <div class="bg-white shadow rounded-lg overflow-hidden">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 p-6">
                <?php foreach ($labels as $label): ?>
                    <div class="border border-gray-200 rounded-lg p-4 hover:shadow-lg transition-shadow">
                        <!-- Header de la etiqueta -->
                        <div class="flex items-center justify-between mb-3">
                            <div class="flex items-center flex-1">
                                <div class="w-4 h-4 rounded-full mr-3" style="background-color: <?= htmlspecialchars($label->color) ?>"></div>
                                <h3 class="font-semibold text-gray-900 truncate"><?= htmlspecialchars($label->name) ?></h3>
                            </div>
                            <div class="flex items-center space-x-1">
                                <a href="?action=label_edit&id=<?= $label->id ?>" class="text-yellow-600 hover:text-yellow-800" title="Editar">
                                    <i class="fas fa-edit text-sm"></i>
                                </a>
                                <a href="?action=label_delete&id=<?= $label->id ?>"
                                    onclick="return confirm('¿Estás seguro de que quieres eliminar esta etiqueta?')"
                                    class="text-red-600 hover:text-red-800" title="Eliminar">
                                    <i class="fas fa-trash text-sm"></i>
                                </a>
                            </div>
                        </div>

                        <!-- Descripción -->
                        <?php if ($label->description): ?>
                            <p class="text-gray-600 text-sm mb-3 line-clamp-2">
                                <?= htmlspecialchars($label->description) ?>
                            </p>
                        <?php else: ?>
                            <p class="text-gray-400 text-sm mb-3 italic">Sin descripción</p>
                        <?php endif; ?>

                        <!-- Estadísticas de la etiqueta -->
                        <div class="flex items-center justify-between text-sm">
                            <div class="flex items-center space-x-3">
                                <span class="flex items-center text-gray-500">
                                    <i class="fas fa-tasks mr-1"></i>
                                    <?= $label->tasks_count ?? 0 ?> tareas
                                </span>
                            </div>
                            <span class="text-xs text-gray-400">
                                <?= date('d/m/Y', strtotime($label->created_at)) ?>
                            </span>
                        </div>

                        <!-- Vista previa de la etiqueta -->
                        <div class="mt-3 pt-3 border-t border-gray-100">
                            <div class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium"
                                style="background-color: <?= htmlspecialchars($label->color) ?>20; color: <?= htmlspecialchars($label->color) ?>">
                                <div class="w-2 h-2 rounded-full mr-2" style="background-color: <?= htmlspecialchars($label->color) ?>"></div>
                                <?= htmlspecialchars($label->name) ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- Paleta de colores más usados -->
        <div class="bg-white shadow rounded-lg p-6 mt-6">
            <h3 class="text-lg font-semibold mb-4">Paleta de Colores</h3>
            <div class="flex flex-wrap gap-2">
                <?php
                $colors = array_unique(array_column($labels, 'color'));
foreach ($colors as $color):
    ?>
                    <div class="flex items-center space-x-2 bg-gray-50 px-3 py-2 rounded-lg">
                        <div class="w-4 h-4 rounded-full" style="background-color: <?= htmlspecialchars($color) ?>"></div>
                        <span class="text-sm font-mono text-gray-600"><?= htmlspecialchars($color) ?></span>
                        <span class="text-xs text-gray-500">
                            (<?= count(array_filter($labels, fn ($l) => $l->color === $color)) ?> etiquetas)
                        </span>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

    <?php else: ?>
        <div class="bg-white shadow rounded-lg p-12 text-center">
            <i class="fas fa-tags text-4xl text-gray-300 mb-4"></i>
            <h3 class="text-lg font-medium text-gray-900 mb-2">No hay etiquetas</h3>
            <p class="text-gray-500 mb-4">Las etiquetas te ayudan a organizar y categorizar tus tareas</p>
            <a href="?action=label_create" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors">
                <i class="fas fa-plus mr-2"></i>
                Crear Primera Etiqueta
            </a>
        </div>
    <?php endif; ?>
</div>

<style>
    .line-clamp-2 {
        display: -webkit-box;
        -webkit-line-clamp: 2;
        -webkit-box-orient: vertical;
        overflow: hidden;
    }
</style>
