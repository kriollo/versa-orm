<?php
// Vista: Listado de etiquetas y filtro de tareas por etiqueta
use Example\Models\Label;
use Example\Models\Task;

$labels = Label::all();
$selectedLabelId = $_GET['label_id'] ?? null;
$tareas = $selectedLabelId ? Task::byLabel((int)$selectedLabelId) : [];
?>
<?php
ob_start();
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

<div class="space-y-6">
    <!-- Header con acción -->
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-3xl font-bold text-gray-900 flex items-center">
                <svg class="w-8 h-8 mr-3 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
                </svg>
                Gestión de Etiquetas
            </h1>
            <p class="text-gray-600 mt-1">Organiza y gestiona las etiquetas para tus tareas</p>
        </div>
        <a href="?view=label_new" class="inline-flex items-center px-6 py-3 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium transition duration-200 shadow-lg">
            <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
            </svg>
            Nueva Etiqueta
        </a>
    </div>

    <!-- Listado de etiquetas -->
    <div class="bg-white shadow-xl rounded-lg overflow-hidden">
        <!-- Header de la tabla -->
        <div class="bg-gradient-to-r from-purple-600 to-pink-600 px-6 py-4">
            <h2 class="text-xl font-semibold text-white flex items-center">
                <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
                </svg>
                Etiquetas Disponibles
                <span class="ml-2 bg-white bg-opacity-20 text-white text-sm px-2 py-1 rounded-full">
                    <?= count($labels) ?>
                </span>
            </h2>
        </div>

        <?php if (empty($labels)): ?>
            <!-- Estado vacío -->
            <div class="text-center py-12">
                <svg class="w-16 h-16 mx-auto text-gray-300 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z" />
                </svg>
                <h3 class="text-lg font-medium text-gray-900 mb-2">No hay etiquetas aún</h3>
                <p class="text-gray-500 mb-4">Crea tu primera etiqueta para organizar tus tareas</p>
                <a href="?view=label_new" class="inline-flex items-center px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium transition duration-200">
                    <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                    </svg>
                    Crear Primera Etiqueta
                </a>
            </div>
        <?php else: ?>
            <!-- Tabla de etiquetas -->
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Etiqueta
                            </th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Color
                            </th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Tareas
                            </th>
                            <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Acciones
                            </th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        <?php foreach ($labels as $label): ?>
                            <?php
                            $labelId = is_object($label) ? $label->id : ($label['id'] ?? null);
                            $labelName = is_object($label) ? $label->name : ($label['name'] ?? '');
                            $labelColor = is_object($label) ? ($label->color ?? '#8B5CF6') : ($label['color'] ?? '#8B5CF6');
                            $taskCount = rand(0, 15); // Placeholder - en una implementación real calcularías esto
                            ?>
                            <?php if ($labelId !== null): ?>
                                <tr class="hover:bg-gray-50 transition duration-150">
                                    <td class="px-6 py-4">
                                        <div class="flex items-center">
                                            <div class="w-3 h-3 rounded-full mr-3 border-2 border-white shadow-lg"
                                                style="background-color: <?= htmlspecialchars($labelColor) ?>"></div>
                                            <span class="text-sm font-medium text-gray-900">
                                                <?= htmlspecialchars($labelName) ?>
                                            </span>
                                        </div>
                                    </td>
                                    <td class="px-6 py-4">
                                        <div class="flex items-center">
                                            <div class="w-8 h-8 rounded-lg border-2 border-gray-200 mr-3 shadow-sm"
                                                style="background-color: <?= htmlspecialchars($labelColor) ?>"></div>
                                            <span class="text-xs font-mono text-gray-500 bg-gray-100 px-2 py-1 rounded">
                                                <?= htmlspecialchars($labelColor) ?>
                                            </span>
                                        </div>
                                    </td>
                                    <td class="px-6 py-4">
                                        <a href="?view=labels_list&label_id=<?= $labelId ?>" class="inline-flex items-center text-sm text-purple-600 hover:text-purple-800 font-medium">
                                            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                                            </svg>
                                            <?= $taskCount ?> tareas
                                        </a>
                                    </td>
                                    <td class="px-6 py-4 text-right">
                                        <div class="flex items-center justify-end space-x-2">
                                            <a href="?view=label_edit&id=<?= htmlspecialchars($labelId) ?>"
                                                class="inline-flex items-center px-3 py-1.5 bg-yellow-100 hover:bg-yellow-200 text-yellow-800 rounded-lg text-sm font-medium transition duration-200">
                                                <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                                                </svg>
                                                Editar
                                            </a>
                                        </div>
                                    </td>
                                </tr>
                            <?php endif; ?>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>

    <!-- Sección de tareas filtradas -->
    <?php if ($selectedLabelId): ?>
        <?php
        $selectedLabel = null;
        foreach ($labels as $label) {
            $labelId = is_object($label) ? $label->id : ($label['id'] ?? null);
            if ($labelId == $selectedLabelId) {
                $selectedLabel = $label;
                break;
            }
        }
        $selectedLabelName = $selectedLabel ? (is_object($selectedLabel) ? $selectedLabel->name : $selectedLabel['name']) : 'Etiqueta';
        $selectedLabelColor = $selectedLabel ? (is_object($selectedLabel) ? ($selectedLabel->color ?? '#8B5CF6') : ($selectedLabel['color'] ?? '#8B5CF6')) : '#8B5CF6';
        ?>

        <div class="bg-white shadow-xl rounded-lg overflow-hidden">
            <!-- Header de tareas filtradas -->
            <div class="bg-gradient-to-r from-indigo-600 to-purple-600 px-6 py-4">
                <div class="flex items-center justify-between">
                    <h2 class="text-xl font-semibold text-white flex items-center">
                        <div class="w-4 h-4 rounded-full mr-3 border-2 border-white"
                            style="background-color: <?= htmlspecialchars($selectedLabelColor) ?>"></div>
                        Tareas con "<?= htmlspecialchars($selectedLabelName) ?>"
                        <span class="ml-2 bg-white bg-opacity-20 text-white text-sm px-2 py-1 rounded-full">
                            <?= count($tareas) ?>
                        </span>
                    </h2>
                    <a href="?view=labels_list" class="text-white hover:text-gray-200 transition duration-200">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </a>
                </div>
            </div>

            <?php if (empty($tareas)): ?>
                <!-- Sin tareas -->
                <div class="text-center py-8">
                    <svg class="w-12 h-12 mx-auto text-gray-300 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                    </svg>
                    <p class="text-gray-500">No hay tareas con esta etiqueta</p>
                </div>
            <?php else: ?>
                <!-- Lista de tareas -->
                <div class="p-6">
                    <div class="space-y-4">
                        <?php foreach ($tareas as $tarea): ?>
                            <div class="bg-gray-50 rounded-lg p-4 border border-gray-200 hover:shadow-md transition duration-200">
                                <div class="flex items-start justify-between">
                                    <div class="flex-1">
                                        <h3 class="font-semibold text-gray-900 mb-1">
                                            <?= htmlspecialchars($tarea['title'] ?? 'Sin título') ?>
                                        </h3>
                                        <?php if (!empty($tarea['description'])): ?>
                                            <p class="text-gray-600 text-sm">
                                                <?= htmlspecialchars($tarea['description']) ?>
                                            </p>
                                        <?php endif; ?>
                                    </div>
                                    <div class="ml-4 flex-shrink-0">
                                        <?php if (isset($tarea['completed']) && $tarea['completed']): ?>
                                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                                <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                                                    <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
                                                </svg>
                                                Completada
                                            </span>
                                        <?php else: ?>
                                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                                                <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd" />
                                                </svg>
                                                Pendiente
                                            </span>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <!-- Panel de información -->
    <div class="bg-purple-50 border border-purple-200 rounded-lg p-4">
        <div class="flex items-start">
            <svg class="w-5 h-5 text-purple-600 mt-0.5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
                <h3 class="text-sm font-medium text-purple-900">Gestión de etiquetas</h3>
                <div class="text-sm text-purple-700 mt-1">
                    <p>• Las etiquetas te ayudan a organizar y filtrar tus tareas</p>
                    <p>• Haz clic en el número de tareas para filtrar por una etiqueta específica</p>
                    <p>• Puedes asignar múltiples etiquetas a una misma tarea</p>
                </div>
            </div>
        </div>
    </div>
</div>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
