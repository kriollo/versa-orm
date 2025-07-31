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
<div class="flex items-center justify-between mb-6">
    <h1 class="text-2xl font-bold text-blue-800">Etiquetas</h1>
    <a href="?view=label_new" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded shadow">Nueva Etiqueta</a>
</div>
<div class="bg-white shadow rounded-lg overflow-hidden mb-8">
    <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-blue-100">
            <tr>
                <th class="px-4 py-2 text-left">Nombre</th>
                <th class="px-4 py-2 text-left">Color</th>
                <th class="px-4 py-2 text-left">Acciones</th>
            </tr>
        </thead>
        <tbody class="bg-white divide-y divide-gray-100">
            <?php foreach ($labels as $label): ?>
                <?php
                $labelId = is_object($label) ? $label->id : ($label['id'] ?? null);
                $labelName = is_object($label) ? $label->name : ($label['name'] ?? '');
                $labelColor = is_object($label) ? ($label->color ?? '#333') : ($label['color'] ?? '#333');
                ?>
                <?php if ($labelId !== null): ?>
                    <tr>
                        <td class="px-4 py-2 font-semibold text-blue-900"><?= htmlspecialchars($labelName) ?></td>
                        <td class="px-4 py-2"><span class="inline-block w-6 h-6 rounded-full border border-gray-300 align-middle" style="background:<?= htmlspecialchars($labelColor) ?>"></span> <span class="text-xs text-gray-500 ml-2">(<?= htmlspecialchars($labelColor) ?>)</span></td>
                        <td class="px-4 py-2">
                            <a href="?view=label_edit&id=<?= htmlspecialchars($labelId) ?>" class="bg-yellow-400 hover:bg-yellow-500 text-white px-3 py-1 rounded mr-2">Editar</a>
                        </td>
                    </tr>
                <?php endif; ?>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>
<?php if ($selectedLabelId): ?>
    <h3 class="text-lg font-semibold mb-2">Tareas con la etiqueta seleccionada</h3>
    <ul class="mb-4">
        <?php foreach ($tareas as $tarea): ?>
            <li class="mb-2">
                <strong><?= htmlspecialchars($tarea['title']) ?></strong>
                <br>
                <?= htmlspecialchars($tarea['description'] ?? '') ?>
            </li>
        <?php endforeach; ?>
    </ul>
    <a href="?view=labels_list" class="text-blue-700 hover:underline">Volver al listado de etiquetas</a>
<?php endif; ?>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
