<?php
// Vista: Asignar/editar etiquetas de una tarea
use Example\Models\Label;
use Example\Models\Task;

$taskId = $_GET['task_id'] ?? null;
$task = $taskId ? Task::find($taskId) : null;
$labels = Label::all();
$taskLabels = $task ? array_column($task->labelsArray(), 'id') : [];

$projectId = $task && isset($task->project_id) ? $task->project_id : ($_GET['project_id'] ?? null);
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $task) {
    $selected = $_POST['labels'] ?? [];
    $task->setLabels(array_map('intval', $selected));
    if ($projectId) {
        header('Location: ?action=show_project&id=' . $projectId . '&labels_updated=1');
    } else {
        header('Location: ?view=labels_list&saved=1');
    }
    exit;
}
?>
<?php if ($task): ?>
    <?php
    ob_start();
    ?>
    <h2 class="text-xl font-bold mb-4">Asignar etiquetas a la tarea: <?= htmlspecialchars(is_object($task) ? $task->title : ($task['title'] ?? '')) ?></h2>
    <form method="post" class="bg-white p-6 rounded shadow max-w-md mx-auto">
        <div class="mb-4">
            <?php foreach ($labels as $label): ?>
                <?php
                $labelId = is_object($label) ? $label->id : ($label['id'] ?? null);
                $labelName = is_object($label) ? $label->name : ($label['name'] ?? '');
                $labelColor = is_object($label) ? ($label->color ?? '#333') : ($label['color'] ?? '#333');
                // Contraste: blanco si el color es oscuro, negro si es claro
                if (!function_exists('isDark')) {
                    function isDark($hex)
                    {
                        $hex = ltrim($hex, '#');
                        if (strlen($hex) === 3) $hex = $hex[0] . $hex[0] . $hex[1] . $hex[1] . $hex[2] . $hex[2];
                        $r = hexdec(substr($hex, 0, 2));
                        $g = hexdec(substr($hex, 2, 2));
                        $b = hexdec(substr($hex, 4, 2));
                        // Percepción luminosa
                        return ($r * 0.299 + $g * 0.587 + $b * 0.114) < 150;
                    }
                }
                $textColor = isDark($labelColor) ? '#fff' : '#222';
                ?>
                <?php if ($labelId !== null): ?>
                    <label class="inline-flex items-center mr-4 mb-2">
                        <input type="checkbox" name="labels[]" value="<?= htmlspecialchars($labelId) ?>" <?= in_array($labelId, $taskLabels) ? 'checked' : '' ?> class="form-checkbox h-4 w-4 text-blue-600">
                        <span class="ml-2 font-semibold text-base" style="color:<?= htmlspecialchars($textColor) ?>;background:<?= htmlspecialchars($labelColor) ?>;padding:2px 8px;border-radius:4px;">
                            <?= htmlspecialchars($labelName) ?>
                        </span>
                        <span class="inline-block w-4 h-4 rounded-full border border-gray-300 ml-2 align-middle" style="background:<?= htmlspecialchars($labelColor) ?>"></span>
                    </label>
                <?php endif; ?>
            <?php endforeach; ?>
        </div>
        <div class="flex gap-2">
            <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded">Guardar etiquetas</button>
            <a href="?view=labels_list" class="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded">Volver</a>
        </div>
    </form>
    <?php if (isset($_GET['saved'])): ?>
        <p class="text-green-600 mt-2">Etiquetas actualizadas correctamente.</p>
    <?php endif; ?>
    <?php
    $content = ob_get_clean();
    include __DIR__ . '/layout.php';
    ?>
<?php else: ?>
    <p>Tarea no encontrada.</p>
<?php endif; ?>
