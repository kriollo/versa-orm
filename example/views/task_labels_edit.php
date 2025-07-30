<?php
// Vista: Asignar/editar etiquetas de una tarea
use Example\Models\Task;
use Example\Models\Label;

$taskId = $_GET['task_id'] ?? null;
$task = $taskId ? Task::find($taskId) : null;
$labels = Label::all();
$taskLabels = $task ? array_column($task->labelsArray(), 'id') : [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $task) {
    $selected = $_POST['labels'] ?? [];
    $task->setLabels(array_map('intval', $selected));
    header('Location: ?view=task_labels_edit&task_id=' . $taskId . '&saved=1');
    exit;
}
?>
<?php if ($task): ?>
    <h2>Editar etiquetas para la tarea: <?= htmlspecialchars($task->title) ?></h2>
    <form method="post">
        <?php foreach ($labels as $label): ?>
            <label style="color:<?= htmlspecialchars($label->color ?? '#333') ?>">
                <input type="checkbox" name="labels[]" value="<?= $label->id ?>" <?= in_array($label->id, $taskLabels) ? 'checked' : '' ?>>
                <?= htmlspecialchars($label->name) ?>
            </label><br>
        <?php endforeach; ?>
        <button type="submit">Guardar etiquetas</button>
    </form>
    <?php if (isset($_GET['saved'])): ?>
        <p style="color:green">Etiquetas actualizadas correctamente.</p>
    <?php endif; ?>
<?php else: ?>
    <p>Tarea no encontrada.</p>
<?php endif; ?>
