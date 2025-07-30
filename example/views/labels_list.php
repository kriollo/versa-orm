<?php
// Vista: Listado de etiquetas y filtro de tareas por etiqueta
use Example\Models\Label;
use Example\Models\Task;

$labels = Label::all();
$selectedLabelId = $_GET['label_id'] ?? null;
$tareas = $selectedLabelId ? Task::byLabel((int)$selectedLabelId) : [];
?>
<h2>Etiquetas</h2>
<ul>
    <?php foreach ($labels as $label): ?>
        <li>
            <a href="?view=labels_list&label_id=<?= $label->id ?>" style="color:<?= htmlspecialchars($label->color ?? '#333') ?>">
                <?= htmlspecialchars($label->name) ?>
            </a>
        </li>
    <?php endforeach; ?>
</ul>

<?php if ($selectedLabelId): ?>
    <h3>Tareas con la etiqueta seleccionada</h3>
    <ul>
        <?php foreach ($tareas as $tarea): ?>
            <li>
                <strong><?= htmlspecialchars($tarea['title']) ?></strong>
                <br>
                <?= htmlspecialchars($tarea['description'] ?? '') ?>
            </li>
        <?php endforeach; ?>
    </ul>
<?php endif; ?>
