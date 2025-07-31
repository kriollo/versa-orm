<?php
// Vista: Editar etiqueta existente
use Example\Models\Label;

$labelId = $_GET['id'] ?? null;
$label = $labelId ? Label::find($labelId) : null;
$error = '';

if (!$label) {
    $content = '<p class="text-red-600">Etiqueta no encontrada.</p>';
    include __DIR__ . '/layout.php';
    return;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = trim($_POST['name'] ?? '');
    $color = trim($_POST['color'] ?? '');
    if ($name === '') {
        $error = 'El nombre es obligatorio';
    } else {
        $label->name = $name;
        $label->color = $color;
        $label->store();
        header('Location: ?view=labels_list&updated=1');
        exit;
    }
}

ob_start();
?>
<h2 class="text-xl font-bold mb-4">Editar etiqueta</h2>
<form method="post" class="bg-white p-6 rounded shadow max-w-md mx-auto">
    <label class="block mb-2 font-semibold">Nombre:
        <input type="text" name="name" value="<?= htmlspecialchars(is_object($label) ? $label->name : ($label['name'] ?? '')) ?>" required class="border rounded px-2 py-1 w-full">
    </label>
    <label class="block mb-4 font-semibold">Color:
        <input type="color" name="color" value="<?= htmlspecialchars(is_object($label) ? ($label->color ?? '#333333') : ($label['color'] ?? '#333333')) ?>" class="ml-2">
    </label>
    <div class="flex gap-2">
        <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded">Guardar cambios</button>
        <a href="?view=labels_list" class="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded">Volver</a>
    </div>
</form>
<?php if ($error): ?><p class="text-red-600 mt-2"><?= htmlspecialchars($error) ?></p><?php endif; ?>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
