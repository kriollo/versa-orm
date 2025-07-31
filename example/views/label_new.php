<?php
// Vista: Crear nueva etiqueta
use Example\Models\Label;

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = trim($_POST['name'] ?? '');
    $color = trim($_POST['color'] ?? '');
    if ($name === '') {
        $error = 'El nombre es obligatorio';
    } else {
        Label::create(['name' => $name, 'color' => $color]);
        header('Location: ?view=labels_list&created=1');
        exit;
    }
}
ob_start();
?>
<h2 class="text-xl font-bold mb-4">Nueva etiqueta</h2>
<form method="post" class="bg-white p-6 rounded shadow max-w-md mx-auto">
    <label class="block mb-2 font-semibold">Nombre:
        <input type="text" name="name" required class="border rounded px-2 py-1 w-full">
    </label>
    <label class="block mb-4 font-semibold">Color:
        <input type="color" name="color" value="#333333" class="ml-2">
    </label>
    <div class="flex gap-2">
        <button type="submit" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded">Crear</button>
        <a href="?view=labels_list" class="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded">Volver</a>
    </div>
</form>
<?php if ($error): ?><p class="text-red-600 mt-2"><?= htmlspecialchars($error) ?></p><?php endif; ?>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
