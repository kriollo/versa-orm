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
?>
<h2>Nueva etiqueta</h2>
<form method="post">
    <label>Nombre: <input type="text" name="name" required></label><br>
    <label>Color: <input type="color" name="color" value="#333333"></label><br>
    <button type="submit">Crear</button>
</form>
<?php if ($error): ?><p style="color:red;"><?= htmlspecialchars($error) ?></p><?php endif; ?>
