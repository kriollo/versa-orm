<?php
// Vista: Editar proyecto
/** @var array<string, mixed> $project */
?>
<h1 class="text-2xl font-bold text-blue-800 mb-6">Editar Proyecto</h1>
<form method="post" action="?action=update_project" class="bg-white shadow rounded-lg p-6 max-w-lg mx-auto">
    <input type="hidden" name="id" value="<?= $project['id'] ?>" />
    <div class="mb-4">
        <label class="block text-gray-700 font-semibold mb-2">Nombre:</label>
        <input type="text" name="name" value="<?= htmlspecialchars($project['name']) ?>" required class="w-full border border-gray-300 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400" />
    </div>
    <div class="mb-4">
        <label class="block text-gray-700 font-semibold mb-2">Descripción:</label>
        <textarea name="description" class="w-full border border-gray-300 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400"><?= htmlspecialchars($project['description']) ?></textarea>
    </div>
    <div class="flex justify-end space-x-2">
        <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded shadow">Actualizar</button>
        <a href="?action=projects" class="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded">Cancelar</a>
    </div>
</form>
<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
