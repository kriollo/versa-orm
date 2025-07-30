<!-- views/edit.php: Formulario de edición -->
<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <title>Editar Tarea</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>

<body class="bg-gray-100 min-h-screen">
    <div class="max-w-md mx-auto mt-16 bg-white rounded-lg shadow-lg p-8">
        <h1 class="text-2xl font-bold mb-6 text-blue-800">Editar Tarea</h1>
        <form method="post" action="?action=update" class="bg-white shadow rounded-lg p-6 max-w-lg mx-auto">
            <input type="hidden" name="id" value="<?= is_array($task) ? $task['id'] : $task->id ?>" />
            <div class="mb-4">
                <label class="block text-gray-700 font-semibold mb-2">Título:</label>
                <input type="text" name="title" value="<?= htmlspecialchars(is_array($task) ? $task['title'] : $task->title) ?>"
                    required
                    class="w-full border border-gray-300 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400" />
            </div>
            <div class="mb-4">
                <label class="block text-gray-700 font-semibold mb-2">Descripción:</label>
                <textarea name="description"
                    class="w-full border border-gray-300 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400"><?= htmlspecialchars(is_array($task) ? $task['description'] : $task->description) ?></textarea>
            </div>
            <div class="mb-4 flex items-center">
                <input type="checkbox" name="completed" id="completed" class="mr-2"
                    <?= (is_array($task) ? $task['completed'] : $task->completed) ? 'checked' : '' ?> />
                <label for="completed" class="text-gray-700">Completada</label>
            </div>
            <div class="flex justify-end space-x-2">
                <button type="submit"
                    class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded shadow">Actualizar</button>
                <a href="index.php"
                    class="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded">Cancelar</a>
            </div>
        </form>
    </div>
</body>

</html>
