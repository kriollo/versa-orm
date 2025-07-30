<!-- views/new.php: Formulario de nueva tarea -->
<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <title>Nueva Tarea</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>

<body class="bg-gray-100 min-h-screen">
    <div class="max-w-md mx-auto mt-16 bg-white rounded-lg shadow-lg p-8">
        <h1 class="text-2xl font-bold text-blue-800 mb-6">Nueva Tarea</h1>
        <form method="post" action="?action=create" class="bg-white shadow rounded-lg p-6 max-w-lg mx-auto">
            <?php if (isset($_GET['project_id'])): ?>
                <input type="hidden" name="project_id" value="<?= htmlspecialchars($_GET['project_id']) ?>">
            <?php endif; ?>
            <div class="mb-4">
                <label class="block text-gray-700 font-semibold mb-2">Título:</label>
                <input type="text" name="title" required
                    class="w-full border border-gray-300 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400" />
            </div>
            <div class="mb-4">
                <label class="block text-gray-700 font-semibold mb-2">Descripción:</label>
                <textarea name="description"
                    class="w-full border border-gray-300 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400"></textarea>
            </div>
            <div class="mb-4 flex items-center">
                <input type="checkbox" name="completed" id="completed" class="mr-2">
                <label for="completed" class="text-gray-700">Completada</label>
            </div>
            <div class="flex justify-end space-x-2">
                <button type="submit"
                    class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded shadow">Crear Tarea
                </button>
                <a href="index.php"
                    class="bg-gray-300 hover:bg-gray-400 text-gray-800 px-4 py-2 rounded">Cancelar</a>
            </div>
        </form>
    </div>
</body>

</html>
