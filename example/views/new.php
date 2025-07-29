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
        <h1 class="text-2xl font-bold mb-6 text-green-700">Nueva Tarea</h1>
        <form method="post" action="?action=create" class="space-y-4">
            <label class="block">
                <span class="text-gray-700">Título</span>
                <input type="text" name="title" required class="mt-1 block w-full border rounded px-3 py-2">
            </label>
            <label class="block">
                <span class="text-gray-700">Descripción</span>
                <textarea name="description" class="mt-1 block w-full border rounded px-3 py-2" rows="3"></textarea>
            </label>
            <label class="flex items-center gap-2">
                <input type="checkbox" name="completed" class="form-checkbox h-5 w-5 text-green-600">
                <span class="text-gray-700">Completada</span>
            </label>
            <div class="flex gap-4 mt-6">
                <button type="submit" class="bg-green-600 text-white px-4 py-2 rounded hover:bg-green-700">Crear
                </button>
                <a href="index.php"
                    class="bg-gray-300 text-gray-700 px-4 py-2 rounded hover:bg-gray-400">Cancelar</a>
            </div>
        </form>
    </div>
</body>

</html>
