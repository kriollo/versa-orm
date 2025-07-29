<!-- views/list.php: Listado de tareas -->
<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <title>Gestor de Tareas</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>

<body class="bg-gray-100 min-h-screen">
    <div class="max-w-4xl mx-auto mt-10 bg-white rounded-lg shadow-lg p-8">
        <h1 class="text-3xl font-bold mb-6 text-blue-700">Gestor de Tareas</h1>

        <!-- Filtros y estadísticas -->
        <form method="get" class="flex flex-wrap gap-4 items-center mb-4">
            <input type="text" name="search"
                value="<?= htmlspecialchars($_GET['search'] ?? '') ?>"
                placeholder="Buscar título o descripción"
                class="border rounded px-3 py-2 w-48">
            <select name="status" class="border rounded px-3 py-2">
                <option value="">Todos</option>
                <option value="1" <?= ($_GET['status'] ?? '') === '1' ? 'selected' : '' ?>>Completadas
                </option>
                <option value="0" <?= ($_GET['status'] ?? '') === '0' ? 'selected' : '' ?>>Pendientes
                </option>
            </select>
            <select name="order" class="border rounded px-3 py-2">
                <option value="id" <?= ($_GET['order'] ?? '') === 'id' ? 'selected' : '' ?>>ID</option>
                <option value="title" <?= ($_GET['order'] ?? '') === 'title' ? 'selected' : '' ?>>Título
                </option>
                <option value="created_at" <?= ($_GET['order'] ?? '') === 'created_at' ? 'selected' : '' ?>>Creación
                </option>
            </select>
            <select name="dir" class="border rounded px-3 py-2">
                <option value="desc" <?= ($_GET['dir'] ?? '') === 'desc' ? 'selected' : '' ?>>Descendente
                </option>
                <option value="asc" <?= ($_GET['dir'] ?? '') === 'asc' ? 'selected' : '' ?>>Ascendente
                </option>
            </select>
            <select name="perPage" class="border rounded px-3 py-2">
                <?php foreach ([5, 10, 20, 50, 100] as $n): ?>
                    <option value="<?= $n ?>" <?= ($perPage ?? 10) == $n ? 'selected' : '' ?>><?= $n ?> por página
                    </option>
                <?php endforeach; ?>
            </select>
            <button type="submit"
                class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">Filtrar</button>
            <a href="index.php"
                class="bg-gray-300 text-gray-700 px-4 py-2 rounded hover:bg-gray-400">Reset</a>
        </form>
        <div class="mb-6 text-sm text-gray-700">
            <span class="mr-4"><b>Total:</b> <?= $total ?></span>
            <span class="mr-4"><b>Completadas:</b> <?= $completed ?></span>
            <span><b>Pendientes:</b> <?= $pending ?></span>
        </div>

        <!-- Tabla de tareas -->
        <div class="overflow-x-auto">
            <table class="w-full border rounded-lg">
                <thead class="bg-blue-100">
                    <tr>
                        <th class="px-3 py-2 text-left">ID</th>
                        <th class="px-3 py-2 text-left">Título</th>
                        <th class="px-3 py-2 text-left">Descripción</th>
                        <th class="px-3 py-2 text-left">Completada</th>
                        <th class="px-3 py-2 text-left">Creación</th>
                        <th class="px-3 py-2 text-left">Actualización</th>
                        <th class="px-3 py-2 text-left">Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($tasks as $task): ?>
                        <tr class="border-b hover:bg-blue-50">
                            <td class="px-3 py-2"><?= $task->id ?></td>
                            <td class="px-3 py-2"><?= htmlspecialchars($task->title) ?></td>
                            <td class="px-3 py-2"><?= htmlspecialchars($task->description) ?></td>
                            <td class="px-3 py-2">
                                <span class="inline-block px-2 py-1 rounded text-xs <?= $task->completed ? 'bg-green-200 text-green-800' : 'bg-yellow-200 text-yellow-800' ?>">
                                    <?= $task->completed ? 'Sí' : 'No' ?>
                                </span>
                            </td>
                            <td class="px-3 py-2 text-xs text-gray-600"><?= $task->created_at ? date('d/m/Y H:i', strtotime($task->created_at)) : '-' ?></td>
                            <td class="px-3 py-2 text-xs text-gray-600"><?= $task->updated_at ? date('d/m/Y H:i', strtotime($task->updated_at)) : '-' ?></td>
                            <td class="px-3 py-2 flex gap-2">
                                <a href="?action=edit&id=<?= $task->id ?>"
                                    class="bg-yellow-400 text-white px-3 py-1 rounded hover:bg-yellow-500">Editar</a>
                                <a href="?action=delete&id=<?= $task->id ?>"
                                    class="bg-red-500 text-white px-3 py-1 rounded hover:bg-red-600"
                                    onclick="return confirm('¿Eliminar tarea?')">Eliminar</a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <!-- Paginación -->
        <?php
        $totalPages = ceil($total / $perPage);
        $currentPage = max(1, (int)($_GET['page'] ?? 1));
        if ($totalPages > 1): ?>
            <nav class="flex gap-2 mt-6">
                <?php for ($p = 1; $p <= $totalPages; $p++): ?>
                    <a href="?<?= http_build_query(array_merge($_GET, ['page' => $p, 'perPage' => $perPage])) ?>"
                        class="px-3 py-1 rounded <?= $p == $currentPage ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300' ?>">
                        <?= $p == $currentPage ? '<b>Página ' . $p . '</b>' : 'Página ' . $p ?>
                    </a>
                <?php endfor; ?>
            </nav>
        <?php endif; ?>
        <a href="?action=new"
            class="bg-green-600 text-white px-4 py-2 rounded mt-8 inline-block hover:bg-green-700">Nueva Tarea</a>
    </div>
</body>

</html>
