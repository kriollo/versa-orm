<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gestor de Proyectos y Tareas | VersaORM</title>
    <script src="https://cdn.tailwindcss.com/"></script>
</head>

<body class="bg-gray-100 min-h-screen">
    <nav class="bg-blue-700 text-white px-6 py-4 shadow">
        <div class="flex items-center justify-between">
            <a href="index.php" class="text-2xl font-bold tracking-tight">VersaORM Demo</a>
            <div class="space-x-4">
                <a href="index.php" class="hover:underline">Tareas</a>
                <a href="?action=projects" class="hover:underline">Proyectos</a>
            </div>
        </div>
    </nav>
    <main class="container mx-auto px-4 py-8">
        <?php if (isset($content)) echo $content; ?>
    </main>
    <footer class="text-center text-gray-500 py-4 text-xs">
        VersaORM-PHP &copy; <?= date('Y') ?> | Demo avanzada con TailwindCSS
    </footer>
</body>

</html>
