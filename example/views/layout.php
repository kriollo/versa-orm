| Gestión de Proyectos</title>
<script src="https://cdn.tailwindcss.com/"></script>
<script>
    tailwind.config = {
        theme: {
            extend: {
                colors: {
                    'trello-blue': '#0079bf',
                    'trello-green': '#61bd4f',
                    'trello-orange': '#ffab4a',
                    'trello-red': '#eb5a46',
                    'trello-purple': '#c377e0',
                }
            }
        }
    }
</script>
</head>

<body class="bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 min-h-screen">
    <nav class="bg-gradient-to-r from-trello-blue to-indigo-700 text-white shadow-lg sticky top-0 z-50">
        <div class="container mx-auto px-4">
            <div class="flex items-center justify-between h-16">
                <a href="index.php" class="flex items-center space-x-3 group">
                    <div class="bg-white/20 p-2 rounded-lg group-hover:bg-white/30 transition-colors">
                        <svg class="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <rect x="3" y="3" width="7" height="18" rx="2" fill="currentColor" opacity="0.7" />
                            <rect x="14" y="3" width="7" height="18" rx="2" fill="currentColor" opacity="0.5" />
                        </svg>
                    </div>
                    <div>
                        <h1 class="text-xl font-bold">VersaORM Trello</h1>
                        <p class="text-xs text-blue-200">Gestión de Proyectos</p>
                    </div>
                </a>

                <div class="hidden md:flex items-center space-x-1">
                    <a href="index.php" class="px-4 py-2 rounded-lg hover:bg-white/20 transition-colors font-medium">
                        <span class="mr-2">🏠</span>Proyectos
                    </a>
                    <a href="?action=tasks" class="px-4 py-2 rounded-lg hover:bg-white/20 transition-colors font-medium">
                        <span class="mr-2">📋</span>Tareas
                    </a>
                    <a href="?view=labels_list" class="px-4 py-2 rounded-lg hover:bg-white/20 transition-colors font-medium">
                        <span class="mr-2">🏷️</span>Etiquetas
                    </a>
                </div>

                <div class="flex items-center space-x-3">
                    <a href="?action=new_project"
                        class="bg-trello-green hover:bg-green-600 px-4 py-2 rounded-lg font-medium transition-colors flex items-center">
                        <span class="mr-2">➕</span>Nuevo Proyecto
                    </a>
                </div>
            </div>
        </div>
    </nav>

    <main class="container mx-auto px-4 py-8">
        <?= $content ?>
    </main>

    <footer class="bg-white/70 backdrop-blur-sm border-t border-gray-200 mt-16">
        <div class="container mx-auto px-4 py-6 text-center">
            <p class="text-gray-600 text-sm">
                VersaORM-PHP &copy; <?= date('Y') ?> ||
                <a href="https://github.com/kriollo/versa-orm" class="text-trello-blue hover:underline">GitHub</a>
            </p>
        </div>
    </footer>
</body>

</html>
