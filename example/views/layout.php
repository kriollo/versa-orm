<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $title ?? 'VersaORM Trello Demo' ?></title>
    <script>
        // Apply theme ASAP to avoid FOUC
        (function () {
            try {
                const stored = localStorage.getItem('darkMode');
                const prefers = window.matchMedia('(prefers-color-scheme: dark)').matches;
                const isDark = stored === 'true' || (stored === null && prefers);
                document.documentElement.classList.toggle('dark', isDark);
            } catch (e) {
                // If access to localStorage fails, fall back to system preference
                if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
                    document.documentElement.classList.add('dark');
                }
            }
        })();
    </script>
    <script>
        // Configure Tailwind CDN to use class-based dark mode
        window.tailwind = window.tailwind || {};
        window.tailwind.config = {
            darkMode: 'class'
        };
    </script>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        [x-cloak] { display: none !important; }
        .kanban-column {
            min-height: 400px;
        }

        .task-card:hover {
            transform: translateY(-2px);
            transition: transform 0.2s ease;
        }

        .avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 14px;
        }
    </style>
</head>

<body class="bg-gray-50 dark:bg-gray-900 transition-colors duration-200" :class="{ 'dark': darkMode }" x-data="{ darkMode: (localStorage.getItem('darkMode') === null ? window.matchMedia('(prefers-color-scheme: dark)').matches : localStorage.getItem('darkMode') === 'true') }" x-init="$nextTick(() => { document.documentElement.classList.toggle('dark', darkMode); $watch('darkMode', val => { localStorage.setItem('darkMode', val); document.documentElement.classList.toggle('dark', val); }); })">
    <!-- Navegación -->
    <nav class="bg-white dark:bg-gray-800 shadow-sm border-b dark:border-gray-700 transition-colors duration-200">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between h-16">
                <div class="flex items-center">
                    <a href="/" class="flex items-center space-x-2">
                        <i class="fas fa-tasks text-2xl text-blue-600"></i>
                        <span class="text-xl font-bold text-gray-900 dark:text-white">VersaORM Trello</span>
                    </a>
                </div>

                <div class="flex items-center space-x-4">
                    <button @click="darkMode = !darkMode; localStorage.setItem('darkMode', darkMode); document.documentElement.classList.toggle('dark', darkMode)" x-bind:aria-pressed="darkMode" class="text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 px-3 py-2 rounded-md text-sm font-medium transition-colors duration-200" aria-label="Cambiar tema" title="Cambiar tema">
                        <i x-show="!darkMode" x-cloak class="fas fa-moon"></i>
                        <i x-show="darkMode" x-cloak class="fas fa-sun"></i>
                    </button>
                    <a href="/" class="text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 px-3 py-2 rounded-md text-sm font-medium">
                        <i class="fas fa-home mr-1"></i> Inicio
                    </a>
                    <a href="/projects?action=projects" class="text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 px-3 py-2 rounded-md text-sm font-medium">
                        <i class="fas fa-folder mr-1"></i> Proyectos
                    </a>
                    <a href="/tasks?action=tasks" class="text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 px-3 py-2 rounded-md text-sm font-medium">
                        <i class="fas fa-tasks mr-1"></i> Tareas
                    </a>
                    <a href="/labels?action=labels" class="text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 px-3 py-2 rounded-md text-sm font-medium">
                        <i class="fas fa-tags mr-1"></i> Etiquetas
                    </a>
                    <a href="/users?action=users" class="text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 px-3 py-2 rounded-md text-sm font-medium">
                        <i class="fas fa-users mr-1"></i> Usuarios
                    </a>
                </div>
            </div>
        </div>
    </nav>

    <!-- Mensajes Flash -->
    <?php $flash = getFlash(); ?>
    <?php if ($flash): ?>
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-4">
            <div class="alert alert-<?= $flash['type'] ?> p-4 rounded-md transition-colors duration-200 <?= $flash['type'] === 'success' ? 'bg-green-100 dark:bg-green-900/30 border border-green-200 dark:border-green-700 text-green-800 dark:text-green-300' : 'bg-red-100 dark:bg-red-900/30 border border-red-200 dark:border-red-700 text-red-800 dark:text-red-300' ?>">
                <i class="fas fa-<?= $flash['type'] === 'success' ? 'check-circle' : 'exclamation-circle' ?> mr-2"></i>
                <?= htmlspecialchars($flash['message']) ?>
            </div>
        </div>
    <?php endif; ?>

    <!-- Contenido principal -->
    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 transition-colors duration-200">
        <?= $content ?>
    </main>

    <!-- Footer -->
    <footer class="bg-white dark:bg-gray-800 border-t dark:border-gray-700 mt-16 transition-colors duration-200">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <div class="text-center text-gray-500 dark:text-gray-400">
                <p>&copy; 2025 VersaORM Trello Demo. Demostrando las capacidades de VersaORM-PHP.</p>
            </div>
        </div>
    </footer>

    <script>
        // Helper functions
        function getAvatarInitials(name) {
            return name.split(' ').map(n => n[0]).join('').toUpperCase().substring(0, 2);
        }

        // Auto-hide flash messages
        document.addEventListener('DOMContentLoaded', function() {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                setTimeout(() => {
                    alert.style.opacity = '0';
                    alert.style.transition = 'opacity 0.5s ease';
                    setTimeout(() => alert.remove(), 500);
                }, 5000);
            });
        });
    </script>
</body>

</html>
