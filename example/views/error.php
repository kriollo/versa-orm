<?php $title = 'Error - VersaORM Trello Demo'; ?>

<div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
    <div class="max-w-md w-full space-y-8">
        <div class="text-center">
            <i class="fas fa-exclamation-triangle text-6xl text-red-500 mb-4"></i>
            <h2 class="mt-6 text-3xl font-extrabold text-gray-900 dark:text-white">
                ¡Oops! Algo salió mal
            </h2>
            <p class="mt-2 text-sm text-gray-600 dark:text-gray-400">
                Ha ocurrido un error en la aplicación
            </p>
        </div>

        <div class="bg-white dark:bg-gray-800 shadow rounded-lg p-6">
            <div class="mb-4">
                <h3 class="text-lg font-medium text-gray-900 dark:text-white mb-2">Detalles del Error:</h3>
                <div class="bg-red-50 dark:bg-red-900 dark:bg-opacity-20 border border-red-200 dark:border-red-800 rounded-md p-4">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <i class="fas fa-exclamation-circle text-red-400"></i>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm text-red-700 dark:text-red-300">
                                <?php echo htmlspecialchars($message ?? 'Error desconocido'); ?>
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            <div class="flex flex-col space-y-3">
                <a href="?action=dashboard"
                    class="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                    <i class="fas fa-home mr-2"></i>
                    Volver al Dashboard
                </a>

                <a href="javascript:history.back()"
                    class="w-full flex justify-center py-2 px-4 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                    <i class="fas fa-arrow-left mr-2"></i>
                    Página Anterior
                </a>

                <button onclick="location.reload()"
                    class="w-full flex justify-center py-2 px-4 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                    <i class="fas fa-redo mr-2"></i>
                    Reintentar
                </button>
            </div>
        </div>

        <?php if (isset($config['app']['debug']) && $config['app']['debug']) { ?>
            <div class="bg-gray-100 dark:bg-gray-800 rounded-lg p-4">
                <h4 class="text-sm font-medium text-gray-900 dark:text-white mb-2">Información de Debug:</h4>
                <div class="text-xs text-gray-600 dark:text-gray-400 font-mono">
                    <p><strong>Timestamp:</strong> <?php echo date('Y-m-d H:i:s'); ?></p>
                    <p><strong>Método:</strong> <?php echo $_SERVER['REQUEST_METHOD'] ?? 'N/A'; ?></p>
                    <p><strong>URI:</strong> <?php echo $_SERVER['REQUEST_URI'] ?? 'N/A'; ?></p>
                    <p><strong>User Agent:</strong> <?php echo substr($_SERVER['HTTP_USER_AGENT'] ?? 'N/A', 0, 100); ?>...</p>
                </div>
            </div>
        <?php } ?>

        <div class="text-center">
            <p class="text-xs text-gray-500 dark:text-gray-400">
                Si el problema persiste, contacta al administrador del sistema.
            </p>
        </div>
    </div>
</div>
