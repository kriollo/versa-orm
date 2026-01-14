<?php

declare(strict_types=1);

/**
 * Bootstrap para tests de compatibilidad PHP.
 */

// Configurar timezone por defecto
date_default_timezone_set('UTC');

// Configurar error reporting
error_reporting(E_ALL);
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');

// Configurar memoria y tiempo de ejecución
ini_set('memory_limit', '256M');
ini_set('max_execution_time', '300');

// Autoload paths
$autoloadPaths = [
    __DIR__ . '/../../vendor/autoload.php',
    __DIR__ . '/../../../../vendor/autoload.php',
];

$autoloaded = false;

foreach ($autoloadPaths as $autoloadPath) {
    if (file_exists($autoloadPath)) {
        require_once $autoloadPath;
        $autoloaded = true;
        break;
    }
}

// Si no hay autoloader, cargar clases manualmente
if (!$autoloaded) {
    // Cargar clases de VersaORM
    $versaormPaths = [
        __DIR__ . '/../../src/VersaORM.php',
        __DIR__ . '/../../src/QueryBuilder.php',
        __DIR__ . '/../../src/VersaModel.php',
    ];

    foreach ($versaormPaths as $path) {
        if (file_exists($path)) {
            require_once $path;
        }
    }

    // Cargar clases de test
    require_once __DIR__ . '/PHPVersionDetector.php';
    require_once __DIR__ . '/PHPVersionTestExecutor.php';
    require_once __DIR__ . '/PHPVersionMatrixRunner.php';
    require_once __DIR__ . '/../Results/TestResult.php';
    require_once __DIR__ . '/../Results/Report.php';
}

// Crear directorio de reportes si no existe
$reportsDir = __DIR__ . '/../reports/php-compatibility';

if (!is_dir($reportsDir)) {
    mkdir($reportsDir, 0755, true);
}

// Configurar variables de entorno para tests
$_ENV['TESTING'] = true;
$_ENV['PHP_VERSION_TESTING'] = true;

// Función helper para logging de tests
function logCompatibilityTest(string $message, string $level = 'INFO'): void
{
    $timestamp = date('Y-m-d H:i:s');
    $phpVersion = PHP_VERSION;
    $logMessage = "[{$timestamp}] [{$level}] [PHP {$phpVersion}] {$message}" . PHP_EOL;

    $logFile = __DIR__ . '/../reports/php-compatibility/test.log';
    file_put_contents($logFile, $logMessage, FILE_APPEND | LOCK_EX);
}

// Log inicio de tests
logCompatibilityTest('PHP Compatibility tests bootstrap loaded');
logCompatibilityTest('PHP Version: ' . PHP_VERSION);
logCompatibilityTest('PHP Version ID: ' . PHP_VERSION_ID);
logCompatibilityTest('SAPI: ' . PHP_SAPI);
logCompatibilityTest('OS: ' . PHP_OS_FAMILY);
logCompatibilityTest('Memory Limit: ' . ini_get('memory_limit'));
logCompatibilityTest('Max Execution Time: ' . ini_get('max_execution_time'));

// Verificar extensiones requeridas
$requiredExtensions = ['pdo', 'json', 'mbstring'];
$missingExtensions = [];

foreach ($requiredExtensions as $extension) {
    if (!extension_loaded($extension)) {
        $missingExtensions[] = $extension;
    }
}

if ($missingExtensions !== []) {
    logCompatibilityTest('Missing required extensions: ' . implode(', ', $missingExtensions), 'WARNING');
}

// Verificar extensiones recomendadas
$recommendedExtensions = ['pdo_mysql', 'pdo_pgsql', 'pdo_sqlite', 'openssl', 'curl'];
$missingRecommended = [];

foreach ($recommendedExtensions as $extension) {
    if (!extension_loaded($extension)) {
        $missingRecommended[] = $extension;
    }
}

if ($missingRecommended !== []) {
    logCompatibilityTest('Missing recommended extensions: ' . implode(', ', $missingRecommended), 'INFO');
}

// Configurar handler de errores para tests
set_error_handler(static function ($severity, $message, $file, $line): bool {
    // Solo log errores críticos durante tests
    if (($severity & (E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR | E_USER_ERROR)) !== 0) {
        logCompatibilityTest("PHP Error: {$message} in {$file}:{$line}", 'ERROR');
    }

    return false; // Permitir que el handler por defecto también procese el error
});

// Configurar handler de excepciones no capturadas
set_exception_handler(static function ($exception): void {
    logCompatibilityTest(
        'Uncaught Exception: ' . $exception->getMessage() . ' in ' . $exception->getFile() . ':'
            . $exception->getLine(),
        'ERROR',
    );
    logCompatibilityTest('Stack trace: ' . $exception->getTraceAsString(), 'ERROR');
});

// Configurar shutdown handler para cleanup
register_shutdown_function(static function (): void {
    $error = error_get_last();

    if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        logCompatibilityTest("Fatal Error: {$error['message']} in {$error['file']}:{$error['line']}", 'FATAL');
    }

    logCompatibilityTest('PHP Compatibility tests completed');

    // Limpiar memoria
    if (function_exists('gc_collect_cycles')) {
        gc_collect_cycles();
    }
});

// PHP 8.0+ configuraciones
logCompatibilityTest('PHP 8.0+ features available');

if (PHP_VERSION_ID >= 80100) {
    // PHP 8.1+ configuraciones
    logCompatibilityTest('PHP 8.1+ features available');
}

if (PHP_VERSION_ID >= 80200) {
    // PHP 8.2+ configuraciones
    logCompatibilityTest('PHP 8.2+ features available');
}

if (PHP_VERSION_ID >= 80300) {
    // PHP 8.3+ configuraciones
    logCompatibilityTest('PHP 8.3+ features available');
}

logCompatibilityTest('Bootstrap completed successfully');
