<?php

declare(strict_types=1);

/**
 * Ejemplo simple de configuración de logs con VersaORM
 */

require_once __DIR__ . '/../vendor/autoload.php';

// Incluir las clases del ejemplo
require_once __DIR__ . '/BaseModel.php';
require_once __DIR__ . '/UserModel.php';

use VersaORM\VersaORM;
use VersaORM\ErrorHandler;
use App\Models\UserModel;

echo "=== VersaORM Log Configuration Example ===\n\n";

// 1. Configurar VersaORM con log_path
echo "1. Configuring VersaORM with log_path...\n";
$config = [
    'driver' => 'sqlite',
    'database' => ':memory:',
    'debug' => true,
    'log_path' => __DIR__ . '/logs', // Los logs se guardarán aquí
];

$orm = new VersaORM($config);
echo "✓ VersaORM configured with log_path: " . $config['log_path'] . "\n";
echo "✓ ErrorHandler configured automatically\n";
echo "✓ Log directory created: " . (is_dir($config['log_path']) ? 'Yes' : 'No') . "\n\n";

// 2. Configurar modelo
UserModel::setORM($orm);

// Crear tabla para el ejemplo
$orm->exec("
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
");

// 3. Generar algunos logs
echo "2. Generating log entries...\n";

// Operación exitosa
try {
    $user = new UserModel([
        'name' => 'John Doe',
        'email' => 'john@example.com'
    ]);
    $user->store();
    echo "✓ Successful operation logged\n";
} catch (Exception $e) {
    echo "✓ Error logged: " . $e->getMessage() . "\n";
}

// Operación con error (email duplicado)
try {
    $user2 = new UserModel([
        'name' => 'Jane Doe',
        'email' => 'john@example.com' // Email duplicado
    ]);
    $user2->store();
    echo "✓ Duplicate email operation logged\n";
} catch (Exception $e) {
    echo "✓ Error operation logged: " . $e->getMessage() . "\n";
}

// Operación con datos inválidos
try {
    $user3 = new UserModel([
        'name' => '', // Nombre vacío
        'email' => 'invalid-email' // Email inválido
    ]);
    $user3->store();
    echo "✓ Invalid data operation logged\n";
} catch (Exception $e) {
    echo "✓ Validation error logged: " . $e->getMessage() . "\n";
}
echo "\n";

// 4. Mostrar archivos de log generados
echo "3. Generated log files:\n";
$logPath = ErrorHandler::getLogPath();

if ($logPath && is_dir($logPath)) {
    $logFiles = glob($logPath . DIRECTORY_SEPARATOR . '*.log');

    foreach ($logFiles as $logFile) {
        $filename = basename($logFile);
        $size = filesize($logFile);
        $lineCount = count(file($logFile));

        echo "📄 {$filename}\n";
        echo "   Size: {$size} bytes\n";
        echo "   Lines: {$lineCount}\n";

        // Mostrar contenido del archivo
        echo "   Content preview:\n";
        $lines = file($logFile, FILE_IGNORE_NEW_LINES);
        foreach (array_slice($lines, 0, 3) as $line) {
            $data = json_decode($line, true);
            if ($data) {
                $timestamp = $data['timestamp'] ?? 'unknown';
                $type = $data['error_code'] ?? $data['operation'] ?? 'operation';
                $message = $data['message'] ?? $data['success'] ?? 'N/A';
                echo "   └─ [{$timestamp}] {$type}: {$message}\n";
            }
        }
        echo "\n";
    }
} else {
    echo "❌ No log directory found\n";
}

// 5. Mostrar configuración actual
echo "4. Current ErrorHandler configuration:\n";
echo "   Debug mode: " . (ErrorHandler::isConfigured() ? 'Yes' : 'No') . "\n";
echo "   Log path: " . (ErrorHandler::getLogPath() ?: 'Not configured') . "\n";
echo "   Error count in memory: " . count(ErrorHandler::getErrorLog()) . "\n\n";

// 6. Ejemplo de acceso a logs programáticamente
echo "5. Accessing logs programmatically:\n";
$errorLog = ErrorHandler::getErrorLog();

if (!empty($errorLog)) {
    $lastError = end($errorLog);
    echo "   Last error:\n";
    echo "   - Code: " . $lastError['error']['error_code'] . "\n";
    echo "   - Message: " . $lastError['error']['message'] . "\n";
    echo "   - Origin: " . $lastError['origin']['type'] . " in " . $lastError['origin']['location'] . "\n";
} else {
    echo "   No errors in memory log\n";
}

echo "\n=== Example completed ===\n";
echo "Check the generated log files in: {$logPath}\n";
