<?php

declare(strict_types=1);

/**
 * Ejemplo completo de uso del sistema de manejo de errores de VersaORM
 */

require_once __DIR__ . '/../vendor/autoload.php';

use VersaORM\VersaORM;
use VersaORM\ErrorHandler;
use App\Models\UserModel;
use App\Controllers\UserController;

// Configuración inicial
define('APP_DEBUG', true);

// Configurar VersaORM
$config = [
    'driver' => 'sqlite',
    'database' => ':memory:', // Base de datos en memoria para el ejemplo
];

$orm = new VersaORM($config);
UserModel::setORM($orm);

// Configurar ErrorHandler
ErrorHandler::setDebugMode(true);
ErrorHandler::setCustomHandler(function ($errorData) {
    // Handler personalizado - puedes enviar a tu sistema de logging
    echo "🚨 Custom Error Handler: " . $errorData['error']['message'] . "\n";
});

// Crear tabla de usuarios para el ejemplo
$orm->exec("
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        status TEXT DEFAULT 'inactive',
        email_verified_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
");

echo "=== VersaORM Error Handling System Demo ===\n\n";

// Ejemplo 1: Crear usuario exitosamente
echo "1. Creating user successfully:\n";
$controller = new UserController();
$result = $controller->create([
    'name' => 'John Doe',
    'email' => 'john@example.com',
    'password' => 'securepassword123',
]);
echo json_encode($result, JSON_PRETTY_PRINT) . "\n\n";

// Ejemplo 2: Intentar crear usuario con email duplicado
echo "2. Attempting to create user with duplicate email:\n";
$result = $controller->create([
    'name' => 'Jane Doe',
    'email' => 'john@example.com', // Email duplicado
    'password' => 'anotherpassword123',
]);
echo json_encode($result, JSON_PRETTY_PRINT) . "\n\n";

// Ejemplo 3: Crear usuario con datos inválidos
echo "3. Creating user with invalid data:\n";
$result = $controller->create([
    'name' => 'A', // Nombre muy corto
    'email' => 'invalid-email', // Email inválido
    'password' => '123', // Password muy corto
]);
echo json_encode($result, JSON_PRETTY_PRINT) . "\n\n";

// Ejemplo 4: Usar métodos seguros del modelo directamente
echo "4. Using safe model methods directly:\n";
$user = new UserModel([
    'name' => 'Safe User',
    'email' => 'safe@example.com',
    'password' => 'safepassword123',
]);

// Configurar para no lanzar excepciones
UserModel::configureErrorHandling([
    'throw_on_error' => false,
    'format_for_api' => true,
]);

$result = $user->safeSave();
if ($user->hasError()) {
    echo "Error occurred:\n";
    echo "Message: " . $user->getLastErrorMessage() . "\n";
    echo "Code: " . $user->getLastErrorCode() . "\n";
    echo "Suggestions:\n";
    foreach ($user->getLastErrorSuggestions() as $suggestion) {
        echo "  - $suggestion\n";
    }
} else {
    echo "User saved successfully!\n";
    echo json_encode($user->toApiResponse(), JSON_PRETTY_PRINT) . "\n";
}
echo "\n";

// Ejemplo 5: Manejo de errores con try-catch tradicional
echo "5. Traditional try-catch error handling:\n";
try {
    $user = UserModel::find(999); // ID que no existe
    echo "User found: " . json_encode($user->toArray()) . "\n";
} catch (VersaORM\VersaORMException $e) {
    $errorData = ErrorHandler::handleException($e, [
        'operation' => 'find_user',
        'user_id' => 999,
    ]);

    echo "Caught VersaORMException:\n";
    echo ErrorHandler::formatForDevelopment($errorData);
}

// Ejemplo 6: Estadísticas de errores
echo "6. Error statistics:\n";
$stats = UserModel::getErrorStats();
echo json_encode($stats, JSON_PRETTY_PRINT) . "\n\n";

// Ejemplo 7: Debugging del último error
echo "7. Debug last error:\n";
$user = new UserModel();
$user->setAttribute('name', ''); // Nombre vacío para causar error
$user->safeSave();
$user->debugLastError();

// Ejemplo 8: Operaciones en lote con manejo de errores
echo "8. Batch operations with error handling:\n";
$users = [
    ['name' => 'User 1', 'email' => 'user1@example.com', 'password' => 'password123'],
    ['name' => 'User 2', 'email' => 'user2@example.com', 'password' => 'password123'],
    ['name' => '', 'email' => 'invalid', 'password' => '123'], // Datos inválidos
];

foreach ($users as $index => $userData) {
    echo "Creating user $index:\n";
    $result = $controller->create($userData);
    echo "Success: " . ($result['success'] ? 'Yes' : 'No') . "\n";
    if (!$result['success']) {
        echo "Error: " . $result['error']['message'] . "\n";
    }
    echo "\n";
}

// Ejemplo 9: Obtener log completo de errores
echo "9. Complete error log:\n";
$errorLog = ErrorHandler::getErrorLog();
echo "Total errors logged: " . count($errorLog) . "\n";

if (!empty($errorLog)) {
    $lastError = end($errorLog);
    echo "Last error: " . $lastError['error']['message'] . "\n";
    echo "Error code: " . $lastError['error']['error_code'] . "\n";
    echo "Origin: " . $lastError['origin']['type'] . " in " . $lastError['origin']['location'] . "\n";
}

echo "\n=== Demo completed ===\n";

// Ejemplo 10: Limpiar log de errores
ErrorHandler::clearErrorLog();
echo "Error log cleared. Current count: " . count(ErrorHandler::getErrorLog()) . "\n";
