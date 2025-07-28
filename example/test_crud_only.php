<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/index.php';

use VersaORM\Exceptions\VersaORMException;
use VersaORM\VersaORM;
use VersaORM\Model;

try {
    global $config;
    $db_config = $config['DB'];

    $orm = new VersaORM([
        'driver' => $db_config['DB_DRIVER'],
        'host' => $db_config['DB_HOST'],
        'port' => $db_config['DB_PORT'],
        'database' => $db_config['DB_NAME'],
        'username' => $db_config['DB_USER'],
        'password' => $db_config['DB_PASS']
    ]);

    echo "=== TESTING CRUD OPERATIONS ===\n\n";

    // CREATE - Crear nuevo usuario usando raw query
    echo "CREATE: Creating new user...\n";
    $newUser = [
        'name' => 'Pedro Silva',
        'email' => 'pedro@example.com',
        'age' => 32
    ];
    $orm->exec('INSERT INTO users (name, email, age) VALUES (?, ?, ?)', [
        $newUser['name'], $newUser['email'], $newUser['age']
    ]);
    $userResult = $orm->exec('SELECT id FROM users WHERE email = ?', [$newUser['email']]);
    $userId = $userResult[0]['id'];
    echo "✅ User created with ID: $userId\n\n";

    // READ - Obtener todos los usuarios
    echo "READ ALL: Getting all users...\n";
    $allUsers = $orm->table('users')->get();
    echo "✅ " . count($allUsers) . " users found\n\n";

    // READ - Obtener usuario específico
    echo "READ ONE: Getting specific user...\n";
    $user = $orm->table('users')->where('id', '=', $userId)->first();
    echo "✅ User found: " . ($user ? $user['name'] : "Not found") . "\n\n";

    // UPDATE - Actualizar usuario usando raw query
    echo "UPDATE: Updating user...\n";
    $orm->exec('UPDATE users SET age = ?, status = ? WHERE id = ?', [33, 'active', $userId]);
    echo "✅ User with ID $userId updated successfully\n\n";

    // DELETE - Eliminar usuario temporal
    echo "DELETE: Creating and deleting temp user...\n";
    $orm->exec('INSERT INTO users (name, email, age) VALUES (?, ?, ?)', [
        'Temp User', 'temp@example.com', 20
    ]);
    $tempUserResult = $orm->exec('SELECT id FROM users WHERE email = ?', ['temp@example.com']);
    $tempUserId = $tempUserResult[0]['id'];
    $orm->exec('DELETE FROM users WHERE id = ?', [$tempUserId]);
    echo "✅ Temp user with ID $tempUserId deleted successfully\n\n";

    echo "=== ALL CRUD OPERATIONS COMPLETED SUCCESSFULLY ===\n";

} catch (VersaORMException $e) {
    echo "❌ VersaORM Error: " . $e->getMessage() . "\n";
    if ($e->getDetails()) {
        echo "Details: " . json_encode($e->getDetails(), JSON_PRETTY_PRINT) . "\n";
    }
} catch (Throwable $e) {
    echo "❌ General Error: " . $e->getMessage() . "\n";
    echo "File: " . $e->getFile() . "\n";
    echo "Line: " . $e->getLine() . "\n";
}

?>
