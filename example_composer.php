<?php

/**
 * Ejemplo de uso de VersaORM-PHP con Composer
 */

require_once 'vendor/autoload.php';

use VersaORM\VersaORM;
use VersaORM\Model;

try {
    // Configuración de la base de datos
    $orm = new VersaORM([
        'driver' => 'mysql',
        'host' => 'localhost',
        'port' => 3306,
        'database' => 'test_db',
        'username' => 'root',
        'password' => 'password'
    ]);
    
    // Configurar la instancia global para los modelos estáticos
    Model::setORM($orm);

    echo "✓ Conexión a la base de datos establecida.\n";

    // === EJEMPLO 1: QueryBuilder ===
    echo "\n--- Ejemplo 1: QueryBuilder ---\n";

    // Consulta simple
    $users = $orm->table('users')
        ->select(['id', 'name', 'email'])
        ->where('active', '=', 1)
        ->orderBy('name', 'asc')
        ->limit(10)
        ->get();

    echo "Usuarios activos encontrados: " . count($users) . "\n";

    // Insertar nuevo usuario
    $newUserId = $orm->table('users')->insertGetId([
        'name' => 'Juan Pérez',
        'email' => 'juan.perez@example.com',
        'active' => 1,
        'created_at' => date('Y-m-d H:i:s')
    ]);

    echo "Nuevo usuario creado con ID: $newUserId\n";

    // === EJEMPLO 2: Modelo ORM ===
    echo "\n--- Ejemplo 2: Modelo ORM ---\n";

    // Crear un nuevo usuario usando el modelo
    $user = $orm->table('users')->dispense();
    $user->name = 'María García';
    $user->email = 'maria.garcia@example.com';
    $user->active = 1;
    $user->created_at = date('Y-m-d H:i:s');

    // Guardar el usuario
    $user->store();
    echo "Usuario modelo creado con ID: " . $user->id . "\n";

    // Cargar y modificar usuario existente
    $existingUser = $orm->table('users')->dispense();
    $existingUser->load($newUserId);
    $existingUser->name = 'Juan Carlos Pérez';
    $existingUser->store();

    echo "Usuario actualizado: " . $existingUser->name . "\n";

    // === EJEMPLO 3: Consultas avanzadas ===
    echo "\n--- Ejemplo 3: Consultas avanzadas ---\n";

    // JOIN con otras tablas
    $userPosts = $orm->table('users')
        ->select(['users.name', 'posts.title', 'posts.created_at'])
        ->join('posts', 'users.id', '=', 'posts.user_id')
        ->where('users.active', '=', 1)
        ->orderBy('posts.created_at', 'desc')
        ->limit(5)
        ->get();

    echo "Posts de usuarios activos: " . count($userPosts) . "\n";

    // Agregaciones
    $totalUsers = $orm->table('users')->count();
    $activeUsers = $orm->table('users')->where('active', '=', 1)->count();

    echo "Total de usuarios: $totalUsers\n";
    echo "Usuarios activos: $activeUsers\n";

    // === EJEMPLO 4: Consultas SQL crudas ===
    echo "\n--- Ejemplo 4: Consultas SQL crudas ---\n";

    $customQuery = $orm->exec(
        "SELECT COUNT(*) as total FROM users WHERE created_at > ?",
        [date('Y-m-d', strtotime('-30 days'))]
    );

    echo "Usuarios creados en los últimos 30 días: " . $customQuery[0]['total'] . "\n";

    // === EJEMPLO 5: Información del esquema ===
    echo "\n--- Ejemplo 5: Información del esquema ---\n";

    // Obtener información de la tabla
    $tableInfo = $orm->schema('table', 'users');
    echo "Información de la tabla 'users':\n";
    echo "Columnas: " . count($tableInfo['columns']) . "\n";

    // === EJEMPLO 6: Métodos estáticos de modelos ===
    echo "\n--- Ejemplo 6: Métodos estáticos de modelos ---\n";

    // Usar métodos estáticos de Model (requieren setORM previo)
    $userModel = Model::dispense('users');
    $userModel->name = 'Usuario Estático';
    $userModel->email = 'estatico@example.com';
    $userModel->active = 1;
    $userModel->store();
    echo "Usuario creado con métodos estáticos: " . $userModel->id . "\n";

    // Buscar usuarios con métodos estáticos
    $foundUser = Model::find('users', $userModel->id);
    echo "Usuario encontrado: " . $foundUser->name . "\n";

    // === LIMPIEZA ===
    echo "\n--- Limpieza ---\n";

    // Eliminar usuarios de prueba
    $orm->table('users')
        ->where('email', 'LIKE', '%@example.com')
        ->delete();

    echo "Usuarios de prueba eliminados.\n";

    // Cerrar conexión
    $orm->disconnect();
    echo "✓ Conexión cerrada.\n";

} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
    echo "Trace: " . $e->getTraceAsString() . "\n";
}
