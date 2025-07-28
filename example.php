<?php

// Usar el autoloader para cargar todas las dependencias
require_once 'php/autoload.php';

// Opción alternativa (cargar archivos individualmente):
// require_once 'php/VersaORM.php';
// require_once 'php/VersaORMQueryBuilder.php';
// require_once 'php/VersaORMModel.php';

try {
    // Configuración de la base de datos
    VersaORM::connect([
        'driver' => 'mysql',
        'host' => 'localhost',
        'port' => 3306,
        'database' => 'test_db',
        'username' => 'root',
        'password' => 'password',
        'charset' => 'utf8mb4'
    ]);

    echo "=== Ejemplo de uso de VersaORM ===\n\n";

    // Ejemplo 1: QueryBuilder básico
    echo "1. Consulta básica con QueryBuilder:\n";
    $users = VersaORM::table('users')
        ->select(['id', 'name', 'email'])
        ->where('activo', '=', true)
        ->orderBy('id', 'desc')
        ->limit(10)
        ->get();
    
    echo "Usuarios encontrados: " . count($users) . "\n";
    print_r($users);
    echo "\n";

    // Ejemplo 2: Buscar un usuario específico
    echo "2. Buscar usuario por ID:\n";
    $user = VersaORM::table('users')->find(1);
    if ($user) {
        echo "Usuario encontrado: " . $user['name'] . "\n";
    } else {
        echo "Usuario no encontrado\n";
    }
    echo "\n";

    // Ejemplo 3: Contar registros
    echo "3. Contar usuarios activos:\n";
    $count = VersaORM::table('users')
        ->where('activo', '=', true)
        ->count();
    echo "Total de usuarios activos: $count\n\n";

    // Ejemplo 4: Consulta SQL cruda
    echo "4. Consulta SQL cruda:\n";
    $rawResults = VersaORM::exec('SELECT * FROM users WHERE activo = ? LIMIT ?', [true, 5]);
    echo "Resultados de consulta cruda: " . count($rawResults) . "\n";
    print_r($rawResults);
    echo "\n";

    // Ejemplo 5: Obtener esquema de tabla
    echo "5. Obtener columnas de la tabla 'users':\n";
    $columns = VersaORM::schema('columns', 'users');
    echo "Columnas encontradas:\n";
    foreach ($columns as $column) {
        echo "- {$column['name']} ({$column['data_type']})\n";
    }
    echo "\n";

    // Ejemplo 6: Obtener todas las tablas
    echo "6. Obtener todas las tablas:\n";
    $tables = VersaORM::schema('tables');
    echo "Tablas en la base de datos:\n";
    foreach ($tables as $table) {
        echo "- $table\n";
    }
    echo "\n";

    // Ejemplo 7: Insertar un nuevo registro
    echo "7. Insertar nuevo usuario:\n";
    $newUserId = VersaORM::table('users')->insertGetId([
        'name' => 'Nuevo Usuario',
        'email' => 'nuevo@example.com',
        'activo' => true
    ]);
    echo "Nuevo usuario creado con ID: $newUserId\n\n";

    // Ejemplo 8: Actualizar registro
    echo "8. Actualizar usuario:\n";
    $updated = VersaORM::table('users')
        ->where('id', '=', $newUserId)
        ->update(['name' => 'Usuario Actualizado']);
    echo "Registros actualizados: $updated\n\n";

    // Ejemplo 9: Verificar existencia
    echo "9. Verificar si existe usuario:\n";
    $exists = VersaORM::table('users')
        ->where('email', '=', 'nuevo@example.com')
        ->exists();
    echo "Usuario existe: " . ($exists ? 'Sí' : 'No') . "\n\n";

    // Ejemplo 10: Administrar caché
    echo "10. Administrar caché:\n";
    VersaORM::cache('clear');
    echo "Caché limpiado\n";
    $cacheStatus = VersaORM::cache('status');
    echo "Estado del caché: $cacheStatus elementos\n\n";

    // Ejemplo 11: Usar VersaORMModel (estilo RedBeanPHP)
    echo "11. Ejemplos con VersaORMModel:\n";
    
    // Crear un nuevo modelo
    echo "  - Crear nuevo usuario con dispense():\n";
    $userModel = VersaORM::table('users')->dispense();
    $userModel->name = 'Usuario Model';
    $userModel->email = 'model@example.com';
    $userModel->activo = true;
    $userModel->store();
    echo "    Usuario creado con ID: {$userModel->id}\n";
    
    // Cargar un modelo existente
    echo "  - Cargar usuario existente con load():\n";
    $loadedModel = VersaORM::table('users')->dispense();
    $loadedModel->load($userModel->id);
    echo "    Usuario cargado: {$loadedModel->name} ({$loadedModel->email})\n";
    
    // Actualizar el modelo
    echo "  - Actualizar modelo con store():\n";
    $loadedModel->name = 'Usuario Model Actualizado';
    $loadedModel->store();
    echo "    Usuario actualizado\n";
    
    // Mostrar datos del modelo
    echo "  - Datos del modelo:\n";
    print_r($loadedModel->toArray());
    
    // Opcional: eliminar el modelo de prueba
    echo "  - Eliminar modelo con trash():\n";
    $loadedModel->trash();
    echo "    Usuario eliminado\n";
    echo "\n";
    
    // Ejemplo 12: Desconectar
    echo "12. Desconectar de la base de datos:\n";
    VersaORM::disconnect();
    echo "Desconectado exitosamente\n\n";

} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
