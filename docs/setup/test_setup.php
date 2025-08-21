<?php

/**
 * Script de prueba para verificar que la configuración funciona correctamente
 */

use VersaORM\VersaModel;

require_once __DIR__.'/example_config.php';

echo "=== PRUEBA DE CONFIGURACIÓN DE VERSAORM ===\n\n";

try {
    // Inicializar ORM
    $orm = getExampleORM();
    VersaModel::setORM($orm);
    echo "✓ VersaORM inicializado correctamente\n";

    $model = new VersaModel('', $orm);

    // Probar consulta básica
    $userCount = $model->getCell('SELECT COUNT(*) FROM users');
    echo "✓ Consulta básica exitosa: $userCount usuarios encontrados\n";

    // Probar VersaModel
    $user = $model->load('users', 1);
    if ($user) {
        echo "✓ VersaModel funcionando: Usuario '{$user->name}' cargado\n";
    } else {
        echo "✗ Error: No se pudo cargar el usuario\n";
    }

    // Probar Query Builder
    $activeUsers = $orm->table('users')->where('active', '=', 1)->getAll();
    echo '✓ Query Builder funcionando: '.count($activeUsers)." usuarios activos\n";

    // Probar relaciones
    $postsWithAuthors = $model->getAll('
        SELECT p.title, u.name as author
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE p.published = 1
        LIMIT 3
    ');
    echo '✓ Relaciones funcionando: '.count($postsWithAuthors)." posts con autores encontrados\n";

    echo "\n=== EJEMPLOS DE DATOS ===\n";

    echo "\nUsuarios activos:\n";
    foreach ($activeUsers as $user) {
        echo "- {$user['name']} ({$user['email']})\n";
    }

    echo "\nPosts publicados:\n";
    foreach ($postsWithAuthors as $post) {
        echo "- '{$post['title']}' por {$post['author']}\n";
    }

    echo "\n✅ CONFIGURACIÓN COMPLETAMENTE FUNCIONAL\n";
    echo "Puedes proceder con los ejemplos de la documentación.\n";

} catch (Exception $e) {
    echo '✗ Error durante la prueba: '.$e->getMessage()."\n";
    echo "Asegúrate de haber ejecutado setup_database.php primero.\n";
    exit(1);
}
