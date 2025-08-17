<?php
/**
 * Configuraciones de base de datos para pruebas de compatibilidad
 *
 * Este archivo define las configuraciones para probar la documentación
 * con diferentes motores de base de datos.
 */

return [
    'sqlite' => [
        'engine' => 'pdo',
        'driver' => 'sqlite',
        'database' => __DIR__ . '/test_sqlite.db',
        'host' => '',
        'username' => '',
        'password' => '',
        'charset' => 'utf8mb4',
        'enabled' => true
    ],

    'mysql' => [
        'engine' => 'pdo',
        'driver' => 'mysql',
        'host' => getenv('DB_HOST') ?: 'localhost',
        'port' => (int) (getenv('DB_PORT') ?: 3306),
        'database' => getenv('DB_NAME') ?: 'versaorm_test',
        'username' => getenv('DB_USER') ?: 'local',
        'password' => getenv('DB_PASS') ?: 'local',
        'charset' => 'utf8mb4',
        'enabled' => !empty(getenv('DB_HOST')) || !empty(getenv('DB_NAME'))
    ],

    'postgresql' => [
        'engine' => 'pdo',
        'driver' => 'postgresql',
        'host' => getenv('DB_HOST') ?: 'localhost',
        'port' => (int) (getenv('DB_PORT') ?: 5432),
        'database' => getenv('DB_NAME') ?: 'versaorm_test',
        'username' => getenv('DB_USER') ?: 'local',
        'password' => getenv('DB_PASS') ?: 'local',
        'charset' => 'utf8',
        'enabled' => !empty(getenv('DB_HOST')) || !empty(getenv('DB_NAME'))
    ]
];
