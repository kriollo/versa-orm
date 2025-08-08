<?php

declare(strict_types=1);

/**
 * Configuración de la aplicación Trello
 * VersaORM-PHP Demo Application.
 */

return [
    'database' => [
        'engine' => 'pdo',
        'host' => 'localhost',
        'port' => 3306,
        'database' => 'versaorm_trello',
        'username' => 'local',
        'password' => 'local',
        'driver' => 'mysql',
        'charset' => 'utf8mb4',
        'collation' => 'utf8mb4_unicode_ci',
    ],

    'app' => [
        'name' => 'VersaORM Trello Demo',
        'version' => '1.0.0',
        'debug' => true,
        'timezone' => 'America/Santiago',
    ],

    'versaorm' => [
        'debug' => true,
        'cache' => false,
        'logging' => true,
        'binary_path' => __DIR__ . '/../src/binary/versaorm_cli.exe',
        'log_path' => __DIR__ . '/../logs/',
    ],
];
