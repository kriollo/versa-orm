<?php

declare(strict_types=1);

/**
 * Configuración de la aplicación Trello
 * VersaORM-PHP Demo Application.
 */

return [
    'database' => [
        'engine' => 'pdo',
        'host' => '127.0.0.1',
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
    ],
];
