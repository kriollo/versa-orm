<?php

declare(strict_types=1);

/**
 * Configuración de la aplicación Trello
 * VersaORM-PHP Demo Application.
 */

/**
 * Cada valor puede sobreescribirse por variable de entorno, para no tener que editar
 * este archivo al desplegar o al correr la demo en CI.
 */
$env = static fn(string $key, string $default): string => (string) (getenv($key) ?: $default);

return [
    'database' => [
        'engine' => 'pdo',
        'host' => $env('DEMO_DB_HOST', '127.0.0.1'),
        'port' => (int) $env('DEMO_DB_PORT', '3306'),
        'database' => $env('DEMO_DB_NAME', 'versaorm_trello'),
        'username' => $env('DEMO_DB_USER', 'local'),
        'password' => $env('DEMO_DB_PASS', 'local'),
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
