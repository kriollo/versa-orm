<?php

declare(strict_types=1);

// testPostgreSQL/bootstrap.php

// Cargar el autoloader de Composer
require_once __DIR__ . '/../vendor/autoload.php';

// Cargar la configuración de la base de datos de prueba (PostgreSQL para pruebas)
global $config;
$config = [
    'DB' => [
        'engine' => 'pdo',
        'DB_DRIVER' => getenv('DB_DRIVER') ?: 'postgresql',
        'DB_HOST' => getenv('DB_HOST') ?: 'localhost',
        'DB_PORT' => getenv('DB_PORT') ?: 5432,
        'DB_NAME' => getenv('DB_NAME') ?: 'versaorm_test',
        'DB_USER' => getenv('DB_USER') ?: 'local',
        'DB_PASS' => getenv('DB_PASS') ?: 'local',
        'debug' => true,
    ],
];
