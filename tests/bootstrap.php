<?php

declare(strict_types=1);

// tests/bootstrap.php

// Cargar el autoloader de Composer
require_once __DIR__ . '/../vendor/autoload.php';

// Cargar la configuración de la base de datos de prueba (MySQL para pruebas)
global $config;
$config = [
    'DB' => [
        'DB_DRIVER' => getenv('DB_DRIVER') ?: 'mysql',
        'DB_HOST' => getenv('DB_HOST') ?: 'localhost',
        'DB_PORT' => getenv('DB_PORT') ?: 3306,
        'DB_NAME' => getenv('DB_NAME') ?: 'versaorm_test',
        'DB_USER' => getenv('DB_USER') ?: 'local',
        'DB_PASS' => getenv('DB_PASS') ?: 'local',
        'debug' => true,
    ],
];
