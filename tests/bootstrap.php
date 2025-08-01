<?php

// tests/bootstrap.php

// Cargar el autoloader de Composer
require_once __DIR__ . '/../vendor/autoload.php';

// Cargar la configuración de la base de datos de prueba (SQLite para pruebas)
global $config;
$config = [
    'DB' => [
        'DB_DRIVER' => getenv('DB_DRIVER') ?: 'sqlite',
        'DB_HOST' => getenv('DB_HOST') ?: null,
        'DB_PORT' => null,
        'DB_NAME' => getenv('DB_NAME') ?: str_replace('\\', '/', __DIR__) . '/temp/test_database.sqlite',
        'DB_USER' => null,
        'DB_PASS' => null,
        'debug' => true,
    ],
];
