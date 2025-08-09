<?php

declare(strict_types=1);

// testSQLite/bootstrap.php

// Cargar el autoloader de Composer
require_once __DIR__ . '/../vendor/autoload.php';

// Configuración de la base de datos de prueba (SQLite)
// Por defecto usa un archivo local en ./tests.sqlite para persistencia entre tests.
// Puedes forzar memoria con DB_NAME=:memory:

global $config;
$config = [
    'DB' => [
        'engine'    => 'pdo',
        'DB_DRIVER' => getenv('DB_DRIVER') ?: 'sqlite',
        // Para archivo local persistente usa ruta absoluta; por defecto en la raíz del repo
        'DB_NAME'   => getenv('DB_NAME') ?: (getenv('SQLITE_PATH') ?: (__DIR__ . '/../tests.sqlite')),
        'DB_HOST'   => '',
        'DB_PORT'   => 0,
        'DB_USER'   => '',
        'DB_PASS'   => '',
        'debug'     => true,
    ],
];

// Habilitar claves foráneas en SQLite
// Se aplica por conexión internamente, pero lo dejamos como referencia
// self::$orm->exec('PRAGMA foreign_keys = ON;');
