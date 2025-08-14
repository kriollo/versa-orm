<?php

declare(strict_types=1);

// testSQLite/bootstrap.php

// Cargar el autoloader de Composer
require_once __DIR__ . '/../vendor/autoload.php';

// Configuración de la base de datos de prueba (SQLite)
// Por defecto usa un archivo local en ./tests.sqlite para persistencia entre tests.
// Puedes forzar memoria con DB_NAME=:memory:

global $config;
$dbNameEnv = getenv('DB_NAME');
// Forzar base en memoria compartida para todos los tests (rápido y aislado). Si se quiere archivo, establecer SQLITE_PATH.
$resolvedDb = $dbNameEnv !== false && $dbNameEnv !== '' ? $dbNameEnv : (getenv('SQLITE_PATH') ?: ':memory:');

// Evitar problemas de múltiples conexiones sqlite::memory: (una por PDO) que pierden el esquema entre consultas
// Forzamos a archivo físico si se solicitó ':memory:' para estabilidad en pruebas de relaciones.
if ($resolvedDb === ':memory:') {
    $resolvedDb = __DIR__ . '/../tests.sqlite';
}

$config = [
    'DB' => [
        'engine' => 'pdo',
        'DB_DRIVER' => getenv('DB_DRIVER') ?: 'sqlite',
        'DB_NAME' => $resolvedDb,
        'DB_HOST' => '',
        'DB_PORT' => 0,
        'DB_USER' => '',
        'DB_PASS' => '',
        'debug' => true,
    ],
];

// Habilitar claves foráneas en SQLite
// Se aplica por conexión internamente, pero lo dejamos como referencia
// self::$orm->exec('PRAGMA foreign_keys = ON;');
