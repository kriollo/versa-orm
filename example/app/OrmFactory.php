<?php

declare(strict_types=1);

namespace App;

use VersaORM\VersaORM;

/**
 * OrmFactory: construye VersaORM por petición a partir de config + request.
 */
class OrmFactory
{
    public static function make(array $appConfig, Request $request): VersaORM
    {
        // Puedes aplicar multi-tenant, selección de DB por header/host, etc.
        $dbConfig = $appConfig['database'] ?? [];
        $voConfig = $appConfig['versaorm'] ?? [];

        // Normalizar claves para VersaORM
        $config = [
            'engine' => $dbConfig['engine'] ?? 'pdo',
            'driver' => $dbConfig['driver'] ?? ($dbConfig['DB_DRIVER'] ?? 'mysql'),
            'database' => $dbConfig['database'] ?? ($dbConfig['DB_NAME'] ?? ''),
            'debug' => ($voConfig['debug'] ?? false) || ($appConfig['app']['debug'] ?? false),
            'host' => $dbConfig['host'] ?? ($dbConfig['DB_HOST'] ?? ''),
            'port' => (int) ($dbConfig['port'] ?? ($dbConfig['DB_PORT'] ?? 0)),
            'username' => $dbConfig['username'] ?? ($dbConfig['DB_USER'] ?? ''),
            'password' => $dbConfig['password'] ?? ($dbConfig['DB_PASS'] ?? ''),
            'charset' => $dbConfig['charset'] ?? 'utf8mb4',
            'collation' => $dbConfig['collation'] ?? 'utf8mb4_unicode_ci',
            // Extras
            'cache' => $voConfig['cache'] ?? false,
            'logging' => $voConfig['logging'] ?? false,
            'log_path' => $voConfig['log_path'] ?? null,
        ];

        return new VersaORM($config);
    }
}
