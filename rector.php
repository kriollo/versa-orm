<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use VersaORM\Tools\Rector\NoopRector;

// Cargar una regla no-op local para evitar el warning de "no rules/sets"
// sin forzar refactors automáticos sobre el core.
require_once __DIR__ . '/tools/rector/NoopRector.php';

return static function (RectorConfig $rectorConfig): void {
    // Only process core src files
    $rectorConfig->paths([
        __DIR__ . '/src',
    ]);

    // Skip everything that might cause issues
    $rectorConfig->skip([
        __DIR__ . '/vendor',
        __DIR__ . '/tests',
        __DIR__ . '/example',
        __DIR__ . '/testMysql',
        __DIR__ . '/testPostgreSQL',
        __DIR__ . '/testSQLite',
        __DIR__ . '/src/binary',
        '*/node_modules/*',
        '*/vendor/*',
        '*.phar',
    ]);

    // Target PHP version (coherente con composer.json)
    $rectorConfig->phpVersion(\Rector\ValueObject\PhpVersion::PHP_81);

    // Registrar al menos una regla para evitar el warning de Rector, sin aplicar cambios.
    $rectorConfig->rule(NoopRector::class);

    // Memory limit
    $rectorConfig->memoryLimit('512M');

    // Cache directory
    $rectorConfig->cacheDirectory(__DIR__ . '/var/cache/rector');
};
