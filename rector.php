<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;

return static function (RectorConfig $rectorConfig): void {
    // Only process core src files
    $rectorConfig->paths([
        __DIR__.'/src',
    ]);

    // Skip everything that might cause issues
    $rectorConfig->skip([
        __DIR__.'/vendor',
        __DIR__.'/tests',
        __DIR__.'/example',
        __DIR__.'/testMysql',
        __DIR__.'/testPostgreSQL',
        __DIR__.'/testSQLite',
        __DIR__.'/src/binary',
        '*/node_modules/*',
        '*/vendor/*',
        '*.phar',
    ]);

    // Conservative PHP version target
    $rectorConfig->phpVersion(\Rector\ValueObject\PhpVersion::PHP_80);

    // No rule sets - just basic parsing
    // $rectorConfig->sets([]);

    // Memory limit
    $rectorConfig->memoryLimit('256M');

    // Cache directory
    $rectorConfig->cacheDirectory(__DIR__.'/var/cache/rector');
};
