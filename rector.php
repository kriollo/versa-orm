<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Set\ValueObject\LevelSetList;
use Rector\Set\ValueObject\SetList;
use Rector\PHPUnit\Set\PHPUnitSetList;

return static function (RectorConfig $rectorConfig): void {
    // Paths to refactor
    $rectorConfig->paths([
        __DIR__ . '/src',
        __DIR__ . '/tests',
        __DIR__ . '/example',
    ]);

    // Skip certain paths
    $rectorConfig->skip([
        __DIR__ . '/vendor',
        __DIR__ . '/tests/reports',
        __DIR__ . '/tests/cache',
        __DIR__ . '/tests/logs',
        __DIR__ . '/src/binary',
        '*/node_modules/*',
        '*/vendor/*',
        '*.phar',

        // Skip specific files that have intentional patterns
        __DIR__ . '/tests/Quality/*',
        __DIR__ . '/tests/bin/*',

        // === CRITICAL: Skip rules that conflict with PHP-CS-Fixer ===

        // Let PHP-CS-Fixer handle code style and formatting

        // Let PHP-CS-Fixer handle array syntax
        \Rector\Php54\Rector\Array_\LongArrayToShortArrayRector::class,

        // === CRITICAL: Skip rules that conflict with PHPStan ===

        // Don't add void return types - PHPStan will handle this
        \Rector\TypeDeclaration\Rector\ClassMethod\AddVoidReturnTypeWhereNoReturnRector::class,

        // Don't change return types that PHPStan expects
        \Rector\TypeDeclaration\Rector\ClassMethod\ReturnTypeFromReturnNewRector::class => [
            __DIR__ . '/src/Relations/*.php',
        ],

        // === ORM-specific skips ===

        // Skip property promotion in test classes and ORM models
        \Rector\Php80\Rector\Class_\ClassPropertyAssignToConstructorPromotionRector::class => [
            __DIR__ . '/test*/*.php',
            __DIR__ . '/src/VersaModel.php',
        ],

        // Skip removing unused properties (might be used dynamically)
        \Rector\DeadCode\Rector\Property\RemoveUnusedPrivatePropertyRector::class => [
            __DIR__ . '/src/VersaModel.php',
        ],

        // Skip changes that might break ORM magic methods

        // Skip strict comparisons in SQL contexts
        \Rector\CodeQuality\Rector\Identical\FlipTypeControlToUseExclusiveTypeRector::class => [
            __DIR__ . '/src/QueryBuilder.php',
            __DIR__ . '/src/VersaORM.php',
        ],
    ]);

    // PHP version target - conservative to maintain compatibility
    $rectorConfig->phpVersion(\Rector\ValueObject\PhpVersion::PHP_80);

    // Import names - let PHP-CS-Fixer handle the formatting
    $rectorConfig->importNames();
    $rectorConfig->importShortClasses(false); // Disable to avoid conflicts

    // Apply rule sets - carefully selected to avoid conflicts
    $rectorConfig->sets([
        // PHP version upgrades - conservative
        LevelSetList::UP_TO_PHP_80,

        // Code quality improvements - safe ones only
        SetList::CODE_QUALITY,
        SetList::DEAD_CODE,

        // Type declarations - but we skip problematic ones above
        SetList::TYPE_DECLARATION,

        // PHPUnit improvements
        PHPUnitSetList::PHPUNIT_90,
        PHPUnitSetList::PHPUNIT_CODE_QUALITY,
    ]);

    // Parallel processing for better performance
    $rectorConfig->parallel();

    // Memory limit for large codebases
    $rectorConfig->memoryLimit('512M');

    // Cache directory
    $rectorConfig->cacheDirectory(__DIR__ . '/var/cache/rector');
};
