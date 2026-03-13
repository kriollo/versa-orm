<?php

declare(strict_types=1);

$finder = PhpCsFixer\Finder::create()
    ->in([
        __DIR__ . '/src',
        __DIR__ . '/testPostgreSQL',
        __DIR__ . '/testMysql',
        __DIR__ . '/testSQLite',
        __DIR__ . '/tests',
        __DIR__ . '/example'
    ])
    ->name('*.php')
    ->ignoreDotFiles(true)
    ->ignoreVCS(true)
    ->exclude([
        'vendor',
        'cache',
        'logs',
        'reports',
        'binary'
    ]);

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setUsingCache(true)
    ->setCacheFile(__DIR__ . '/.php-cs-fixer.cache')
    ->setRules([
        // === LOGICAL SYNTAX MODERNIZATION ===
        '@PHP80Migration' => true,

        // === IMPORTS (CS Fixer is good at these) ===
        'no_unused_imports' => true,
        'ordered_imports' => [
            'imports_order' => ['class', 'function', 'const'],
            'sort_algorithm' => 'alpha'
        ],
        'no_leading_import_slash' => true,
        'single_import_per_statement' => true,
        'group_import' => false,

        // === CLEANUP ===
        'no_empty_statement' => true,
        'no_useless_else' => true,
        'no_superfluous_elseif' => true,
        
        // Disable formatting rules that Mago handles (indentation, spaces, etc)
        // We do strictly minimal cleanup here.
        'array_syntax' => ['syntax' => 'short'],
        'no_trailing_comma_in_singleline' => true,
    ])
    ->setFinder($finder);
