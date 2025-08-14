<?php

declare(strict_types=1);

/**
 * QA Integration Configuration for VersaORM.
 *
 * This configuration ensures all quality tools work together harmoniously
 * without conflicts. It defines compatible rules and exclusions.
 */

return [
    // Global settings that apply to all tools
    'global' => [
        'php_version' => '8.0',
        'target_compatibility' => '8.0',
        'paths' => [
            'src',
            'example',
            'tests',
            'testMysql',
            'testPostgreSQL',
            'testSQLite',
        ],
        'exclude_paths' => [
            'vendor',
            'src/binary',
            'tests/reports',
            'tests/cache',
            'tests/logs',
            'var/cache',
            'node_modules',
        ],
    ],

    // Tool-specific configurations that are compatible
    'rector' => [
        'enabled_sets' => [
            'UP_TO_PHP_80',           // Conservative PHP version upgrade
            'CODE_QUALITY',           // Safe code quality improvements
            'DEAD_CODE',              // Remove unused code
            'TYPE_DECLARATION',       // Add type declarations carefully
            'PHPUNIT_90',             // PHPUnit improvements
            'PHPUNIT_CODE_QUALITY',    // PHPUnit code quality
        ],
        'disabled_rules' => [
            // Rules that conflict with ORM patterns
            'RemoveUnusedPublicMethodRector',           // Public methods might be API
            'CompactToVariablesRector',                 // Used in views
            'EncapsedStringsToSprintfRector',          // Might break SQL strings
            'UnionTypesRector',                        // Compatibility issues
            'ReadOnlyPropertyRector',                  // Compatibility issues
            'AnnotationToAttributeRector',             // Keep annotations for now

            // Rules that conflict with test patterns
            'ClassPropertyAssignToConstructorPromotionRector', // Test classes need nullable properties
            'TypedPropertyRector',                             // Test classes need nullable properties
        ],
        'skip_files' => [
            // Files with intentional patterns
            'tests/Quality/*',
            'tests/bin/*',
            'src/Relations/*',  // Relations have specific inheritance patterns
        ],
    ],

    'php_cs_fixer' => [
        'base_rules' => [
            '@PSR12',
            '@PHP80Migration',
        ],
        'enabled_rules' => [
            // Array formatting
            'array_syntax' => ['syntax' => 'short'],
            'array_indentation' => true,
            'trim_array_spaces' => true,
            'trailing_comma_in_multiline' => ['elements' => ['arrays', 'arguments', 'parameters']],

            // Imports - let Rector handle complex cases
            'no_unused_imports' => true,
            'ordered_imports' => ['imports_order' => ['class', 'function', 'const']],

            // Whitespace
            'no_trailing_whitespace' => true,
            'no_whitespace_in_blank_line' => true,
            'blank_line_after_opening_tag' => true,

            // PHPDoc - compatible with PHPStan
            'phpdoc_align' => ['align' => 'left'],
            'phpdoc_trim' => true,
            'phpdoc_types_order' => ['null_adjustment' => 'always_last'],

            // Classes and methods
            'visibility_required' => ['elements' => ['property', 'method', 'const']],
            'method_chaining_indentation' => true,

            // Control structures
            'yoda_style' => ['equal' => false, 'identical' => false],
        ],
        'disabled_rules' => [
            // Rules that conflict with Rector
            '@PhpCsFixer:risky',
            'declare_strict_types',
            'strict_comparison',
            'strict_param',
            'void_return',
            'nullable_type_declaration_for_default_null_value',
            'constructor_promotion',

            // Rules that might break SQL strings
            'string_implicit_backslashes',
            'explicit_string_variable',
            'simple_to_complex_string_variable',
            'escape_implicit_backslashes',
            'heredoc_to_nowdoc',

            // Rules that might break ORM patterns
            'final_class',
            'final_public_method_for_abstract_class',
            'no_null_property_initialization',
        ],
    ],

    'phpstan' => [
        'level' => 8,
        'strict_rules' => true,
        'baseline_enabled' => true,
        'compatible_settings' => [
            'treatPhpDocTypesAsCertain' => false,
            'checkMissingIterableValueType' => true,
            'checkGenericClassInNonGenericObjectType' => true,
            'reportUnmatchedIgnoredErrors' => false,  // More lenient
        ],
        'orm_patterns' => [
            // Allow ORM magic methods
            'undefined_method_patterns' => [
                'where', 'select', 'join', 'orderBy', 'groupBy', 'having', 'limit', 'offset',
            ],
            // Allow dynamic properties
            'undefined_property_patterns' => [
                'VersaModel properties',
            ],
        ],
    ],

    'psalm' => [
        'error_level' => 4,  // More lenient than PHPStan
        'php_version' => '8.0',
        'strict_settings' => [
            'ensureArrayStringOffsetsExist' => true,
            'findUnusedVariablesAndParams' => true,
            'findUnusedCode' => false,      // Let other tools handle this
            'strictBinaryOperands' => false, // More lenient
            'reportMixedIssues' => false,   // More lenient
        ],
        'security_focus' => [
            'TaintedInput' => 'error',
            'TaintedSql' => 'error',
            'TaintedShell' => 'error',
            'TaintedFile' => 'error',
            'TaintedHtml' => 'error',
        ],
    ],

    // Integration rules - how tools should work together
    'integration' => [
        'execution_order' => [
            'rector',       // 1. Modernize code first
            'php-cs-fixer', // 2. Format code second
            'phpstan',      // 3. Analyze types third
            'psalm',        // 4. Additional analysis fourth
            'tests',         // 5. Verify functionality last
        ],
        'conflict_resolution' => [
            // When tools disagree, this is the priority order
            'type_declarations' => 'rector',     // Rector handles type declarations
            'code_formatting' => 'php-cs-fixer', // PHP-CS-Fixer handles formatting
            'static_analysis' => 'phpstan',      // PHPStan is primary static analyzer
            'security_analysis' => 'psalm',      // Psalm handles security
        ],
        'shared_exclusions' => [
            // Files/patterns that all tools should skip
            'vendor/*',
            'src/binary/*',
            'tests/reports/*',
            'tests/cache/*',
            'tests/logs/*',
            'var/cache/*',
            '*.phar',
        ],
    ],

    // Compatibility matrix - which rules can coexist
    'compatibility_matrix' => [
        'rector_phpstan' => [
            // Rector rules that are compatible with PHPStan level 8
            'safe_rector_rules' => [
                'CODE_QUALITY',
                'DEAD_CODE',
                'TYPE_DECLARATION',
                'PHPUNIT_CODE_QUALITY',
            ],
            'conflicting_rector_rules' => [
                'STRICT_BOOLEANS',  // Can conflict with PHPStan
                'EARLY_RETURN',     // Can conflict with PHPStan
            ],
        ],
        'phpstan_psalm' => [
            // Settings that work well together
            'compatible_error_levels' => [
                'phpstan' => 8,
                'psalm' => 4,
            ],
        ],
    ],

    // Quality gates - minimum standards all tools must meet
    'quality_gates' => [
        'rector' => [
            'max_files_changed' => 50,  // Don't allow massive changes
            'required_improvements' => ['type_declarations', 'code_quality'],
        ],
        'php_cs_fixer' => [
            'max_files_changed' => 100, // Formatting can touch many files
            'zero_violations' => true,   // Must have zero style violations
        ],
        'phpstan' => [
            'max_errors' => 10,         // Allow some errors initially
            'critical_errors' => 0,     // Zero critical errors
            'baseline_growth' => false,  // Don't allow baseline to grow
        ],
        'psalm' => [
            'max_errors' => 20,         // More lenient than PHPStan
            'security_errors' => 0,     // Zero security errors
            'mixed_types' => 'info',     // Allow mixed types with warnings
        ],
        'tests' => [
            'min_pass_rate' => 95,      // 95% of tests must pass
            'zero_failures' => false,   // Allow some failures initially
            'zero_errors' => true,       // No errors allowed
        ],
    ],
];
