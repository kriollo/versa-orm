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
        // === BASE RULE SETS ===
        '@PSR12' => true,
        '@PHP80Migration' => true,

        // === ARRAY FORMATTING ===
        'array_syntax' => ['syntax' => 'short'],
        'array_indentation' => true,
        'trim_array_spaces' => true,
        'no_trailing_comma_in_singleline' => true,
        'trailing_comma_in_multiline' => ['elements' => ['arrays', 'arguments', 'parameters']],

        // === BINARY OPERATORS ===
        'binary_operator_spaces' => [
            'operators' => [
                '=>' => 'single_space',
                '=' => 'single_space'
            ]
        ],
        'concat_space' => ['spacing' => 'one'],
        'operator_linebreak' => ['only_booleans' => true],

        // === IMPORTS AND NAMESPACES ===
        // PHP-CS-Fixer handles formatting, Rector handles logic
        'no_unused_imports' => true,
        'ordered_imports' => [
            'imports_order' => ['class', 'function', 'const'],
            'sort_algorithm' => 'alpha'
        ],
        'no_leading_import_slash' => true,
        'single_import_per_statement' => true,
        'group_import' => false, // Keep imports separate for clarity

        // === STRINGS - ORM/SQL SAFE ===
        'single_quote' => ['strings_containing_single_quote_chars' => false],
        // Disabled to avoid breaking SQL queries:
        'string_implicit_backslashes' => false,
        'explicit_string_variable' => false,
        'simple_to_complex_string_variable' => false,
        'escape_implicit_backslashes' => false,
        'heredoc_to_nowdoc' => false,

        // === WHITESPACE AND FORMATTING ===
        'no_trailing_whitespace' => true,
        'no_whitespace_in_blank_line' => true,
        'blank_line_after_opening_tag' => true,
        'blank_line_before_statement' => [
            'statements' => ['return', 'throw', 'try']
        ],
        'no_extra_blank_lines' => [
            'tokens' => ['extra', 'throw', 'use', 'curly_brace_block']
        ],
        'single_blank_line_at_eof' => true,

        // === PHPDOC - PHPSTAN COMPATIBLE ===
        'phpdoc_align' => ['align' => 'left'],
        'phpdoc_annotation_without_dot' => true,
        'phpdoc_indent' => true,
        'phpdoc_inline_tag_normalizer' => true,
        'phpdoc_no_access' => true,
        'phpdoc_no_empty_return' => false, // Allow for PHPStan compatibility
        'phpdoc_no_package' => true,
        'phpdoc_no_useless_inheritdoc' => true,
        'phpdoc_order' => true,
        'phpdoc_return_self_reference' => true,
        'phpdoc_scalar' => true,
        'phpdoc_separation' => true,
        'phpdoc_single_line_var_spacing' => true,
        'phpdoc_summary' => true,
        'phpdoc_tag_type' => true,
        'phpdoc_trim' => true,
        'phpdoc_trim_consecutive_blank_line_separation' => true,
        'phpdoc_types' => true,
        'phpdoc_types_order' => ['null_adjustment' => 'always_last'],
        'phpdoc_var_annotation_correct_order' => true,
        'phpdoc_var_without_name' => true,

        // === CLASSES AND METHODS - ORM FRIENDLY ===
        'class_attributes_separation' => [
            'elements' => [
                'method' => 'one',
                'property' => 'one',
                'trait_import' => 'none'
            ]
        ],
        'method_chaining_indentation' => true,
        'no_null_property_initialization' => false, // Allow for test classes
        'ordered_class_elements' => [
            'order' => [
                'use_trait',
                'constant_public',
                'constant_protected',
                'constant_private',
                'property_public',
                'property_protected',
                'property_private',
                'construct',
                'destruct',
                'magic',
                'phpunit',
                'method_public',
                'method_protected',
                'method_private'
            ]
        ],
        'visibility_required' => ['elements' => ['property', 'method', 'const']],

        // === CONTROL STRUCTURES ===
        'yoda_style' => ['equal' => false, 'identical' => false, 'less_and_greater' => false],
        'no_superfluous_elseif' => true,
        'no_useless_else' => true,
        'switch_case_semicolon_to_colon' => true,
        'switch_case_space' => true,

        // === FUNCTIONS ===
        'function_declaration' => ['closure_function_spacing' => 'none'], // Compatible con Mago: fn() en lugar de fn ()
        'lambda_not_used_import' => true,
        'method_argument_space' => ['on_multiline' => 'ensure_fully_multiline'],
        'no_spaces_after_function_name' => true,
        'return_type_declaration' => ['space_before' => 'none'],

        // === MAGO COMPATIBILITY ADDITIONS ===
        'single_line_empty_body' => true, // Constructor vacío en una línea: {}
        'compact_nullable_type_declaration' => true,

        // === SECURITY AND BEST PRACTICES ===
        'no_php4_constructor' => true,
        'no_unreachable_default_argument_value' => true,
        'non_printable_character' => true,
        'psr_autoloading' => true,
        'self_accessor' => true,
        'self_static_accessor' => true,

        // === DISABLED - LET RECTOR HANDLE THESE ===
        'declare_strict_types' => false,
        'strict_comparison' => false,
        'strict_param' => false,
        'void_return' => false,
        'nullable_type_declaration_for_default_null_value' => false,
        'ternary_to_null_coalescing' => false,

        // === DISABLED - ORM COMPATIBILITY ===
        'final_class' => false,
        'final_public_method_for_abstract_class' => false,
        'php_unit_internal_class' => false,
        'php_unit_test_class_requires_covers' => false,
        'date_time_immutable' => false,
        'mb_str_functions' => false,
        'no_alias_functions' => false,
        'pow_to_exponentiation' => false,
        'random_api_migration' => false,

        // === DISABLED - AVOID CONFLICTS ===
        'single_line_comment_style' => false, // Can conflict with SQL comments
        'global_namespace_import' => false,   // Let Rector handle imports
    ])
    ->setFinder($finder);
