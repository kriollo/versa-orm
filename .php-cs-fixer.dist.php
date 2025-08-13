<?php
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
        'reports'
    ]);

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setUsingCache(true)
    ->setCacheFile(__DIR__ . '/.php-cs-fixer.cache')
    ->setRules([
        // Base rule sets
        '@PSR12' => true,
        '@PHP80Migration' => true,
        '@PhpCsFixer' => true,
        '@PhpCsFixer:risky' => true,

        // Array formatting
        'array_syntax' => ['syntax' => 'short'],
        'array_indentation' => true,
        'trim_array_spaces' => true,
        'no_trailing_comma_in_singleline' => true,
        'trailing_comma_in_multiline' => ['elements' => ['arrays', 'arguments', 'parameters']],

        // Binary operators
        'binary_operator_spaces' => [
            'operators' => [
                '=>' => 'align_single_space_minimal',
                '=' => 'align_single_space_minimal'
            ]
        ],
        'concat_space' => ['spacing' => 'one'],
        'operator_linebreak' => ['only_booleans' => true],

        // Imports and namespaces
        'no_unused_imports' => true,
        'ordered_imports' => [
            'imports_order' => ['class', 'function', 'const'],
            'sort_algorithm' => 'alpha'
        ],
        'global_namespace_import' => [
            'import_classes' => true,
            'import_constants' => true,
            'import_functions' => true
        ],
        'no_leading_import_slash' => true,
        'single_import_per_statement' => true,

        // Strings
        'single_quote' => ['strings_containing_single_quote_chars' => false],
        'string_implicit_backslashes' => true,
        'explicit_string_variable' => true,
        'simple_to_complex_string_variable' => true,

        // Whitespace and formatting
        'no_trailing_whitespace' => true,
        'no_whitespace_in_blank_line' => true,
        'blank_line_after_opening_tag' => true,
        'blank_line_before_statement' => [
            'statements' => ['return', 'throw', 'try', 'if', 'for', 'foreach', 'while', 'do', 'switch']
        ],
        'no_extra_blank_lines' => [
            'tokens' => ['extra', 'throw', 'use']
        ],

        // PHPDoc
        'phpdoc_align' => ['align' => 'left'],
        'phpdoc_annotation_without_dot' => true,
        'phpdoc_indent' => true,
        'phpdoc_inline_tag_normalizer' => true,
        'phpdoc_no_access' => true,
        'phpdoc_no_empty_return' => true,
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

        // Classes and methods
        'class_attributes_separation' => [
            'elements' => [
                'method' => 'one',
                'property' => 'one',
                'trait_import' => 'none'
            ]
        ],
        'method_chaining_indentation' => true,
        'no_null_property_initialization' => true,
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

        // Control structures
        'yoda_style' => ['equal' => false, 'identical' => false, 'less_and_greater' => false],
        'no_superfluous_elseif' => true,
        'no_useless_else' => true,
        'switch_case_semicolon_to_colon' => true,
        'switch_case_space' => true,

        // Functions
        'function_declaration' => ['closure_function_spacing' => 'one'],
        'lambda_not_used_import' => true,
        'method_argument_space' => ['on_multiline' => 'ensure_fully_multiline'],
        'no_spaces_after_function_name' => true,
        'return_type_declaration' => ['space_before' => 'none'],

        // Strict types and declarations
        'declare_strict_types' => true,
        'strict_comparison' => true,
        'strict_param' => true,

        // Security and best practices
        'no_php4_constructor' => true,
        'no_unreachable_default_argument_value' => true,
        'non_printable_character' => true,
        'psr_autoloading' => true,
        'self_accessor' => true,
        'self_static_accessor' => true,

        // ORM-specific rules
        'final_class' => false, // Allow inheritance for models
        'final_public_method_for_abstract_class' => false, // Allow method overriding

        // Disable some overly strict rules for ORM context
        'php_unit_internal_class' => false,
        'php_unit_test_class_requires_covers' => false,
        'date_time_immutable' => false, // Allow mutable DateTime for compatibility
        'mb_str_functions' => false, // Not always needed for DB operations
    ])
    ->setFinder($finder);
