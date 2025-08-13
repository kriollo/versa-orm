<?php

declare(strict_types=1);

/**
 * Coverage Configuration for VersaORM.
 *
 * This configuration file defines coverage settings, thresholds,
 * and reporting options for the comprehensive testing system.
 */

return [
    // Global coverage settings
    'global' => [
        'minimum_coverage'   => 95.0,
        'critical_threshold' => 90.0,
        'warning_threshold'  => 85.0,
        'target_coverage'    => 100.0,
    ],

    // Engine-specific coverage settings
    'engines' => [
        'mysql' => [
            'minimum_coverage' => 95.0,
            'critical_files'   => [
                'src/VersaORM.php',
                'src/VersaModel.php',
                'src/QueryBuilder.php',
                'src/ErrorHandler.php',
            ],
            'features_to_cover' => [
                'fulltext_search',
                'json_operations',
                'storage_engines',
                'mysql_specific_types',
                'advanced_sql',
            ],
        ],
        'postgresql' => [
            'minimum_coverage' => 95.0,
            'critical_files'   => [
                'src/VersaORM.php',
                'src/VersaModel.php',
                'src/QueryBuilder.php',
                'src/ErrorHandler.php',
            ],
            'features_to_cover' => [
                'arrays',
                'jsonb',
                'window_functions',
                'cte',
                'uuid',
                'postgresql_specific_types',
            ],
        ],
        'sqlite' => [
            'minimum_coverage' => 90.0, // Slightly lower due to limitations
            'critical_files'   => [
                'src/VersaORM.php',
                'src/VersaModel.php',
                'src/QueryBuilder.php',
                'src/ErrorHandler.php',
            ],
            'features_to_cover' => [
                'limitations_handling',
                'workarounds',
                'file_based_operations',
                'in_memory_operations',
            ],
        ],
    ],

    // File-specific coverage requirements
    'file_requirements' => [
        'src/VersaORM.php' => [
            'minimum_coverage' => 98.0,
            'critical'         => true,
            'description'      => 'Core ORM class - must have near-perfect coverage',
        ],
        'src/VersaModel.php' => [
            'minimum_coverage' => 98.0,
            'critical'         => true,
            'description'      => 'Base model class - must have near-perfect coverage',
        ],
        'src/QueryBuilder.php' => [
            'minimum_coverage' => 95.0,
            'critical'         => true,
            'description'      => 'Query builder - critical for all database operations',
        ],
        'src/ErrorHandler.php' => [
            'minimum_coverage' => 90.0,
            'critical'         => true,
            'description'      => 'Error handling - important for stability',
        ],
        'src/VersaORMException.php' => [
            'minimum_coverage' => 85.0,
            'critical'         => false,
            'description'      => 'Exception class - basic coverage required',
        ],
    ],

    // Feature-based coverage tracking
    'feature_coverage' => [
        'crud_operations' => [
            'description'      => 'Create, Read, Update, Delete operations',
            'minimum_coverage' => 98.0,
            'test_files'       => [
                'testMysql/VersaORMTest.php',
                'testPostgreSQL/VersaORMTest.php',
                'testSQLite/QueryBuilderTest.php',
            ],
        ],
        'relationships' => [
            'description'      => 'Model relationships and joins',
            'minimum_coverage' => 95.0,
            'test_files'       => [
                'testMysql/RelationshipsTest.php',
                'testPostgreSQL/RelationshipsTest.php',
            ],
        ],
        'query_builder' => [
            'description'      => 'Query building functionality',
            'minimum_coverage' => 96.0,
            'test_files'       => [
                'testMysql/QueryBuilderTest.php',
                'testPostgreSQL/QueryBuilderTest.php',
                'testSQLite/QueryBuilderTest.php',
            ],
        ],
        'transactions' => [
            'description'      => 'Transaction handling',
            'minimum_coverage' => 92.0,
            'test_files'       => [
                'testMysql/TransactionsRollbackTest.php',
                'testPostgreSQL/TransactionsRollbackTest.php',
                'testSQLite/TransactionsRollbackTest.php',
            ],
        ],
        'security' => [
            'description'      => 'Security features and SQL injection protection',
            'minimum_coverage' => 100.0,
            'test_files'       => [
                'testMysql/SecurityTest.php',
                'testPostgreSQL/SecurityTest.php',
                'testSQLite/SecurityTest.php',
            ],
        ],
        'validation' => [
            'description'      => 'Data validation and schema validation',
            'minimum_coverage' => 94.0,
            'test_files'       => [
                'testMysql/ValidationTest.php',
                'testPostgreSQL/ValidationTest.php',
            ],
        ],
        'type_mapping' => [
            'description'      => 'Data type mapping and casting',
            'minimum_coverage' => 93.0,
            'test_files'       => [
                'testMysql/AdvancedTypeMappingTest.php',
                'testPostgreSQL/AdvancedTypeMappingTest.php',
                'testSQLite/StrongTypingTest.php',
            ],
        ],
    ],

    // Reporting configuration
    'reporting' => [
        'formats'            => ['html', 'xml', 'clover', 'text', 'cobertura'],
        'output_directories' => [
            'html'      => 'tests/reports/coverage/{engine}/html',
            'xml'       => 'tests/reports/coverage/{engine}/xml',
            'clover'    => 'tests/reports/coverage/{engine}/clover.xml',
            'text'      => 'tests/reports/coverage/{engine}/coverage.txt',
            'cobertura' => 'tests/reports/coverage/{engine}/cobertura.xml',
        ],
        'consolidated_report' => 'tests/reports/coverage/consolidated-report.json',
        'gaps_report'         => 'tests/reports/coverage/gaps-report.json',
        'alerts_report'       => 'tests/reports/coverage/alerts-report.json',
    ],

    // Exclusion patterns
    'exclusions' => [
        'directories' => [
            'vendor',
            'tests',
            'example',
            'docs',
            'src/binary',
        ],
        'files' => [
            'src/Console/deprecated.php',
            '*.phar',
        ],
        'patterns' => [
            '*/vendor/*',
            '*/tests/*',
            '*/example/*',
            '*/docs/*',
            '*/.git/*',
        ],
    ],

    // Alert configuration
    'alerts' => [
        'coverage_below_threshold' => [
            'severity'         => 'high',
            'enabled'          => true,
            'message_template' => 'Coverage for {engine} ({coverage}%) is below minimum threshold ({threshold}%)',
        ],
        'critical_files_uncovered' => [
            'severity'         => 'critical',
            'enabled'          => true,
            'message_template' => 'Critical files have insufficient coverage in {engine}',
        ],
        'feature_coverage_gap' => [
            'severity'         => 'medium',
            'enabled'          => true,
            'message_template' => 'Feature {feature} has coverage gap: {coverage}% (required: {threshold}%)',
        ],
        'regression_detected' => [
            'severity'         => 'high',
            'enabled'          => true,
            'message_template' => 'Coverage regression detected: {current}% vs {previous}%',
        ],
    ],

    // Integration settings
    'integration' => [
        'ci_cd' => [
            'fail_build_on_threshold'          => true,
            'fail_build_on_critical_uncovered' => true,
            'generate_pr_comments'             => true,
            'upload_to_codecov'                => false,
            'upload_to_coveralls'              => false,
        ],
        'notifications' => [
            'slack_webhook'    => null,
            'email_recipients' => [],
            'discord_webhook'  => null,
        ],
    ],

    // Performance settings
    'performance' => [
        'parallel_execution'     => true,
        'max_parallel_processes' => 3,
        'memory_limit'           => '512M',
        'timeout_per_engine'     => 300, // 5 minutes
        'cache_coverage_data'    => true,
        'cache_duration'         => 3600, // 1 hour
    ],

    // Historical tracking
    'history' => [
        'track_trends'         => true,
        'retention_days'       => 90,
        'baseline_file'        => 'tests/reports/coverage/baseline.json',
        'trend_analysis'       => true,
        'regression_detection' => true,
    ],
];
