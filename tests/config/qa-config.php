<?php

declare(strict_types=1);

/**
 * Configuración principal del sistema de QA.
 *
 * Define todos los parámetros de configuración para el sistema de testing,
 * benchmarking, análisis de calidad y reportes.
 */

return [
    // Configuración general
    'version'     => '1.0.0',
    'environment' => $_ENV['QA_ENVIRONMENT'] ?? 'development',

    // Configuración de logging
    'logging' => [
        'level'              => $_ENV['QA_LOG_LEVEL'] ?? 'info',
        'output_dir'         => 'tests/logs',
        'max_files'          => 10,
        'console_output'     => true,
        'structured_logging' => true,
    ],

    // Configuración de métricas
    'metrics' => [
        'enabled'        => true,
        'output_dir'     => 'tests/metrics',
        'retention_days' => 30,
        'collect_memory' => true,
        'collect_timing' => true,
        'collect_custom' => true,
    ],

    // Configuración de reportes
    'reports' => [
        'output_dir'     => 'tests/reports',
        'formats'        => ['json', 'html'],
        'include_trends' => true,
        'include_charts' => true,
        'auto_cleanup'   => true,
        'retention_days' => 60,
    ],

    // Gates de calidad
    'quality_gates' => [
        'min_coverage'         => 95.0,
        'max_complexity'       => 10,
        'min_quality_score'    => 80,
        'max_duplicated_lines' => 3,
        'max_technical_debt'   => 30, // minutos
    ],

    // Configuración de motores de BD
    'database_engines' => [
        'mysql' => [
            'enabled'        => true,
            'versions'       => ['5.7', '8.0', '8.1'],
            'specific_tests' => ['fulltext', 'json_operations', 'storage_engines'],
            'phpunit_config' => 'phpunit-mysql.xml',
        ],
        'postgresql' => [
            'enabled'        => true,
            'versions'       => ['10', '11', '12', '13', '14', '15'],
            'specific_tests' => ['arrays', 'jsonb', 'window_functions', 'ctes', 'uuid'],
            'phpunit_config' => 'phpunit-postgresql.xml',
        ],
        'sqlite' => [
            'enabled'        => true,
            'versions'       => ['3.6+'],
            'specific_tests' => ['limitations', 'workarounds'],
            'phpunit_config' => 'phpunit-sqlite.xml',
        ],
    ],

    // Configuración de PHP
    'php_versions' => [
        'supported'   => ['7.4', '8.0', '8.1', '8.2', '8.3'],
        'primary'     => '8.2',
        'test_matrix' => true,
    ],

    // Configuración de herramientas de calidad
    'quality_tools' => [
        'phpstan' => [
            'enabled'      => true,
            'level'        => 8,
            'config'       => 'phpstan.neon',
            'memory_limit' => '1G',
            'baseline'     => 'phpstan-baseline.neon',
        ],
        'psalm' => [
            'enabled'           => true,
            'config'            => 'psalm.xml',
            'security_analysis' => true,
            'taint_analysis'    => true,
        ],
        'php_cs_fixer' => [
            'enabled' => true,
            'config'  => '.php-cs-fixer.dist.php',
            'rules'   => 'PSR-12',
            'risky'   => false,
        ],
        'cargo_clippy' => [
            'enabled' => true,
            'config'  => 'versaorm_cli/.clippy.toml',
            'deny'    => ['warnings'],
        ],
    ],

    // Configuración de benchmarks
    'benchmarks' => [
        'enabled'           => true,
        'data_sizes'        => [1000, 10000, 100000, 1000000],
        'iterations'        => 3,
        'warmup_iterations' => 1,
        'memory_limit'      => '2G',
        'time_limit'        => 300, // 5 minutos
        'comparisons'       => [
            'eloquent' => false, // Deshabilitado por defecto
            'doctrine' => false, // Deshabilitado por defecto
            'pdo'      => true,
        ],
    ],

    // Configuración de tests de seguridad
    'security_tests' => [
        'enabled'          => true,
        'sql_injection'    => true,
        'xss_protection'   => true,
        'input_validation' => true,
        'taint_analysis'   => true,
    ],

    // Configuración de CI/CD
    'ci_cd' => [
        'github_actions'     => true,
        'parallel_jobs'      => 4,
        'fail_fast'          => false,
        'artifact_retention' => 30, // días
        'notifications'      => [
            'slack'   => false,
            'email'   => false,
            'discord' => false,
        ],
    ],

    // Configuración de alertas
    'alerts' => [
        'enabled'    => true,
        'thresholds' => [
            'test_failure_rate'       => 5.0, // %
            'quality_score_drop'      => 10, // puntos
            'performance_degradation' => 20.0, // %
            'memory_increase'         => 50.0, // %
        ],
        'channels' => [
            'log'     => true,
            'console' => true,
            'file'    => true,
        ],
    ],

    // Configuración de cache
    'cache' => [
        'enabled'   => true,
        'driver'    => 'file',
        'ttl'       => 3600, // 1 hora
        'directory' => 'tests/cache',
    ],

    // Configuración de paralelización
    'parallel' => [
        'enabled'       => true,
        'max_processes' => 4,
        'chunk_size'    => 10,
        'timeout'       => 300, // 5 minutos
    ],

    // Configuración de desarrollo
    'development' => [
        'debug_mode'        => false,
        'verbose_output'    => false,
        'profile_tests'     => false,
        'generate_coverage' => true,
    ],
];
