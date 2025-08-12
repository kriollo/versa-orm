<?php

declare(strict_types=1);

namespace VersaORM\Tests\Compatibility;

use VersaORM\Tests\Results\TestResult;
use VersaORM\Tests\Results\Report;
use DateTime;

/**
 * PHPVersionTestExecutor - Ejecuta tests específicos para diferentes versiones de PHP
 *
 * Esta clase maneja la ejecución de tests de compatibilidad para diferentes
 * versiones de PHP y genera reportes específicos por versión.
 */
class PHPVersionTestExecutor
{
    private PHPVersionDetector $detector;
    private array $config;
    private array $testResults = [];

    public function __construct(array $config = [])
    {
        $this->detector = new PHPVersionDetector();
        $this->config = array_merge($this->getDefaultConfig(), $config);
    }

    /**
     * Ejecuta todos los tests de compatibilidad PHP
     */
    public function runAllCompatibilityTests(): Report
    {
        $startTime = microtime(true);

        $results = [
            'version_detection' => $this->runVersionDetectionTests(),
            'feature_compatibility' => $this->runFeatureCompatibilityTests(),
            'performance_tests' => $this->runPerformanceTests(),
            'memory_tests' => $this->runMemoryTests(),
            'extension_tests' => $this->runExtensionTests(),
            'configuration_tests' => $this->runConfigurationTests(),
            'orm_functionality_tests' => $this->runORMFunctionalityTests(),
        ];

        $executionTime = microtime(true) - $startTime;

        return new Report([
            'test_type' => 'php_compatibility',
            'php_version' => $this->detector->getCurrentVersion()['full_version'],
            'results' => $results,
            'summary' => $this->generateSummary($results),
            'execution_time' => $executionTime,
            'timestamp' => new DateTime(),
            'recommendations' => $this->generateRecommendations($results),
        ]);
    }

    /**
     * Ejecuta tests de detección de versión
     */
    private function runVersionDetectionTests(): TestResult
    {
        $startTime = microtime(true);
        $tests = [];

        try {
            // Test 1: Verificar versión soportada
            $currentVersion = $this->detector->getCurrentVersion();
            $isSupported = $this->detector->isCurrentVersionSupported();

            $tests['version_supported'] = [
                'status' => $isSupported ? 'pass' : 'fail',
                'message' => $isSupported
                    ? "PHP {$currentVersion['full_version']} is supported"
                    : "PHP {$currentVersion['full_version']} is not supported",
                'details' => $currentVersion
            ];

            // Test 2: Verificar características disponibles
            $features = $this->detector->detectAvailableFeatures();
            $tests['features_detection'] = [
                'status' => 'pass',
                'message' => count($features) . ' features detected',
                'details' => $features
            ];

            // Test 3: Verificar información de soporte
            $support = $this->detector->getCurrentVersionSupport();
            $tests['support_info'] = [
                'status' => $support ? 'pass' : 'fail',
                'message' => $support ? 'Support information available' : 'No support information',
                'details' => $support
            ];

        } catch (\Exception $e) {
            $tests['version_detection_error'] = [
                'status' => 'fail',
                'message' => 'Version detection failed: ' . $e->getMessage(),
                'details' => ['exception' => $e->getMessage()]
            ];
        }

        return new TestResult([
            'test_type' => 'version_detection',
            'engine' => 'php',
            'total_tests' => count($tests),
            'passed_tests' => count(array_filter($tests, fn($t) => $t['status'] === 'pass')),
            'failed_tests' => count(array_filter($tests, fn($t) => $t['status'] === 'fail')),
            'skipped_tests' => 0,
            'execution_time' => microtime(true) - $startTime,
            'failures' => array_filter($tests, fn($t) => $t['status'] === 'fail'),
            'metrics' => ['tests' => $tests],
            'timestamp' => new DateTime()
        ]);
    }

    /**
     * Ejecuta tests de compatibilidad de características
     */
    private function runFeatureCompatibilityTests(): TestResult
    {
        $startTime = microtime(true);
        $tests = [];

        try {
            $currentVersionId = PHP_VERSION_ID;
            $features = $this->detector->detectAvailableFeatures();

            // Test características específicas por versión
            $versionTests = [
                70400 => ['typed_properties', 'arrow_functions', 'null_coalescing_assignment'],
                80000 => ['named_arguments', 'attributes', 'constructor_promotion', 'union_types'],
                80100 => ['enums', 'readonly_properties', 'intersection_types'],
                80200 => ['readonly_classes', 'dnf_types', 'constants_in_traits'],
                80300 => ['typed_class_constants', 'override_attribute']
            ];

            foreach ($versionTests as $versionId => $expectedFeatures) {
                if ($currentVersionId >= $versionId) {
                    foreach ($expectedFeatures as $feature) {
                        $hasFeature = in_array($feature, $features);
                        $tests["feature_{$feature}"] = [
                            'status' => $hasFeature ? 'pass' : 'fail',
                            'message' => $hasFeature
                                ? "Feature {$feature} is available"
                                : "Feature {$feature} should be available but is not detected",
                            'details' => ['required_version' => $versionId, 'current_version' => $currentVersionId]
                        ];
                    }
                }
            }

            // Test funciones específicas de versión
            $functionTests = [
                'str_contains' => 80000,
                'str_starts_with' => 80000,
                'str_ends_with' => 80000,
                'array_is_list' => 80100,
                'enum_exists' => 80100,
            ];

            foreach ($functionTests as $function => $requiredVersion) {
                if ($currentVersionId >= $requiredVersion) {
                    $exists = function_exists($function);
                    $tests["function_{$function}"] = [
                        'status' => $exists ? 'pass' : 'fail',
                        'message' => $exists
                            ? "Function {$function} is available"
                            : "Function {$function} should be available but is not",
                        'details' => ['required_version' => $requiredVersion]
                    ];
                }
            }

        } catch (\Exception $e) {
            $tests['feature_compatibility_error'] = [
                'status' => 'fail',
                'message' => 'Feature compatibility test failed: ' . $e->getMessage(),
                'details' => ['exception' => $e->getMessage()]
            ];
        }

        return new TestResult([
            'test_type' => 'feature_compatibility',
            'engine' => 'php',
            'total_tests' => count($tests),
            'passed_tests' => count(array_filter($tests, fn($t) => $t['status'] === 'pass')),
            'failed_tests' => count(array_filter($tests, fn($t) => $t['status'] === 'fail')),
            'skipped_tests' => 0,
            'execution_time' => microtime(true) - $startTime,
            'failures' => array_filter($tests, fn($t) => $t['status'] === 'fail'),
            'metrics' => ['tests' => $tests],
            'timestamp' => new DateTime()
        ]);
    }

    /**
     * Ejecuta tests de rendimiento específicos por versión
     */
    private function runPerformanceTests(): TestResult
    {
        $startTime = microtime(true);
        $tests = [];

        try {
            // Test 1: Tiempo de instanciación de VersaORM
            $instantiationTimes = [];
            for ($i = 0; $i < 100; $i++) {
                $start = microtime(true);
                $config = ['driver' => 'sqlite', 'database' => ':memory:'];
                $orm = new \VersaORM\VersaORM($config);
                $instantiationTimes[] = microtime(true) - $start;
                unset($orm);
            }

            $avgInstantiationTime = array_sum($instantiationTimes) / count($instantiationTimes);
            $tests['orm_instantiation_performance'] = [
                'status' => $avgInstantiationTime < 0.01 ? 'pass' : 'warning',
                'message' => "Average instantiation time: " . number_format($avgInstantiationTime * 1000, 2) . "ms",
                'details' => [
                    'average_time' => $avgInstantiationTime,
                    'min_time' => min($instantiationTimes),
                    'max_time' => max($instantiationTimes),
                    'iterations' => count($instantiationTimes)
                ]
            ];

            // Test 2: Uso de memoria
            $initialMemory = memory_get_usage(true);
            $instances = [];
            for ($i = 0; $i < 50; $i++) {
                $config = ['driver' => 'sqlite', 'database' => ':memory:'];
                $instances[] = new \VersaORM\VersaORM($config);
            }
            $memoryUsed = memory_get_usage(true) - $initialMemory;
            unset($instances);

            $tests['memory_usage'] = [
                'status' => $memoryUsed < 5 * 1024 * 1024 ? 'pass' : 'warning', // 5MB threshold
                'message' => "Memory usage for 50 instances: " . number_format($memoryUsed / 1024 / 1024, 2) . "MB",
                'details' => [
                    'memory_used_bytes' => $memoryUsed,
                    'memory_used_mb' => $memoryUsed / 1024 / 1024,
                    'instances_created' => 50
                ]
            ];

        } catch (\Exception $e) {
            $tests['performance_test_error'] = [
                'status' => 'fail',
                'message' => 'Performance test failed: ' . $e->getMessage(),
                'details' => ['exception' => $e->getMessage()]
            ];
        }

        return new TestResult([
            'test_type' => 'performance',
            'engine' => 'php',
            'total_tests' => count($tests),
            'passed_tests' => count(array_filter($tests, fn($t) => $t['status'] === 'pass')),
            'failed_tests' => count(array_filter($tests, fn($t) => $t['status'] === 'fail')),
            'skipped_tests' => 0,
            'execution_time' => microtime(true) - $startTime,
            'failures' => array_filter($tests, fn($t) => $t['status'] === 'fail'),
            'metrics' => ['tests' => $tests],
            'timestamp' => new DateTime()
        ]);
    }

    /**
     * Ejecuta tests de memoria específicos por versión
     */
    private function runMemoryTests(): TestResult
    {
        $startTime = microtime(true);
        $tests = [];

        try {
            // Test 1: Memory leak detection
            $initialMemory = memory_get_usage(true);

            for ($i = 0; $i < 1000; $i++) {
                $config = ['driver' => 'sqlite', 'database' => ':memory:'];
                $orm = new \VersaORM\VersaORM($config);
                $qb = $orm->table('test');
                unset($orm, $qb);

                // Force garbage collection every 100 iterations
                if ($i % 100 === 0) {
                    gc_collect_cycles();
                }
            }

            $finalMemory = memory_get_usage(true);
            $memoryDiff = $finalMemory - $initialMemory;

            $tests['memory_leak_detection'] = [
                'status' => $memoryDiff < 1024 * 1024 ? 'pass' : 'fail', // 1MB threshold
                'message' => "Memory difference after 1000 iterations: " . number_format($memoryDiff / 1024, 2) . "KB",
                'details' => [
                    'initial_memory' => $initialMemory,
                    'final_memory' => $finalMemory,
                    'memory_diff' => $memoryDiff,
                    'iterations' => 1000
                ]
            ];

            // Test 2: Peak memory usage
            $peakMemory = memory_get_peak_usage(true);
            $tests['peak_memory_usage'] = [
                'status' => 'info',
                'message' => "Peak memory usage: " . number_format($peakMemory / 1024 / 1024, 2) . "MB",
                'details' => ['peak_memory_bytes' => $peakMemory]
            ];

        } catch (\Exception $e) {
            $tests['memory_test_error'] = [
                'status' => 'fail',
                'message' => 'Memory test failed: ' . $e->getMessage(),
                'details' => ['exception' => $e->getMessage()]
            ];
        }

        return new TestResult([
            'test_type' => 'memory',
            'engine' => 'php',
            'total_tests' => count($tests),
            'passed_tests' => count(array_filter($tests, fn($t) => $t['status'] === 'pass')),
            'failed_tests' => count(array_filter($tests, fn($t) => $t['status'] === 'fail')),
            'skipped_tests' => 0,
            'execution_time' => microtime(true) - $startTime,
            'failures' => array_filter($tests, fn($t) => $t['status'] === 'fail'),
            'metrics' => ['tests' => $tests],
            'timestamp' => new DateTime()
        ]);
    }

    /**
     * Ejecuta tests de extensiones requeridas
     */
    private function runExtensionTests(): TestResult
    {
        $startTime = microtime(true);
        $tests = [];

        try {
            $extensions = $this->detector->getRelevantExtensions();
            $requiredExtensions = ['pdo', 'json', 'mbstring'];
            $recommendedExtensions = ['pdo_mysql', 'pdo_pgsql', 'pdo_sqlite', 'openssl', 'curl'];

            // Test extensiones requeridas
            foreach ($requiredExtensions as $extension) {
                $isLoaded = $extensions[$extension]['loaded'] ?? false;
                $tests["required_extension_{$extension}"] = [
                    'status' => $isLoaded ? 'pass' : 'fail',
                    'message' => $isLoaded
                        ? "Required extension {$extension} is loaded (version: {$extensions[$extension]['version']})"
                        : "Required extension {$extension} is not loaded",
                    'details' => $extensions[$extension] ?? ['loaded' => false]
                ];
            }

            // Test extensiones recomendadas
            foreach ($recommendedExtensions as $extension) {
                $isLoaded = $extensions[$extension]['loaded'] ?? false;
                $tests["recommended_extension_{$extension}"] = [
                    'status' => $isLoaded ? 'pass' : 'warning',
                    'message' => $isLoaded
                        ? "Recommended extension {$extension} is loaded (version: {$extensions[$extension]['version']})"
                        : "Recommended extension {$extension} is not loaded",
                    'details' => $extensions[$extension] ?? ['loaded' => false]
                ];
            }

        } catch (\Exception $e) {
            $tests['extension_test_error'] = [
                'status' => 'fail',
                'message' => 'Extension test failed: ' . $e->getMessage(),
                'details' => ['exception' => $e->getMessage()]
            ];
        }

        return new TestResult([
            'test_type' => 'extensions',
            'engine' => 'php',
            'total_tests' => count($tests),
            'passed_tests' => count(array_filter($tests, fn($t) => $t['status'] === 'pass')),
            'failed_tests' => count(array_filter($tests, fn($t) => $t['status'] === 'fail')),
            'skipped_tests' => 0,
            'execution_time' => microtime(true) - $startTime,
            'failures' => array_filter($tests, fn($t) => $t['status'] === 'fail'),
            'metrics' => ['tests' => $tests],
            'timestamp' => new DateTime()
        ]);
    }

    /**
     * Ejecuta tests de configuración PHP
     */
    private function runConfigurationTests(): TestResult
    {
        $startTime = microtime(true);
        $tests = [];

        try {
            $config = $this->detector->getRelevantConfiguration();

            // Test memory limit
            $memoryLimit = $config['memory_limit'];
            if ($memoryLimit !== '-1') {
                $memoryBytes = $this->parseMemoryLimit($memoryLimit);
                $tests['memory_limit'] = [
                    'status' => $memoryBytes >= 128 * 1024 * 1024 ? 'pass' : 'warning',
                    'message' => "Memory limit: {$memoryLimit}",
                    'details' => ['memory_limit' => $memoryLimit, 'memory_bytes' => $memoryBytes]
                ];
            } else {
                $tests['memory_limit'] = [
                    'status' => 'pass',
                    'message' => "Memory limit: unlimited",
                    'details' => ['memory_limit' => $memoryLimit]
                ];
            }

            // Test max execution time
            $maxExecutionTime = (int)$config['max_execution_time'];
            $tests['max_execution_time'] = [
                'status' => $maxExecutionTime === 0 || $maxExecutionTime >= 30 ? 'pass' : 'warning',
                'message' => "Max execution time: {$maxExecutionTime}s",
                'details' => ['max_execution_time' => $maxExecutionTime]
            ];

            // Test error reporting
            $errorReporting = (int)$config['error_reporting'];
            $tests['error_reporting'] = [
                'status' => 'info',
                'message' => "Error reporting level: {$errorReporting}",
                'details' => ['error_reporting' => $errorReporting]
            ];

            // Test OPcache
            $opcacheInfo = $this->detector->getOpcacheInfo();
            if ($opcacheInfo) {
                $tests['opcache'] = [
                    'status' => $opcacheInfo['enabled'] ? 'pass' : 'info',
                    'message' => $opcacheInfo['enabled'] ? 'OPcache is enabled' : 'OPcache is available but not enabled',
                    'details' => $opcacheInfo
                ];
            } else {
                $tests['opcache'] = [
                    'status' => 'info',
                    'message' => 'OPcache is not available',
                    'details' => ['available' => false]
                ];
            }

        } catch (\Exception $e) {
            $tests['configuration_test_error'] = [
                'status' => 'fail',
                'message' => 'Configuration test failed: ' . $e->getMessage(),
                'details' => ['exception' => $e->getMessage()]
            ];
        }

        return new TestResult([
            'test_type' => 'configuration',
            'engine' => 'php',
            'total_tests' => count($tests),
            'passed_tests' => count(array_filter($tests, fn($t) => $t['status'] === 'pass')),
            'failed_tests' => count(array_filter($tests, fn($t) => $t['status'] === 'fail')),
            'skipped_tests' => 0,
            'execution_time' => microtime(true) - $startTime,
            'failures' => array_filter($tests, fn($t) => $t['status'] === 'fail'),
            'metrics' => ['tests' => $tests],
            'timestamp' => new DateTime()
        ]);
    }

    /**
     * Ejecuta tests de funcionalidad básica del ORM
     */
    private function runORMFunctionalityTests(): TestResult
    {
        $startTime = microtime(true);
        $tests = [];

        try {
            // Test 1: Instanciación básica
            $config = ['driver' => 'sqlite', 'database' => ':memory:'];
            $orm = new \VersaORM\VersaORM($config);

            $tests['orm_instantiation'] = [
                'status' => 'pass',
                'message' => 'VersaORM instantiation successful',
                'details' => ['config' => $config]
            ];

            // Test 2: Conexión a base de datos
            $isConnected = $orm->isConnected();
            $tests['database_connection'] = [
                'status' => $isConnected ? 'pass' : 'fail',
                'message' => $isConnected ? 'Database connection successful' : 'Database connection failed',
                'details' => ['connected' => $isConnected]
            ];

            // Test 3: QueryBuilder básico
            $qb = $orm->table('test');
            $tests['querybuilder_creation'] = [
                'status' => $qb instanceof \VersaORM\QueryBuilder ? 'pass' : 'fail',
                'message' => 'QueryBuilder creation successful',
                'details' => ['class' => get_class($qb)]
            ];

            // Test 4: Creación de tabla básica
            $orm->execute("CREATE TABLE IF NOT EXISTS test_table (id INTEGER PRIMARY KEY, name TEXT)");
            $tests['table_creation'] = [
                'status' => 'pass',
                'message' => 'Table creation successful',
                'details' => ['table' => 'test_table']
            ];

            // Test 5: Inserción básica
            $insertResult = $orm->table('test_table')->insert(['name' => 'test']);
            $tests['basic_insert'] = [
                'status' => $insertResult ? 'pass' : 'fail',
                'message' => $insertResult ? 'Basic insert successful' : 'Basic insert failed',
                'details' => ['result' => $insertResult]
            ];

            // Test 6: Consulta básica
            $selectResult = $orm->table('test_table')->select()->get();
            $tests['basic_select'] = [
                'status' => is_array($selectResult) && count($selectResult) > 0 ? 'pass' : 'fail',
                'message' => 'Basic select successful',
                'details' => ['result_count' => count($selectResult)]
            ];

        } catch (\Exception $e) {
            $tests['orm_functionality_error'] = [
                'status' => 'fail',
                'message' => 'ORM functionality test failed: ' . $e->getMessage(),
                'details' => ['exception' => $e->getMessage()]
            ];
        }

        return new TestResult([
            'test_type' => 'orm_functionality',
            'engine' => 'php',
            'total_tests' => count($tests),
            'passed_tests' => count(array_filter($tests, fn($t) => $t['status'] === 'pass')),
            'failed_tests' => count(array_filter($tests, fn($t) => $t['status'] === 'fail')),
            'skipped_tests' => 0,
            'execution_time' => microtime(true) - $startTime,
            'failures' => array_filter($tests, fn($t) => $t['status'] === 'fail'),
            'metrics' => ['tests' => $tests],
            'timestamp' => new DateTime()
        ]);
    }

    /**
     * Genera resumen de resultados
     */
    private function generateSummary(array $results): array
    {
        $totalTests = 0;
        $totalPassed = 0;
        $totalFailed = 0;
        $totalSkipped = 0;
        $totalTime = 0;

        foreach ($results as $result) {
            if ($result instanceof TestResult) {
                $totalTests += $result->total_tests;
                $totalPassed += $result->passed_tests;
                $totalFailed += $result->failed_tests;
                $totalSkipped += $result->skipped_tests;
                $totalTime += $result->execution_time;
            }
        }

        return [
            'total_tests' => $totalTests,
            'passed_tests' => $totalPassed,
            'failed_tests' => $totalFailed,
            'skipped_tests' => $totalSkipped,
            'success_rate' => $totalTests > 0 ? ($totalPassed / $totalTests) * 100 : 0,
            'total_execution_time' => $totalTime,
            'php_version' => PHP_VERSION,
            'overall_status' => $totalFailed === 0 ? 'pass' : 'fail'
        ];
    }

    /**
     * Genera recomendaciones basadas en los resultados
     */
    private function generateRecommendations(array $results): array
    {
        $recommendations = [];

        // Agregar recomendaciones del detector
        $detectorRecommendations = $this->detector->generateCompatibilityReport()['recommendations'] ?? [];
        $recommendations = array_merge($recommendations, $detectorRecommendations);

        // Analizar resultados para recomendaciones adicionales
        foreach ($results as $testType => $result) {
            if ($result instanceof TestResult && $result->failed_tests > 0) {
                $recommendations[] = [
                    'type' => 'error',
                    'message' => "Failed tests in {$testType}: {$result->failed_tests} out of {$result->total_tests}"
                ];
            }
        }

        return $recommendations;
    }

    /**
     * Convierte memory_limit a bytes
     */
    private function parseMemoryLimit(string $limit): int
    {
        if ($limit === '-1') {
            return PHP_INT_MAX;
        }

        $limit = trim($limit);
        $last = strtolower($limit[strlen($limit) - 1]);
        $value = (int) $limit;

        switch ($last) {
            case 'g':
                $value *= 1024;
                // no break
            case 'm':
                $value *= 1024;
                // no break
            case 'k':
                $value *= 1024;
        }

        return $value;
    }

    /**
     * Obtiene configuración por defecto
     */
    private function getDefaultConfig(): array
    {
        return [
            'timeout' => 300,
            'memory_limit' => '256M',
            'include_performance_tests' => true,
            'include_memory_tests' => true,
            'include_extension_tests' => true,
            'verbose' => false,
        ];
    }

    /**
     * Ejecuta tests específicos para una versión PHP
     */
    public function runVersionSpecificTests(string $version): Report
    {
        if (!$this->detector->isVersionSupported($version)) {
            throw new \InvalidArgumentException("PHP version {$version} is not supported");
        }

        // Solo ejecutar si estamos en la versión correcta
        $currentVersion = $this->detector->getCurrentVersion()['short_version'];
        if ($currentVersion !== $version) {
            throw new \RuntimeException("Cannot run tests for PHP {$version} on PHP {$currentVersion}");
        }

        return $this->runAllCompatibilityTests();
    }

    /**
     * Genera reporte específico por versión PHP
     */
    public function generateVersionReport(): array
    {
        $report = $this->runAllCompatibilityTests();
        $compatibilityReport = $this->detector->generateCompatibilityReport();

        return [
            'php_version' => PHP_VERSION,
            'version_short' => PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION,
            'test_results' => $report->results,
            'summary' => $report->summary,
            'compatibility_info' => $compatibilityReport,
            'execution_time' => $report->execution_time,
            'timestamp' => $report->timestamp->format('Y-m-d H:i:s'),
            'recommendations' => $report->recommendations,
            'system_info' => [
                'os' => PHP_OS_FAMILY,
                'sapi' => PHP_SAPI,
                'zts' => PHP_ZTS,
                'debug' => PHP_DEBUG,
            ]
        ];
    }
}
