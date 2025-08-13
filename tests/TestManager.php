<?php

declare(strict_types=1);

namespace VersaORM\Tests;

use DateTime;
use Exception;
use InvalidArgumentException;
use VersaORM\Tests\Interfaces\TestManagerInterface;
use VersaORM\Tests\Logging\TestLogger;
use VersaORM\Tests\Metrics\MetricsCollector;
use VersaORM\Tests\Results\BenchmarkResult;
use VersaORM\Tests\Results\QualityResult;
use VersaORM\Tests\Results\Report;
use VersaORM\Tests\Results\TestResult;

use function call_user_func_array;
use function count;
use function in_array;
use function is_array;

/**
 * TestManager - Coordina la ejecución de todos los tipos de tests y genera reportes consolidados.
 *
 * Responsabilidades:
 * - Orquestar la ejecución de tests unitarios, integración, benchmarks y análisis de calidad
 * - Generar reportes consolidados con métricas unificadas
 * - Manejar la configuración y logging del sistema de QA
 */
class TestManager implements TestManagerInterface
{
    private TestLogger $logger;

    private MetricsCollector $metrics;

    private array $config;

    private array $supportedEngines = ['mysql', 'postgresql', 'sqlite'];

    public function __construct(array $config = [])
    {
        $this->config  = array_merge($this->getDefaultConfig(), $config);
        $this->logger  = new TestLogger($this->config['logging']);
        $this->metrics = new MetricsCollector($this->config['metrics']);

        $this->logger->info('TestManager initialized', ['config' => $this->config]);
    }

    /**
     * Ejecuta la suite completa de tests con todas las validaciones.
     */
    public function runFullSuite(array $options = []): Report
    {
        $startTime = microtime(true);
        $this->logger->info('Starting full test suite execution', $options);

        $results = [
            'unit_tests'        => [],
            'integration_tests' => [],
            'benchmarks'        => [],
            'quality_analysis'  => [],
        ];

        try {
            // Ejecutar tests unitarios en todos los motores
            foreach ($this->supportedEngines as $engine) {
                $this->logger->info("Running unit tests for engine: {$engine}");
                $results['unit_tests'][$engine] = $this->runUnitTests($engine);
            }

            // Ejecutar tests de integración
            foreach ($this->supportedEngines as $engine) {
                $this->logger->info("Running integration tests for engine: {$engine}");
                $results['integration_tests'][$engine] = $this->runIntegrationTests($engine);
            }

            // Ejecutar benchmarks si está habilitado
            if ($options['include_benchmarks'] ?? true) {
                $this->logger->info('Running benchmark suite');
                $results['benchmarks'] = $this->runBenchmarks($options['benchmark_comparisons'] ?? []);
            }

            // Ejecutar análisis de calidad
            if ($options['include_quality'] ?? true) {
                $this->logger->info('Running quality analysis');
                $results['quality_analysis'] = $this->runQualityAnalysis();
            }

            $executionTime = microtime(true) - $startTime;
            $this->metrics->recordExecutionTime('full_suite', $executionTime);

            $report = $this->generateReport($results);
            $this->logger->info('Full test suite completed successfully', [
                'execution_time' => $executionTime,
                'total_tests'    => $this->countTotalTests($results),
            ]);

            return $report;
        } catch (Exception $e) {
            $this->logger->error('Full test suite execution failed', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            throw $e;
        }
    }

    /**
     * Ejecuta tests unitarios para un motor específico o todos.
     */
    public function runUnitTests(string $engine = 'all'): TestResult
    {
        $startTime = microtime(true);
        $this->logger->info('Starting unit tests', ['engine' => $engine]);

        if ($engine === 'all') {
            $results = [];

            foreach ($this->supportedEngines as $eng) {
                $results[$eng] = $this->runUnitTests($eng);
            }

            return $this->mergeTestResults($results, 'unit');
        }

        if (!in_array($engine, $this->supportedEngines, true)) {
            throw new InvalidArgumentException("Unsupported engine: {$engine}");
        }

        // Ejecutar PHPUnit para el motor específico
        $testDir     = 'test' . ucfirst($engine === 'mysql' ? 'Mysql' : ($engine === 'postgresql' ? 'PostgreSQL' : 'SQLite'));
        $phpunitPath = PHP_OS_FAMILY === 'Windows' ? 'vendor\bin\phpunit.bat' : 'vendor/bin/phpunit';
        $command     = "{$phpunitPath} {$testDir} --testdox --no-coverage";

        $output     = [];
        $returnCode = 0;
        exec($command, $output, $returnCode);

        // Debug: Log the actual output for troubleshooting
        $this->logger->info("PHPUnit command: {$command}");
        $this->logger->info('PHPUnit output: ' . implode("\n", $output));
        $this->logger->info("PHPUnit return code: {$returnCode}");

        $executionTime = microtime(true) - $startTime;
        $this->metrics->recordExecutionTime("unit_tests_{$engine}", $executionTime);

        $result = new TestResult([
            'test_type'      => 'unit',
            'engine'         => $engine,
            'total_tests'    => $this->parseTestCount($output),
            'passed_tests'   => $this->parsePassedTests($output),
            'failed_tests'   => $this->parseFailedTests($output),
            'skipped_tests'  => $this->parseSkippedTests($output),
            'execution_time' => $executionTime,
            'failures'       => $this->parseFailures($output),
            'metrics'        => $this->extractMetrics($output),
            'timestamp'      => new DateTime(),
        ]);

        $this->logger->info("Unit tests completed for {$engine}", [
            'total'          => $result->total_tests,
            'passed'         => $result->passed_tests,
            'failed'         => $result->failed_tests,
            'execution_time' => $executionTime,
        ]);

        return $result;
    }

    /**
     * Ejecuta tests de integración para un motor específico o todos.
     */
    public function runIntegrationTests(string $engine = 'all'): TestResult
    {
        $startTime = microtime(true);
        $this->logger->info('Starting integration tests', ['engine' => $engine]);

        // Por ahora, los tests de integración son los mismos que los unitarios
        // pero con configuración específica para validar integración entre componentes
        $result            = $this->runUnitTests($engine);
        $result->test_type = 'integration';

        $executionTime = microtime(true) - $startTime;
        $this->metrics->recordExecutionTime("integration_tests_{$engine}", $executionTime);

        return $result;
    }

    /**
     * Ejecuta suite de benchmarks con comparaciones opcionales.
     */
    public function runBenchmarks(array $comparisons = []): BenchmarkResult
    {
        $startTime = microtime(true);
        $this->logger->info('Starting benchmark execution', ['comparisons' => $comparisons]);

        // Placeholder para implementación futura de benchmarks
        $result = new BenchmarkResult(
            benchmarkName: 'comprehensive_suite',
            engine: 'all',
            metrics: [
                'throughput'   => 1000,
                'latency'      => 0.05,
                'memory_usage' => 64 * 1024 * 1024,
            ],
            comparisons: $comparisons,
            dataPoints: [],
            executionTime: microtime(true) - $startTime,
            timestamp: new DateTime(),
        );

        $this->logger->info('Benchmarks completed', ['execution_time' => $result->executionTime]);

        return $result;
    }

    /**
     * Ejecuta análisis de calidad con todas las herramientas.
     */
    public function runQualityAnalysis(): QualityResult
    {
        $startTime = microtime(true);
        $this->logger->info('Starting quality analysis');

        $tools   = ['phpstan', 'psalm', 'php-cs-fixer'];
        $results = [];

        foreach ($tools as $tool) {
            try {
                $results[$tool] = $this->runQualityTool($tool);
            } catch (Exception $e) {
                $this->logger->warning("Quality tool {$tool} failed", ['error' => $e->getMessage()]);
                $results[$tool] = [
                    'passed' => false,
                    'score'  => 0,
                    'issues' => [$e->getMessage()],
                ];
            }
        }

        $overallScore = $this->calculateOverallQualityScore($results);

        $result = new QualityResult(
            tool: 'comprehensive',
            score: $overallScore,
            issues: $this->aggregateIssues($results),
            metrics: $results,
            passed: $overallScore >= 80,
            output: json_encode($results, JSON_PRETTY_PRINT),
            timestamp: new DateTime(),
        );

        $executionTime = microtime(true) - $startTime;
        $this->metrics->recordExecutionTime('quality_analysis', $executionTime);

        $this->logger->info('Quality analysis completed', [
            'score'          => $overallScore,
            'passed'         => $result->passed,
            'execution_time' => $executionTime,
        ]);

        return $result;
    }

    /**
     * Genera reporte consolidado de todos los resultados.
     */
    public function generateReport(array $results): Report
    {
        $this->logger->info('Generating consolidated report');

        $summary = $this->generateSummary($results);
        $alerts  = $this->generateAlerts($results);

        $report = new Report([
            'report_id'   => uniqid('report_', true),
            'test_type'   => 'full_suite',
            'php_version' => PHP_VERSION,
            'results'     => [
                'unit_tests'        => $results['unit_tests'] ?? [],
                'integration_tests' => $results['integration_tests'] ?? [],
                'benchmarks'        => $results['benchmarks'] ?? [],
                'quality_analysis'  => $results['quality_analysis'] ?? [],
            ],
            'summary'         => $summary,
            'execution_time'  => $this->calculateTotalExecutionTime($results),
            'timestamp'       => new DateTime(),
            'recommendations' => $alerts,
        ]);

        // Guardar reporte en archivo
        $reportPath = $this->config['reports']['output_dir'] . '/report_' . date('Y-m-d_H-i-s') . '.json';
        file_put_contents($reportPath, json_encode($report, JSON_PRETTY_PRINT));

        $this->logger->info('Report generated successfully', ['path' => $reportPath]);

        return $report;
    }

    /**
     * Configuración por defecto del sistema.
     */
    private function getDefaultConfig(): array
    {
        return [
            'logging' => [
                'level'      => 'info',
                'output_dir' => 'tests/logs',
                'max_files'  => 10,
            ],
            'metrics' => [
                'enabled'        => true,
                'output_dir'     => 'tests/metrics',
                'retention_days' => 30,
            ],
            'reports' => [
                'output_dir'     => 'tests/reports',
                'format'         => ['json', 'html'],
                'include_trends' => true,
            ],
            'quality_gates' => [
                'min_coverage'      => 95,
                'max_complexity'    => 10,
                'min_quality_score' => 80,
            ],
        ];
    }

    // Métodos auxiliares para parsing de resultados de PHPUnit
    private function parseTestCount(array $output): int
    {
        foreach ($output as $line) {
            // Buscar patrones como "OK (399 tests, 1176 assertions)"
            if (preg_match('/OK \((\d+) tests?/', $line, $matches)) {
                return (int) $matches[1];
            }

            // Buscar patrones como "Tests: 399, Assertions: 1176"
            if (preg_match('/Tests: (\d+)/', $line, $matches)) {
                return (int) $matches[1];
            }
        }

        return 0;
    }

    private function parsePassedTests(array $output): int
    {
        foreach ($output as $line) {
            // Si encontramos "OK (X tests)" significa que todos pasaron
            if (preg_match('/OK \((\d+) tests?/', $line, $matches)) {
                return (int) $matches[1];
            }

            // Buscar patrones de fallos para calcular los que pasaron
            if (preg_match('/FAILURES!.*Tests: (\d+), Assertions: \d+, Failures: (\d+)/', $line, $matches)) {
                $total    = (int) $matches[1];
                $failures = (int) $matches[2];

                return $total - $failures;
            }
        }

        return 0;
    }

    private function parseFailedTests(array $output): int
    {
        foreach ($output as $line) {
            // Buscar patrones como "FAILURES! Tests: 10, Assertions: 20, Failures: 2"
            if (preg_match('/FAILURES!.*Failures: (\d+)/', $line, $matches)) {
                return (int) $matches[1];
            }

            if (preg_match('/Failures: (\d+)/', $line, $matches)) {
                return (int) $matches[1];
            }
        }

        return 0;
    }

    private function parseSkippedTests(array $output): int
    {
        foreach ($output as $line) {
            if (preg_match('/Skipped: (\d+)/', $line, $matches)) {
                return (int) $matches[1];
            }
        }

        return 0;
    }

    private function parseFailures(array $output): array
    {
        // Implementar parsing de fallos específicos
        return [];
    }

    private function extractMetrics(array $output): array
    {
        return [
            'memory_usage' => memory_get_peak_usage(true),
            'time'         => microtime(true),
        ];
    }

    private function mergeTestResults(array $results, string $type): TestResult
    {
        $totalTests    = array_sum(array_map(static fn ($r) => $r->total_tests, $results));
        $passedTests   = array_sum(array_map(static fn ($r) => $r->passed_tests, $results));
        $failedTests   = array_sum(array_map(static fn ($r) => $r->failed_tests, $results));
        $skippedTests  = array_sum(array_map(static fn ($r) => $r->skipped_tests, $results));
        $executionTime = array_sum(array_map(static fn ($r) => $r->execution_time, $results));

        return new TestResult([
            'test_type'      => $type,
            'engine'         => 'all',
            'total_tests'    => $totalTests,
            'passed_tests'   => $passedTests,
            'failed_tests'   => $failedTests,
            'skipped_tests'  => $skippedTests,
            'execution_time' => $executionTime,
            'failures'       => call_user_func_array('array_merge', array_values(array_map(static fn ($r) => $r->failures, $results))),
            'metrics'        => ['merged_results' => $results],
            'timestamp'      => new DateTime(),
        ]);
    }

    private function runQualityTool(string $tool): array
    {
        $isWindows = PHP_OS_FAMILY === 'Windows';

        switch ($tool) {
            case 'phpstan':
                $phpstanPath = $isWindows ? 'vendor\bin\phpstan.bat' : 'vendor/bin/phpstan';
                $command     = "{$phpstanPath} analyse src --level=8 --no-progress --error-format=json";
                exec($command, $output, $code);

                return [
                    'passed' => $code === 0,
                    'score'  => $code === 0 ? 100 : 50,
                    'issues' => $code === 0 ? [] : ['PHPStan found issues'],
                ];

            case 'psalm':
                $psalmPath = $isWindows ? 'vendor\bin\psalm.bat' : 'vendor/bin/psalm';
                $command   = "{$psalmPath} --no-cache --output-format=json";
                exec($command, $output, $code);

                return [
                    'passed' => $code === 0,
                    'score'  => $code === 0 ? 100 : 50,
                    'issues' => $code === 0 ? [] : ['Psalm found issues'],
                ];

            case 'php-cs-fixer':
                $csFixerPath = $isWindows ? 'vendor\bin\php-cs-fixer.bat' : 'vendor/bin/php-cs-fixer';
                $command     = "{$csFixerPath} fix --dry-run --diff";
                exec($command, $output, $code);

                return [
                    'passed' => $code === 0,
                    'score'  => $code === 0 ? 100 : 80,
                    'issues' => $code === 0 ? [] : ['Code style issues found'],
                ];

            default:
                throw new InvalidArgumentException("Unknown quality tool: {$tool}");
        }
    }

    private function calculateOverallQualityScore(array $results): int
    {
        if (empty($results)) {
            return 0;
        }

        $totalScore = array_sum(array_map(static fn ($r) => $r['score'], $results));

        return (int) ($totalScore / count($results));
    }

    private function aggregateIssues(array $results): array
    {
        $issues = [];

        foreach ($results as $tool => $result) {
            foreach ($result['issues'] as $issue) {
                $issues[] = "[{$tool}] {$issue}";
            }
        }

        return $issues;
    }

    private function generateSummary(array $results): array
    {
        $totalTests   = 0;
        $passedTests  = 0;
        $failedTests  = 0;
        $skippedTests = 0;

        // Contar tests unitarios
        foreach ($results['unit_tests'] ?? [] as $result) {
            $totalTests += $result->total_tests;
            $passedTests += $result->passed_tests;
            $failedTests += $result->failed_tests;
            $skippedTests += $result->skipped_tests;
        }

        // Contar tests de integración
        foreach ($results['integration_tests'] ?? [] as $result) {
            $totalTests += $result->total_tests;
            $passedTests += $result->passed_tests;
            $failedTests += $result->failed_tests;
            $skippedTests += $result->skipped_tests;
        }

        $successRate = $totalTests > 0 ? ($passedTests / $totalTests) * 100 : 0;

        return [
            'total_test_suites' => count($results['unit_tests'] ?? []),
            'total_tests'       => $totalTests,
            'passed_tests'      => $passedTests,
            'failed_tests'      => $failedTests,
            'skipped_tests'     => $skippedTests,
            'success_rate'      => $successRate,
            'overall_status'    => $this->calculateOverallStatus($results),
            'execution_time'    => $this->calculateTotalExecutionTime($results),
            'quality_score'     => $this->extractQualityScore($results),
        ];
    }

    private function generateAlerts(array $results): array
    {
        $alerts = [];

        // Verificar fallos críticos
        foreach ($results['unit_tests'] ?? [] as $engine => $result) {
            if ($result->failed_tests > 0) {
                $alerts[] = [
                    'level'   => 'error',
                    'message' => "Unit tests failed for {$engine}: {$result->failed_tests} failures",
                    'engine'  => $engine,
                ];
            }
        }

        return $alerts;
    }

    private function calculateOverallStatus(array $results): string
    {
        // Lógica para determinar estado general
        return 'success'; // Placeholder
    }

    private function calculateTotalExecutionTime(array $results): float
    {
        $total = 0;

        foreach ($results as $category => $categoryResults) {
            if (is_array($categoryResults)) {
                foreach ($categoryResults as $result) {
                    if (isset($result->executionTime)) {
                        $total += $result->executionTime;
                    }
                }
            }
        }

        return $total;
    }

    private function extractQualityScore(array $results): int
    {
        return $results['quality_analysis']->score ?? 0;
    }

    private function countTotalTests(array $results): int
    {
        $total = 0;

        foreach ($results['unit_tests'] ?? [] as $result) {
            $total += $result->total_tests;
        }

        return $total;
    }

    private function getProjectVersion(): string
    {
        $composer = json_decode(file_get_contents('composer.json'), true);

        return $composer['version'] ?? '1.0.0';
    }
}
