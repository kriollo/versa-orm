#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * CLI Script para ejecutar tests de compatibilidad PHP.
 *
 * Uso:
 * php tests/bin/run-php-compatibility.php [opciones]
 *
 * Opciones:
 * --version=X.Y    Ejecutar tests para versión específica (solo versión actual)
 * --output=path    Directorio de salida para reportes
 * --format=json|html|both  Formato de reporte (default: both)
 * --verbose        Salida detallada
 * --help           Mostrar ayuda
 */

// Autoload
$autoloadPaths = [
    __DIR__ . '/../../vendor/autoload.php',
    __DIR__ . '/../../../../vendor/autoload.php',
];

$autoloaded = false;

foreach ($autoloadPaths as $autoloadPath) {
    if (file_exists($autoloadPath)) {
        require_once $autoloadPath;
        $autoloaded = true;
        break;
    }
}

if (! $autoloaded) {
    // Fallback: cargar clases manualmente
    require_once __DIR__ . '/../Compatibility/PHPVersionDetector.php';
    require_once __DIR__ . '/../Compatibility/PHPVersionTestExecutor.php';
    require_once __DIR__ . '/../Compatibility/PHPVersionMatrixRunner.php';
    require_once __DIR__ . '/../Results/TestResult.php';
    require_once __DIR__ . '/../Results/Report.php';
}

use VersaORM\Tests\Compatibility\PHPVersionDetector;
use VersaORM\Tests\Compatibility\PHPVersionMatrixRunner;
use VersaORM\Tests\Results\Report;

/**
 * Clase principal del CLI.
 */
class PHPCompatibilityCLI
{
    private array $options = [];

    private PHPVersionMatrixRunner $runner;

    public function __construct(array $argv)
    {
        $this->parseArguments($argv);
        $this->runner = new PHPVersionMatrixRunner([
            'verbose' => $this->options['verbose'] ?? false,
        ]);
    }

    /**
     * Ejecuta el CLI.
     */
    public function run(): int
    {
        try {
            if (isset($this->options['help'])) {
                $this->showHelp();

                return 0;
            }

            $this->showHeader();

            // Verificar versión PHP
            $currentVersion = PHPVersionDetector::getCurrentVersion();
            $this->output("Current PHP Version: {$currentVersion['full_version']}");
            $this->output("Version ID: {$currentVersion['version_id']}");
            $this->output("SAPI: {$currentVersion['sapi']}");
            $this->output('');

            // Ejecutar tests
            $this->output('Running PHP compatibility tests...');
            $startTime = microtime(true);

            if (isset($this->options['version'])) {
                $report = $this->runVersionSpecificTests($this->options['version']);
            } else {
                $report = $this->runner->runCompatibilityMatrix();
            }

            $executionTime = microtime(true) - $startTime;
            $this->output('Tests completed in ' . number_format($executionTime, 2) . ' seconds');
            $this->output('');

            // Mostrar resumen
            $this->showSummary($report);

            // Generar reportes
            $this->generateReports($report);

            // Mostrar recomendaciones
            $this->showRecommendations($report);

            return $report->isSuccessful() ? 0 : 1;
        } catch (Exception $e) {
            $this->error('Error: ' . $e->getMessage());

            if ($this->options['verbose'] ?? false) {
                $this->error('Stack trace:');
                $this->error($e->getTraceAsString());
            }

            return 1;
        }
    }

    /**
     * Ejecuta tests para versión específica.
     */
    private function runVersionSpecificTests(string $version): Report
    {
        $currentVersion = PHPVersionDetector::getCurrentVersion()['short_version'];

        if ($version !== $currentVersion) {
            throw new InvalidArgumentException(
                "Cannot run tests for PHP {$version} on PHP {$currentVersion}. " .
                'Tests can only be run on the current PHP version.',
            );
        }

        return $this->runner->runCurrentVersionTests();
    }

    /**
     * Muestra el header del CLI.
     */
    private function showHeader(): void
    {
        $this->output('=== VersaORM PHP Compatibility Test Suite ===');
        $this->output('Version: 1.0.0');
        $this->output('Date: ' . date('Y-m-d H:i:s'));
        $this->output('');
    }

    /**
     * Muestra el resumen de resultados.
     */
    private function showSummary(Report $report): void
    {
        $this->output('=== Test Summary ===');
        $this->output('Total Tests: ' . $report->getTotalTests());
        $this->output('Passed: ' . $report->getPassedTests());
        $this->output('Failed: ' . $report->getFailedTests());
        $this->output('Success Rate: ' . number_format($report->getSuccessRate(), 1) . '%');
        $this->output('Overall Status: ' . strtoupper($report->getOverallStatus()));
        $this->output('');
    }

    /**
     * Genera reportes en los formatos solicitados.
     */
    private function generateReports(Report $report): void
    {
        $outputDir = $this->options['output'] ?? 'tests/reports/php-compatibility';
        $format = $this->options['format'] ?? 'both';

        if (! is_dir($outputDir)) {
            mkdir($outputDir, 0755, true);
        }

        $timestamp = date('Y-m-d_H-i-s');
        $phpVersion = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;

        if ($format === 'json' || $format === 'both') {
            $jsonFile = "{$outputDir}/php-{$phpVersion}-compatibility-{$timestamp}.json";
            file_put_contents($jsonFile, $report->toJson());
            $this->output("JSON report saved to: {$jsonFile}");
        }

        if ($format === 'html' || $format === 'both') {
            $htmlFile = "{$outputDir}/php-{$phpVersion}-compatibility-{$timestamp}.html";
            $html = $this->runner->exportMatrixToHtml();
            file_put_contents($htmlFile, $html);
            $this->output("HTML report saved to: {$htmlFile}");
        }

        $this->output('');
    }

    /**
     * Muestra recomendaciones.
     */
    private function showRecommendations(Report $report): void
    {
        if ($report->recommendations === []) {
            return;
        }

        $this->output('=== Recommendations ===');

        foreach ($report->recommendations as $recommendation) {
            $type = strtoupper($recommendation['type'] ?? 'INFO');
            $message = $recommendation['message'] ?? '';
            $this->output("[{$type}] {$message}");
        }
        $this->output('');
    }

    /**
     * Parsea argumentos de línea de comandos.
     */
    private function parseArguments(array $argv): void
    {
        $counter = count($argv);

        for ($i = 1; $i < $counter; $i++) {
            $arg = $argv[$i];

            if ($arg === '--help' || $arg === '-h') {
                $this->options['help'] = true;
            } elseif ($arg === '--verbose' || $arg === '-v') {
                $this->options['verbose'] = true;
            } elseif (str_starts_with($arg, '--version=')) {
                $this->options['version'] = substr($arg, 10);
            } elseif (str_starts_with($arg, '--output=')) {
                $this->options['output'] = substr($arg, 9);
            } elseif (str_starts_with($arg, '--format=')) {
                $format = substr($arg, 9);

                if (! in_array($format, ['json', 'html', 'both'], true)) {
                    throw new InvalidArgumentException("Invalid format: {$format}. Use json, html, or both.");
                }
                $this->options['format'] = $format;
            } else {
                throw new InvalidArgumentException("Unknown argument: {$arg}");
            }
        }
    }

    /**
     * Muestra ayuda.
     */
    private function showHelp(): void
    {
        $this->output('VersaORM PHP Compatibility Test Suite');
        $this->output('');
        $this->output('Usage:');
        $this->output('  php tests/bin/run-php-compatibility.php [options]');
        $this->output('');
        $this->output('Options:');
        $this->output('  --version=X.Y     Run tests for specific PHP version (current version only)');
        $this->output('  --output=path     Output directory for reports (default: tests/reports/php-compatibility)');
        $this->output('  --format=format   Report format: json, html, or both (default: both)');
        $this->output('  --verbose, -v     Verbose output');
        $this->output('  --help, -h        Show this help message');
        $this->output('');
        $this->output('Examples:');
        $this->output('  php tests/bin/run-php-compatibility.php');
        $this->output('  php tests/bin/run-php-compatibility.php --version=8.1 --format=html');
        $this->output('  php tests/bin/run-php-compatibility.php --output=/tmp/reports --verbose');
        $this->output('');
        $this->output('Supported PHP Versions: 7.4, 8.0, 8.1, 8.2, 8.3');
    }

    /**
     * Imprime mensaje de salida.
     */
    private function output(string $message): void
    {
        echo $message . PHP_EOL;
    }

    /**
     * Imprime mensaje de error.
     */
    private function error(string $message): void
    {
        fwrite(STDERR, $message . PHP_EOL);
    }
}

// Ejecutar CLI
$cli = new PHPCompatibilityCLI($argv);
exit($cli->run());
