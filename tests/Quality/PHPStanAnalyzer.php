<?php

declare(strict_types=1);

namespace VersaORM\Tests\Quality;

use DateTime;

use function count;
use function in_array;
use function is_bool;
use function sprintf;

/**
 * PHPStan Analyzer for automated code quality analysis.
 */
class PHPStanAnalyzer
{
    private string $phpstanPath;

    public function __construct(
        ?string $phpstanPath = null,
        private string $configPath = 'phpstan.neon',
        private string $reportsDir = 'tests/reports/phpstan',
    ) {
        // Auto-detect PHPStan path based on OS
        if ($phpstanPath === null) {
            $phpstanPath = $this->detectPHPStanPath();
        }
        $this->phpstanPath = $phpstanPath;

        if (! is_dir($this->reportsDir)) {
            mkdir($this->reportsDir, 0755, true);
        }
    }

    /**
     * Run PHPStan analysis with detailed reporting.
     */
    public function analyze(array $options = []): array
    {
        $timestamp = new DateTime();
        $reportFile = $this->reportsDir . '/phpstan-' . $timestamp->format('Y-m-d-H-i-s') . '.json';

        $command = $this->buildCommand($options);

        $startTime = microtime(true);
        $output = [];
        $returnCode = 0;

        exec($command, $output, $returnCode);

        $executionTime = microtime(true) - $startTime;

        $result = [
            'timestamp' => $timestamp->format('c'),
            'execution_time' => $executionTime,
            'return_code' => $returnCode,
            'command' => $command,
            'output' => implode("\n", $output),
            'report_file' => $reportFile,
            'passed' => $returnCode === 0,
            'errors' => [],
            'warnings' => [],
            'summary' => [],
        ];

        // Parse output for errors and warnings
        $this->parseOutput($output, $result);

        // Save detailed report
        file_put_contents($reportFile, json_encode($result, JSON_PRETTY_PRINT));

        return $result;
    }

    /**
     * Generate baseline for existing errors.
     */
    public function generateBaseline(string $memoryLimit = '512M'): array
    {
        $command = sprintf(
            '%s analyse --generate-baseline --memory-limit=%s',
            $this->phpstanPath,
            $memoryLimit,
        );

        $output = [];
        $returnCode = 0;

        exec($command, $output, $returnCode);

        return [
            'success' => $returnCode === 0,
            'output' => implode("\n", $output),
            'baseline_file' => 'phpstan-baseline.neon',
        ];
    }

    /**
     * Run analysis without baseline to see all errors.
     */
    public function analyzeWithoutBaseline(): array
    {
        // Temporarily disable baseline
        $configContent = file_get_contents($this->configPath);
        $modifiedConfig = str_replace(
            'baseline: phpstan-baseline.neon',
            '# baseline: phpstan-baseline.neon',
            $configContent,
        );

        $tempConfigFile = $this->configPath . '.temp';
        file_put_contents($tempConfigFile, $modifiedConfig);

        try {
            $command = sprintf(
                '%s analyse --configuration=%s --error-format=json --memory-limit=512M',
                $this->phpstanPath,
                $tempConfigFile,
            );

            $output = [];
            $returnCode = 0;

            exec($command, $output, $returnCode);

            $result = [
                'without_baseline' => true,
                'return_code' => $returnCode,
                'raw_output' => implode("\n", $output),
            ];

            // Try to parse JSON output
            $jsonOutput = implode("\n", $output);
            $decoded = json_decode($jsonOutput, true);

            if ($decoded !== null) {
                $result['parsed_output'] = $decoded;
                $result['total_errors'] = $decoded['totals']['errors'] ?? 0;
                $result['total_file_errors'] = $decoded['totals']['file_errors'] ?? 0;
            }

            return $result;
        } finally {
            // Clean up temp config file
            if (file_exists($tempConfigFile)) {
                unlink($tempConfigFile);
            }
        }
    }

    /**
     * Get quality metrics from PHPStan analysis.
     */
    public function getQualityMetrics(): array
    {
        $result = $this->analyze(['--error-format' => 'json']);

        $metrics = [
            'phpstan_level' => 8,
            'execution_time' => $result['execution_time'],
            'passed' => $result['passed'],
            'total_errors' => 0,
            'error_categories' => [],
            'files_analyzed' => 0,
            'quality_score' => 0,
        ];

        // Parse JSON output if available
        if (isset($result['parsed_output'])) {
            $parsed = $result['parsed_output'];
            $metrics['total_errors'] = $parsed['totals']['errors'] ?? 0;
            $metrics['total_file_errors'] = $parsed['totals']['file_errors'] ?? 0;

            // Calculate quality score (100 - error_density)
            $filesAnalyzed = count($parsed['files'] ?? []);
            $metrics['files_analyzed'] = $filesAnalyzed;

            if ($filesAnalyzed > 0) {
                $errorDensity = ($metrics['total_errors'] / $filesAnalyzed) * 10;
                $metrics['quality_score'] = max(0, 100 - $errorDensity);
            }
        }

        return $metrics;
    }

    /**
     * Generate HTML report from analysis results.
     */
    public function generateHTMLReport(array $analysisResult): string
    {
        $html = '<!DOCTYPE html>
<html>
<head>
    <title>PHPStan Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .passed { color: green; }
        .failed { color: red; }
        .section { margin: 20px 0; }
        .error { background: #ffe6e6; padding: 10px; margin: 5px 0; border-radius: 3px; }
        .warning { background: #fff3cd; padding: 10px; margin: 5px 0; border-radius: 3px; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>PHPStan Analysis Report</h1>
        <p><strong>Timestamp:</strong> ' . $analysisResult['timestamp'] . '</p>
        <p><strong>Execution Time:</strong> ' . number_format($analysisResult['execution_time'], 2) . 's</p>
        <p><strong>Status:</strong> <span class="' . ($analysisResult['passed'] ? 'passed' : 'failed') . '">' .
            ($analysisResult['passed'] ? 'PASSED' : 'FAILED') . '</span></p>
    </div>';

        if (! empty($analysisResult['errors'])) {
            $html .= '<div class="section">
                <h2>Errors</h2>';

            foreach ($analysisResult['errors'] as $error) {
                $html .= '<div class="error">' . htmlspecialchars($error) . '</div>';
            }
            $html .= '</div>';
        }

        if (! empty($analysisResult['warnings'])) {
            $html .= '<div class="section">
                <h2>Warnings</h2>';

            foreach ($analysisResult['warnings'] as $warning) {
                $html .= '<div class="warning">' . htmlspecialchars($warning) . '</div>';
            }
            $html .= '</div>';
        }

        return $html . ('<div class="section">
            <h2>Full Output</h2>
            <pre>' . htmlspecialchars($analysisResult['output']) . '</pre>
        </div>

        <div class="section">
            <h2>Command Executed</h2>
            <pre>' . htmlspecialchars($analysisResult['command']) . '</pre>
        </div>
    </body>
</html>');
    }

    /**
     * Detect PHPStan executable path based on OS.
     */
    private function detectPHPStanPath(): string
    {
        $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';

        if ($isWindows) {
            // Try different Windows paths
            $paths = [
                'vendor\bin\phpstan.bat',
                'vendor\bin\phpstan',
                'php vendor\phpstan\phpstan\phpstan.phar',
            ];
        } else {
            // Unix-like systems
            $paths = [
                'vendor/bin/phpstan',
                'php vendor/phpstan/phpstan/phpstan.phar',
            ];
        }

        foreach ($paths as $path) {
            if (file_exists($path) || $this->commandExists($path)) {
                return $path;
            }
        }

        // Fallback to composer execution
        return $isWindows ? 'php vendor\phpstan\phpstan\phpstan.phar' : 'php vendor/phpstan/phpstan/phpstan.phar';
    }

    /**
     * Check if a command exists.
     */
    private function commandExists(string $command): bool
    {
        $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        $testCommand = $isWindows ? "where {$command}" : "which {$command}";

        $output = shell_exec($testCommand);

        return ! ($output === '' || $output === '0' || $output === false || $output === null);
    }

    /**
     * Build PHPStan command with options.
     */
    private function buildCommand(array $options): string
    {
        $command = $this->phpstanPath . ' analyse';

        // Add memory limit
        $memoryLimit = $options['memory-limit'] ?? '512M';
        $command .= ' --memory-limit=' . $memoryLimit;

        // Add error format
        $errorFormat = $options['error-format'] ?? 'table';
        $command .= ' --error-format=' . $errorFormat;

        // Add other options
        foreach ($options as $key => $value) {
            if (! in_array($key, ['memory-limit', 'error-format'], true)) {
                if (is_bool($value) && $value) {
                    $command .= ' --' . $key;
                } elseif (! is_bool($value)) {
                    $command .= ' --' . $key . '=' . $value;
                }
            }
        }

        return $command;
    }

    /**
     * Parse PHPStan output for errors and warnings.
     */
    private function parseOutput(array $output, array &$result): void
    {
        $errors = [];
        $warnings = [];

        foreach ($output as $line) {
            if (str_contains($line, '[ERROR]')) {
                $errors[] = trim(str_replace('[ERROR]', '', $line));
            } elseif (str_contains($line, '[WARNING]')) {
                $warnings[] = trim(str_replace('[WARNING]', '', $line));
            } elseif (preg_match('/(\d+)\/(\d+)/', $line, $matches)) {
                $result['summary']['files_processed'] = $matches[2];
            }
        }

        $result['errors'] = $errors;
        $result['warnings'] = $warnings;
    }
}
