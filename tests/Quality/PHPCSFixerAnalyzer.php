<?php

declare(strict_types=1);

namespace VersaORM\Tests\Quality;

use DateTime;
use Exception;
use PhpCsFixer\Config;

use function count;
use function dirname;
use function is_bool;

/**
 * PHP-CS-Fixer Analyzer for automated code style analysis and fixing.
 */
class PHPCSFixerAnalyzer
{
    private string $phpcsFixerPath;

    public function __construct(
        null|string $phpcsFixerPath = null,
        private string $configPath = '.php-cs-fixer.dist.php',
        private string $reportsDir = 'tests/reports/php-cs-fixer',
    ) {
        // Auto-detect PHP-CS-Fixer path based on OS
        if ($phpcsFixerPath === null) {
            $phpcsFixerPath = $this->detectPHPCSFixerPath();
        }

        $this->phpcsFixerPath = $phpcsFixerPath;

        if (!is_dir($this->reportsDir)) {
            mkdir($this->reportsDir, 0755, true);
        }
    }

    /**
     * Run PHP-CS-Fixer analysis (dry-run by default).
     */
    public function analyze(bool $dryRun = true, array $options = []): array
    {
        $timestamp = new DateTime();
        $reportFile = $this->reportsDir . '/php-cs-fixer-' . $timestamp->format('Y-m-d-H-i-s') . '.json';

        $command = $this->buildCommand($dryRun, $options);

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
            'dry_run' => $dryRun,
            'output' => implode("\n", $output),
            'report_file' => $reportFile,
            'passed' => $dryRun ? $returnCode === 0 || $returnCode === 8 : $returnCode === 0,
            'files_processed' => 0,
            'files_fixed' => 0,
            'violations' => [],
            'summary' => [],
        ];

        // Parse output for violations and statistics
        $this->parseOutput($output, $result);

        // Save detailed report
        file_put_contents($reportFile, json_encode($result, JSON_PRETTY_PRINT));

        return $result;
    }

    /**
     * Fix code style issues.
     */
    public function fix(array $options = []): array
    {
        return $this->analyze(false, $options);
    }

    /**
     * Check code style without fixing.
     */
    public function check(array $options = []): array
    {
        return $this->analyze(true, $options);
    }

    /**
     * Get code style quality metrics.
     */
    public function getQualityMetrics(): array
    {
        $result = $this->check(['--format' => 'json']);

        $metrics = [
            'execution_time' => $result['execution_time'],
            'passed' => $result['passed'],
            'files_processed' => $result['files_processed'],
            'files_with_violations' => 0,
            'total_violations' => 0,
            'violation_types' => [],
            'quality_score' => 0,
        ];

        // Count violations
        $violationCount = count($result['violations']);
        $metrics['total_violations'] = $violationCount;

        if ($result['files_processed'] > 0) {
            $metrics['files_with_violations'] = count(array_unique(array_column($result['violations'], 'file')));

            // Calculate quality score (100 - violation_density)
            $violationDensity = ($violationCount / $result['files_processed']) * 10;
            $metrics['quality_score'] = max(0, 100 - $violationDensity);
        }

        // Group violations by type
        foreach ($result['violations'] as $violation) {
            $rule = $violation['rule'] ?? 'unknown';

            if (!isset($metrics['violation_types'][$rule])) {
                $metrics['violation_types'][$rule] = 0;
            }
            $metrics['violation_types'][$rule]++;
        }

        return $metrics;
    }

    /**
     * Validate configuration file.
     */
    public function validateConfig(): array
    {
        if (!file_exists($this->configPath)) {
            return [
                'valid' => false,
                'error' => 'Configuration file not found: ' . $this->configPath,
            ];
        }

        // Try to load the configuration
        try {
            $config = include $this->configPath;

            if (!$config instanceof Config) {
                return [
                    'valid' => false,
                    'error' => 'Configuration file does not return a PhpCsFixer\Config instance',
                ];
            }

            return [
                'valid' => true,
                'rules_count' => count($config->getRules()),
                'risky_allowed' => $config->getRiskyAllowed(),
                'using_cache' => $config->getUsingCache(),
            ];
        } catch (Exception $e) {
            return [
                'valid' => false,
                'error' => 'Configuration error: ' . $e->getMessage(),
            ];
        }
    }

    /**
     * Create pre-commit hook for automatic formatting.
     */
    public function createPreCommitHook(): array
    {
        $hookPath = '.git/hooks/pre-commit';
        $hookContent =
            '#!/bin/sh
# PHP-CS-Fixer pre-commit hook

echo "Running PHP-CS-Fixer..."

# Get list of staged PHP files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep "\.php$")

if [ -z "$STAGED_FILES" ]; then
    echo "No PHP files to check."
    exit 0
fi

# Run PHP-CS-Fixer on staged files
'
            . $this->phpcsFixerPath
            . ' fix --config='
            . $this->configPath
            . ' --dry-run --diff --verbose

if [ $? -ne 0 ]; then
    echo "PHP-CS-Fixer found style violations. Please run:"
    echo "  '
            . $this->phpcsFixerPath
            . ' fix --config='
            . $this->configPath
            . '"
    echo "Then add the fixed files and commit again."
    exit 1
fi

echo "PHP-CS-Fixer: All files are properly formatted."
exit 0
';

        try {
            // Create .git/hooks directory if it doesn't exist
            $hooksDir = dirname($hookPath);

            if (!is_dir($hooksDir)) {
                mkdir($hooksDir, 0755, true);
            }

            file_put_contents($hookPath, $hookContent);
            chmod($hookPath, 0755);

            return [
                'success' => true,
                'hook_path' => $hookPath,
                'message' => 'Pre-commit hook created successfully',
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => 'Failed to create pre-commit hook: ' . $e->getMessage(),
            ];
        }
    }

    /**
     * Generate HTML report from analysis results.
     */
    public function generateHTMLReport(array $analysisResult): string
    {
        $html =
            '<!DOCTYPE html>
<html>
<head>
    <title>PHP-CS-Fixer Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .passed { color: green; }
        .failed { color: red; }
        .section { margin: 20px 0; }
        .violation { background: #fff3cd; padding: 10px; margin: 5px 0; border-radius: 3px; }
        .file-path { font-weight: bold; color: #0066cc; }
        .rule-name { color: #cc6600; font-family: monospace; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .stats { display: flex; gap: 20px; }
        .stat { background: #e9ecef; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-number { font-size: 24px; font-weight: bold; color: #495057; }
        .stat-label { color: #6c757d; }
    </style>
</head>
<body>
    <div class="header">
        <h1>PHP-CS-Fixer Analysis Report</h1>
        <p><strong>Timestamp:</strong> '
            . $analysisResult['timestamp']
            . '</p>
        <p><strong>Execution Time:</strong> '
            . number_format($analysisResult['execution_time'], 2)
            . 's</p>
        <p><strong>Mode:</strong> '
            . ($analysisResult['dry_run'] ? 'Check Only' : 'Fix Mode')
            . '</p>
        <p><strong>Status:</strong> <span class="'
            . ($analysisResult['passed'] ? 'passed' : 'failed')
            . '">'
            . ($analysisResult['passed'] ? 'PASSED' : 'FAILED')
            . '</span></p>
    </div>

    <div class="stats">
        <div class="stat">
            <div class="stat-number">'
            . $analysisResult['files_processed']
            . '</div>
            <div class="stat-label">Files Processed</div>
        </div>
        <div class="stat">
            <div class="stat-number">'
            . $analysisResult['files_fixed']
            . '</div>
            <div class="stat-label">Files Fixed</div>
        </div>
        <div class="stat">
            <div class="stat-number">'
            . count($analysisResult['violations'])
            . '</div>
            <div class="stat-label">Violations Found</div>
        </div>
    </div>';

        if (!empty($analysisResult['violations'])) {
            $html .= '<div class="section">
                <h2>Style Violations</h2>';

            foreach ($analysisResult['violations'] as $violation) {
                $html .=
                    '<div class="violation">
                    <div class="file-path">'
                    . htmlspecialchars($violation['file'])
                    . '</div>
                    <div><span class="rule-name">'
                    . htmlspecialchars($violation['rule'])
                    . '</span>: '
                    . htmlspecialchars($violation['message'])
                    . '</div>
                </div>';
            }
            $html .= '</div>';
        }

        return (
            $html . (
                '<div class="section">
            <h2>Full Output</h2>
            <pre>'
                . htmlspecialchars($analysisResult['output'])
                . '</pre>
        </div>

        <div class="section">
            <h2>Command Executed</h2>
            <pre>'
                . htmlspecialchars($analysisResult['command'])
                . '</pre>
        </div>
    </body>
</html>'
            )
        );
    }

    /**
     * Detect PHP-CS-Fixer executable path based on OS.
     */
    private function detectPHPCSFixerPath(): string
    {
        $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';

        if ($isWindows) {
            // Try different Windows paths
            $paths = [
                'vendor\bin\php-cs-fixer.bat',
                'vendor\bin\php-cs-fixer',
                'php vendor\friendsofphp\php-cs-fixer\php-cs-fixer',
            ];
        } else {
            // Unix-like systems
            $paths = [
                'vendor/bin/php-cs-fixer',
                'php vendor/friendsofphp/php-cs-fixer/php-cs-fixer',
            ];
        }

        foreach ($paths as $path) {
            if (file_exists($path) || $this->commandExists($path)) {
                return $path;
            }
        }

        // Fallback to composer execution
        return $isWindows
            ? 'php vendor\friendsofphp\php-cs-fixer\php-cs-fixer'
            : 'php vendor/friendsofphp/php-cs-fixer/php-cs-fixer';
    }

    /**
     * Check if a command exists.
     */
    private function commandExists(string $command): bool
    {
        $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        $testCommand = $isWindows ? "where {$command}" : "which {$command}";

        $output = shell_exec($testCommand);

        return !($output === '' || $output === '0' || $output === false || $output === null);
    }

    /**
     * Build PHP-CS-Fixer command with options.
     */
    private function buildCommand(bool $dryRun, array $options): string
    {
        $command = $this->phpcsFixerPath . ' fix';

        // Add config file
        $command .= ' --config=' . $this->configPath;

        // Add dry-run flag
        if ($dryRun) {
            $command .= ' --dry-run';
        }

        // Add default options
        $defaultOptions = [
            '--verbose' => true,
            '--diff' => true,
        ];

        $allOptions = array_merge($defaultOptions, $options);

        // Add options
        foreach ($allOptions as $key => $value) {
            if (is_bool($value) && $value) {
                $command .= ' --' . ltrim($key, '-');
            } elseif (!is_bool($value)) {
                $command .= ' --' . ltrim($key, '-') . '=' . $value;
            }
        }

        return $command;
    }

    /**
     * Parse PHP-CS-Fixer output for violations and statistics.
     */
    private function parseOutput(array $output, array &$result): void
    {
        $violations = [];
        $filesProcessed = 0;
        $filesFixed = 0;

        foreach ($output as $line) {
            // Count processed files
            if (preg_match('/(\d+)\) (.+\.php)/', $line, $matches)) {
                $filesProcessed++;

                // Extract file path
                $filePath = $matches[2];

                // Check if file was fixed (contains diff markers)
                if (str_contains($line, '--- Original') || str_contains($line, '+++ New')) {
                    $filesFixed++;
                }

                // Parse violations from diff output
                if (preg_match('/\s+(\w+)\s+(.+)/', $line, $ruleMatches)) {
                    $violations[] = [
                        'file' => $filePath,
                        'rule' => $ruleMatches[1] ?? 'unknown',
                        'message' => $ruleMatches[2] ?? 'Style violation',
                        'line' => $line,
                    ];
                }
            }

            // Parse summary information
            if (preg_match('/Fixed (\d+) of (\d+) files/', $line, $matches)) {
                $filesFixed = (int) $matches[1];
                $filesProcessed = (int) $matches[2];
            }
        }

        $result['files_processed'] = $filesProcessed;
        $result['files_fixed'] = $filesFixed;
        $result['violations'] = $violations;
        $result['summary'] = [
            'files_processed' => $filesProcessed,
            'files_fixed' => $filesFixed,
            'violations_found' => count($violations),
        ];
    }
}
