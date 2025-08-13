<?php

declare(strict_types=1);

namespace VersaORM\Tests\Quality;

use DateTime;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

use function count;
use function is_bool;
use function sprintf;

/**
 * Psalm Analyzer forsecurity and type analysis.
 */
class PsalmAnalyzer
{
    private string $psalmPath;

    private string $configPath;

    private string $reportsDir;

    public function __construct(
        ?string $psalmPath = null,
        string $configPath = 'psalm.xml',
        string $reportsDir = 'tests/reports/psalm',
    ) {
        // Auto-detect Psalm path based on OS
        if ($psalmPath === null) {
            $psalmPath = $this->detectPsalmPath();
        }

        $this->psalmPath  = $psalmPath;
        $this->configPath = $configPath;
        $this->reportsDir = $reportsDir;

        if (!is_dir($this->reportsDir)) {
            mkdir($this->reportsDir, 0755, true);
        }
    }

    /**
     * Run Psalm analysis with security focus.
     */
    public function analyze(array $options = []): array
    {
        $timestamp  = new DateTime();
        $reportFile = $this->reportsDir . '/psalm-' . $timestamp->format('Y-m-d-H-i-s') . '.json';

        $command = $this->buildCommand($options);

        $startTime  = microtime(true);
        $output     = [];
        $returnCode = 0;

        exec($command, $output, $returnCode);

        $executionTime = microtime(true) - $startTime;

        $result = [
            'timestamp'       => $timestamp->format('c'),
            'execution_time'  => $executionTime,
            'return_code'     => $returnCode,
            'command'         => $command,
            'output'          => implode("\n", $output),
            'report_file'     => $reportFile,
            'passed'          => $returnCode === 0,
            'issues'          => [],
            'security_issues' => [],
            'type_issues'     => [],
            'summary'         => [],
        ];

        // Parse output for issues
        $this->parseOutput($output, $result);

        // Save detailed report
        file_put_contents($reportFile, json_encode($result, JSON_PRETTY_PRINT));

        return $result;
    }

    /**
     * Run security-focused analysis.
     */
    public function analyzeSecurity(array $options = []): array
    {
        $securityOptions = array_merge($options, [
            '--taint-analysis' => true,
            '--report'         => $this->reportsDir . '/psalm-security-' . date('Y-m-d-H-i-s') . '.json',
        ]);

        return $this->analyze($securityOptions);
    }

    /**
     * Run type analysis without security checks.
     */
    public function analyzeTypes(array $options = []): array
    {
        $typeOptions = array_merge($options, [
            '--no-taint-analysis' => true,
        ]);

        return $this->analyze($typeOptions);
    }

    /**
     * Get security and quality metrics.
     */
    public function getSecurityMetrics(): array
    {
        $result = $this->analyzeSecurity(['--output-format' => 'json']);

        $metrics = [
            'execution_time'    => $result['execution_time'],
            'passed'            => $result['passed'],
            'total_issues'      => count($result['issues']),
            'security_issues'   => count($result['security_issues']),
            'type_issues'       => count($result['type_issues']),
            'issue_categories'  => [],
            'security_score'    => 0,
            'type_safety_score' => 0,
        ];

        // Categorize issues
        foreach ($result['issues'] as $issue) {
            $category = $issue['type'] ?? 'unknown';

            if (!isset($metrics['issue_categories'][$category])) {
                $metrics['issue_categories'][$category] = 0;
            }
            ++$metrics['issue_categories'][$category];
        }

        // Calculate security score (100 - security_issue_density)
        $totalLines = $this->countLinesOfCode();

        if ($totalLines > 0) {
            $securityIssueDensity      = ($metrics['security_issues'] / $totalLines) * 1000;
            $metrics['security_score'] = max(0, 100 - $securityIssueDensity);

            $typeIssueDensity             = ($metrics['type_issues'] / $totalLines) * 1000;
            $metrics['type_safety_score'] = max(0, 100 - $typeIssueDensity);
        }

        return $metrics;
    }

    /**
     * Generate baseline for existing issues.
     */
    public function generateBaseline(): array
    {
        $command = sprintf(
            '%s --set-baseline=%s',
            $this->psalmPath,
            'psalm-baseline.xml',
        );

        $output     = [];
        $returnCode = 0;

        exec($command, $output, $returnCode);

        return [
            'success'       => $returnCode === 0,
            'output'        => implode("\n", $output),
            'baseline_file' => 'psalm-baseline.xml',
        ];
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

        // Try to validate the XML configuration
        libxml_use_internal_errors(true);
        $xml    = simplexml_load_file($this->configPath);
        $errors = libxml_get_errors();

        if ($xml === false || !empty($errors)) {
            $errorMessages = [];

            foreach ($errors as $error) {
                $errorMessages[] = trim($error->message);
            }

            return [
                'valid' => false,
                'error' => 'Invalid XML configuration: ' . implode(', ', $errorMessages),
            ];
        }

        return [
            'valid'          => true,
            'error_level'    => (string) $xml['errorLevel'] ?? 'unknown',
            'php_version'    => (string) $xml['phpVersion'] ?? 'unknown',
            'taint_analysis' => isset($xml->issueHandlers->TaintedInput),
            'strict_mode'    => isset($xml['strictBinaryOperands']) && (string) $xml['strictBinaryOperands'] === 'true',
        ];
    }

    /**
     * Run specific security checks.
     */
    public function runSecurityChecks(): array
    {
        $checks = [
            'sql_injection'       => $this->checkSQLInjection(),
            'xss_vulnerabilities' => $this->checkXSSVulnerabilities(),
            'file_inclusion'      => $this->checkFileInclusion(),
            'command_injection'   => $this->checkCommandInjection(),
            'tainted_data'        => $this->checkTaintedData(),
        ];

        $totalIssues  = array_sum(array_column($checks, 'issues_found'));
        $overallScore = $totalIssues === 0 ? 100 : max(0, 100 - ($totalIssues * 10));

        return [
            'checks'                => $checks,
            'total_security_issues' => $totalIssues,
            'security_score'        => $overallScore,
            'timestamp'             => date('c'),
        ];
    }

    /**
     * Generate HTML report from analysis results.
     */
    public function generateHTMLReport(array $analysisResult): string
    {
        $html = '<!DOCTYPE html>
<html>
<head>
    <title>Psalm Security Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .passed { color: green; }
        .failed { color: red; }
        .section { margin: 20px 0; }
        .issue { background: #ffe6e6; padding: 10px; margin: 5px 0; border-radius: 3px; }
        .security-issue { background: #ffcccc; border-left: 4px solid #cc0000; }
        .type-issue { background: #fff3cd; border-left: 4px solid #cc6600; }
        .file-path { font-weight: bold; color: #0066cc; }
        .issue-type { color: #cc6600; font-family: monospace; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .stats { display: flex; gap: 20px; }
        .stat { background: #e9ecef; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-number { font-size: 24px; font-weight: bold; color: #495057; }
        .stat-label { color: #6c757d; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Psalm Security Analysis Report</h1>
        <p><strong>Timestamp:</strong> ' . $analysisResult['timestamp'] . '</p>
        <p><strong>Execution Time:</strong> ' . number_format($analysisResult['execution_time'], 2) . 's</p>
        <p><strong>Status:</strong> <span class="' . ($analysisResult['passed'] ? 'passed' : 'failed') . '">' .
            ($analysisResult['passed'] ? 'PASSED' : 'FAILED') . '</span></p>
    </div>

    <div class="stats">
        <div class="stat">
            <div class="stat-number">' . count($analysisResult['issues']) . '</div>
            <div class="stat-label">Total Issues</div>
        </div>
        <div class="stat">
            <div class="stat-number">' . count($analysisResult['security_issues']) . '</div>
            <div class="stat-label">Security Issues</div>
        </div>
        <div class="stat">
            <div class="stat-number">' . count($analysisResult['type_issues']) . '</div>
            <div class="stat-label">Type Issues</div>
        </div>
    </div>';

        if (!empty($analysisResult['security_issues'])) {
            $html .= '<div class="section">
                <h2>Security Issues</h2>';

            foreach ($analysisResult['security_issues'] as $issue) {
                $html .= '<div class="issue security-issue">
                    <div class="file-path">' . htmlspecialchars($issue['file']) . ':' . $issue['line'] . '</div>
                    <div><span class="issue-type">' . htmlspecialchars($issue['type']) . '</span>: ' .
                    htmlspecialchars($issue['message']) . '</div>
                </div>';
            }
            $html .= '</div>';
        }

        if (!empty($analysisResult['type_issues'])) {
            $html .= '<div class="section">
                <h2>Type Issues</h2>';

            foreach ($analysisResult['type_issues'] as $issue) {
                $html .= '<div class="issue type-issue">
                    <div class="file-path">' . htmlspecialchars($issue['file']) . ':' . $issue['line'] . '</div>
                    <div><span class="issue-type">' . htmlspecialchars($issue['type']) . '</span>: ' .
                    htmlspecialchars($issue['message']) . '</div>
                </div>';
            }
            $html .= '</div>';
        }

        $html .= '<div class="section">
            <h2>Full Output</h2>
            <pre>' . htmlspecialchars($analysisResult['output']) . '</pre>
        </div>

        <div class="section">
            <h2>Command Executed</h2>
            <pre>' . htmlspecialchars($analysisResult['command']) . '</pre>
        </div>
    </body>
</html>';

        return $html;
    }

    /**
     * Detect Psalm executable path based on OS.
     */
    private function detectPsalmPath(): string
    {
        $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';

        if ($isWindows) {
            // Try different Windows paths
            $paths = [
                'vendor\bin\psalm.bat',
                'vendor\bin\psalm',
                'php vendor\vimeo\psalm\psalm',
            ];
        } else {
            // Unix-like systems
            $paths = [
                'vendor/bin/psalm',
                'php vendor/vimeo/psalm/psalm',
            ];
        }

        foreach ($paths as $path) {
            if (file_exists($path) || $this->commandExists($path)) {
                return $path;
            }
        }

        // Fallback to composer execution
        return $isWindows ? 'php vendor\vimeo\psalm\psalm' : 'php vendor/vimeo/psalm/psalm';
    }

    /**
     * Check if a command exists.
     */
    private function commandExists(string $command): bool
    {
        $isWindows   = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        $testCommand = $isWindows ? "where {$command}" : "which {$command}";

        $output = shell_exec($testCommand);

        return !empty($output);
    }

    /**
     * Build Psalm command with options.
     */
    private function buildCommand(array $options): string
    {
        $command = $this->psalmPath;

        // Add config file
        $command .= ' --config=' . $this->configPath;

        // Add default options
        $defaultOptions = [
            '--show-info'   => false,
            '--no-progress' => true,
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
     * Parse Psalm output for issues.
     */
    private function parseOutput(array $output, array &$result): void
    {
        $issues         = [];
        $securityIssues = [];
        $typeIssues     = [];

        foreach ($output as $line) {
            // Parse JSON output if available
            if (strpos($line, '{') === 0) {
                $decoded = json_decode($line, true);

                if ($decoded !== null && isset($decoded['type'])) {
                    $issue = [
                        'type'     => $decoded['type'],
                        'message'  => $decoded['message'] ?? '',
                        'file'     => $decoded['file_name'] ?? '',
                        'line'     => $decoded['line_from'] ?? 0,
                        'severity' => $decoded['severity'] ?? 'error',
                    ];

                    $issues[] = $issue;

                    // Categorize security issues
                    if (strpos($issue['type'], 'Tainted') !== false) {
                        $securityIssues[] = $issue;
                    } else {
                        $typeIssues[] = $issue;
                    }
                }
            }

            // Parse text output for summary
            if (preg_match('/(\d+) errors?, (\d+) warnings?/', $line, $matches)) {
                $result['summary']['errors']   = (int) $matches[1];
                $result['summary']['warnings'] = (int) $matches[2];
            }
        }

        $result['issues']          = $issues;
        $result['security_issues'] = $securityIssues;
        $result['type_issues']     = $typeIssues;
    }

    /**
     * Count lines of code in the project.
     */
    private function countLinesOfCode(): int
    {
        $totalLines = 0;
        $iterator   = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator('src'),
        );

        foreach ($iterator as $file) {
            if ($file->getExtension() === 'php') {
                $totalLines += count(file($file->getPathname()));
            }
        }

        return $totalLines;
    }

    /**
     * Check for SQL injection vulnerabilities.
     */
    private function checkSQLInjection(): array
    {
        $result = $this->analyze(['--taint-analysis' => true, '--output-format' => 'json']);

        $sqlInjectionIssues = array_filter($result['issues'], static function ($issue) {
            return strpos($issue['type'], 'TaintedSql') !== false;
        });

        return [
            'issues_found' => count($sqlInjectionIssues),
            'details'      => $sqlInjectionIssues,
            'description'  => 'SQL injection vulnerability detection',
        ];
    }

    /**
     * Check for XSS vulnerabilities.
     */
    private function checkXSSVulnerabilities(): array
    {
        $result = $this->analyze(['--taint-analysis' => true, '--output-format' => 'json']);

        $xssIssues = array_filter($result['issues'], static function ($issue) {
            return strpos($issue['type'], 'TaintedHtml') !== false;
        });

        return [
            'issues_found' => count($xssIssues),
            'details'      => $xssIssues,
            'description'  => 'Cross-site scripting (XSS) vulnerability detection',
        ];
    }

    /**
     * Check for file inclusion vulnerabilities.
     */
    private function checkFileInclusion(): array
    {
        $result = $this->analyze(['--taint-analysis' => true, '--output-format' => 'json']);

        $fileIssues = array_filter($result['issues'], static function ($issue) {
            return strpos($issue['type'], 'TaintedFile') !== false;
        });

        return [
            'issues_found' => count($fileIssues),
            'details'      => $fileIssues,
            'description'  => 'File inclusion vulnerability detection',
        ];
    }

    /**
     * Check for command injection vulnerabilities.
     */
    private function checkCommandInjection(): array
    {
        $result = $this->analyze(['--taint-analysis' => true, '--output-format' => 'json']);

        $commandIssues = array_filter($result['issues'], static function ($issue) {
            return strpos($issue['type'], 'TaintedShell') !== false;
        });

        return [
            'issues_found' => count($commandIssues),
            'details'      => $commandIssues,
            'description'  => 'Command injection vulnerability detection',
        ];
    }

    /**
     * Check for general tainted data issues.
     */
    private function checkTaintedData(): array
    {
        $result = $this->analyze(['--taint-analysis' => true, '--output-format' => 'json']);

        $taintedIssues = array_filter($result['issues'], static function ($issue) {
            return strpos($issue['type'], 'TaintedInput') !== false;
        });

        return [
            'issues_found' => count($taintedIssues),
            'details'      => $taintedIssues,
            'description'  => 'General tainted data flow detection',
        ];
    }
}
