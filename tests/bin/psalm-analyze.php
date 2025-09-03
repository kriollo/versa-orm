#!/usr/bin/env php
<?php

declare(strict_types=1);

require_once __DIR__ . '/../../vendor/autoload.php';

use VersaORM\Tests\Quality\PsalmAnalyzer;

/**
 * Psalm Security Analysis CLI Tool.
 */
class PsalmCLI
{
    private PsalmAnalyzer $analyzer;

    public function __construct()
    {
        $this->analyzer = new PsalmAnalyzer();
    }

    public function run(array $argv): int
    {
        $command = $argv[1] ?? 'analyze';

        switch ($command) {
            case 'analyze':
                return $this->runAnalysis($argv);

            case 'security':
                return $this->runSecurityAnalysis($argv);

            case 'types':
                return $this->runTypeAnalysis($argv);

            case 'security-checks':
                return $this->runSecurityChecks($argv);

            case 'metrics':
                return $this->showMetrics();

            case 'baseline':
                return $this->generateBaseline();

            case 'validate-config':
                return $this->validateConfig();

            case 'help':
            default:
                $this->showHelp();

                return 0;
        }
    }

    private function runAnalysis(array $argv): int
    {
        echo "Running Psalm analysis...\n";

        $options = $this->parseOptions($argv);
        $result = $this->analyzer->analyze($options);

        echo 'Analysis completed in ' . number_format($result['execution_time'], 2) . "s\n";
        echo 'Status: ' . ($result['passed'] ? 'PASSED' : 'FAILED') . "\n";
        echo 'Total issues: ' . count($result['issues']) . "\n";
        echo 'Security issues: ' . count($result['security_issues']) . "\n";
        echo 'Type issues: ' . count($result['type_issues']) . "\n";

        if (!empty($result['issues'])) {
            echo "\nIssues found:\n";
            $this->displayIssues($result['issues'], $argv);
        }

        echo "\nDetailed report saved to: " . $result['report_file'] . "\n";

        // Generate HTML report if requested
        if (in_array('--html', $argv, true)) {
            $htmlReport = $this->analyzer->generateHTMLReport($result);
            $htmlFile = str_replace('.json', '.html', $result['report_file']);
            file_put_contents($htmlFile, $htmlReport);
            echo "HTML report saved to: {$htmlFile}\n";
        }

        return $result['passed'] ? 0 : 1;
    }

    private function runSecurityAnalysis(array $argv): int
    {
        echo "Running Psalm security analysis...\n";

        $options = $this->parseOptions($argv);
        $result = $this->analyzer->analyzeSecurity($options);

        echo 'Security analysis completed in ' . number_format($result['execution_time'], 2) . "s\n";
        echo 'Status: ' . ($result['passed'] ? 'PASSED' : 'FAILED') . "\n";
        echo 'Security issues found: ' . count($result['security_issues']) . "\n";

        if (!empty($result['security_issues'])) {
            echo "\nSecurity issues:\n";

            foreach ($result['security_issues'] as $issue) {
                echo "  🔒 {$issue['type']}: {$issue['message']}\n";
                echo "     File: {$issue['file']}:{$issue['line']}\n\n";
            }
        } else {
            echo "\n✅ No security issues found!\n";
        }

        echo "\nDetailed report saved to: " . $result['report_file'] . "\n";

        // Generate HTML report if requested
        if (in_array('--html', $argv, true)) {
            $htmlReport = $this->analyzer->generateHTMLReport($result);
            $htmlFile = str_replace('.json', '.html', $result['report_file']);
            file_put_contents($htmlFile, $htmlReport);
            echo "HTML report saved to: {$htmlFile}\n";
        }

        return $result['passed'] ? 0 : 1;
    }

    private function runTypeAnalysis(array $argv): int
    {
        echo "Running Psalm type analysis...\n";

        $options = $this->parseOptions($argv);
        $result = $this->analyzer->analyzeTypes($options);

        echo 'Type analysis completed in ' . number_format($result['execution_time'], 2) . "s\n";
        echo 'Status: ' . ($result['passed'] ? 'PASSED' : 'FAILED') . "\n";
        echo 'Type issues found: ' . count($result['type_issues']) . "\n";

        if (!empty($result['type_issues'])) {
            echo "\nType issues:\n";
            $this->displayIssues($result['type_issues'], $argv);
        } else {
            echo "\n✅ No type issues found!\n";
        }

        echo "\nDetailed report saved to: " . $result['report_file'] . "\n";

        return $result['passed'] ? 0 : 1;
    }

    private function runSecurityChecks(array $argv): int
    {
        echo "Running comprehensive security checks...\n";

        $checks = $this->analyzer->runSecurityChecks();

        echo "Security checks completed\n";
        echo 'Overall security score: ' . number_format($checks['security_score'], 1) . "/100\n";
        echo 'Total security issues: ' . $checks['total_security_issues'] . "\n\n";

        foreach ($checks['checks'] as $checkName => $checkResult) {
            $status = $checkResult['issues_found'] === 0 ? '✅' : '❌';
            echo
                "{$status} "
                    . ucfirst(str_replace('_', ' ', $checkName))
                    . ': '
                    . $checkResult['issues_found']
                    . " issues\n"
            ;

            if (
                $checkResult['issues_found'] > 0
                && (in_array('--verbose', $argv, true) || in_array('-v', $argv, true))
            ) {
                foreach ($checkResult['details'] as $detail) {
                    echo "    - {$detail['file']}:{$detail['line']} - {$detail['message']}\n";
                }
            }
        }

        return $checks['total_security_issues'] === 0 ? 0 : 1;
    }

    private function showMetrics(): int
    {
        echo "Calculating Psalm security and quality metrics...\n";
        $metrics = $this->analyzer->getSecurityMetrics();
        echo "\nSecurity & Quality Metrics:\n";
        echo '  Execution Time: ' . number_format($metrics['execution_time'], 2) . "s\n";
        echo '  Status: ' . ($metrics['passed'] ? 'PASSED' : 'FAILED') . "\n";
        echo '  Total Issues: ' . $metrics['total_issues'] . "\n";
        echo '  Security Issues: ' . $metrics['security_issues'] . "\n";
        echo '  Type Issues: ' . $metrics['type_issues'] . "\n";
        echo '  Security Score: ' . number_format($metrics['security_score'], 1) . "/100\n";
        echo '  Type Safety Score: ' . number_format($metrics['type_safety_score'], 1) . "/100\n";

        if (!empty($metrics['issue_categories'])) {
            echo "\nIssue Categories:\n";
            arsort($metrics['issue_categories']);

            foreach ($metrics['issue_categories'] as $category => $count) {
                echo "  {$category}: {$count}\n";
            }
        }

        return $metrics['passed'] ? 0 : 1;
    }

    private function generateBaseline(): int
    {
        echo "Generating Psalm baseline...\n";
        $result = $this->analyzer->generateBaseline();

        if ($result['success']) {
            echo 'Baseline generated successfully: ' . $result['baseline_file'] . "\n";

            return 0;
        }
        echo "Failed to generate baseline:\n";
        echo $result['output'] . "\n";

        return 1;
    }

    private function validateConfig(): int
    {
        echo "Validating Psalm configuration...\n";
        $validation = $this->analyzer->validateConfig();

        if ($validation['valid']) {
            echo "Configuration is valid!\n";
            echo '  Error Level: ' . $validation['error_level'] . "\n";
            echo '  PHP Version: ' . $validation['php_version'] . "\n";
            echo '  Taint Analysis: ' . ($validation['taint_analysis'] ? 'Enabled' : 'Disabled') . "\n";
            echo '  Strict Mode: ' . ($validation['strict_mode'] ? 'Enabled' : 'Disabled') . "\n";

            return 0;
        }
        echo "Configuration is invalid!\n";
        echo 'Error: ' . $validation['error'] . "\n";

        return 1;
    }

    private function displayIssues(array $issues, array $argv): void
    {
        $verbose = in_array('--verbose', $argv, true) || in_array('-v', $argv, true);
        $maxIssues = $verbose ? count($issues) : min(10, count($issues));

        for ($i = 0; $i < $maxIssues; $i++) {
            $issue = $issues[$i];
            echo "  - {$issue['type']}: {$issue['message']}\n";
            echo "    File: {$issue['file']}:{$issue['line']}\n";
        }

        if (!$verbose && count($issues) > 10) {
            echo '  ... and ' . (count($issues) - 10) . " more issues (use --verbose to see all)\n";
        }
    }

    private function parseOptions(array $argv): array
    {
        $options = [];
        $counter = count($argv);

        for ($i = 2; $i < $counter; $i++) {
            $arg = $argv[$i];

            if (str_starts_with($arg, '--')) {
                if (str_contains($arg, '=')) {
                    [$key, $value] = explode('=', substr($arg, 2), 2);
                    $options[$key] = $value;
                } else {
                    $key = substr($arg, 2);
                    $options[$key] = true;
                }
            }
        }

        return $options;
    }

    private function showHelp(): void
    {
        echo "Psalm Security Analysis Tool\n\n";
        echo "Usage: php psalm-analyze.php [command] [options]\n\n";
        echo "Commands:\n";
        echo "  analyze           Run full Psalm analysis (default)\n";
        echo "  security          Run security-focused analysis with taint checking\n";
        echo "  types             Run type analysis without security checks\n";
        echo "  security-checks   Run comprehensive security vulnerability checks\n";
        echo "  metrics           Show security and quality metrics\n";
        echo "  baseline          Generate baseline for existing issues\n";
        echo "  validate-config   Validate Psalm configuration\n";
        echo "  help              Show this help message\n\n";
        echo "Options:\n";
        echo "  --html            Generate HTML report\n";
        echo "  --output-format   Set output format (json, text, etc.)\n";
        echo "  --verbose, -v     Show verbose output\n";
        echo "  --taint-analysis  Enable taint analysis\n";
        echo "  --no-cache        Disable cache\n\n";
        echo "Examples:\n";
        echo "  php psalm-analyze.php analyze --html\n";
        echo "  php psalm-analyze.php security --verbose\n";
        echo "  php psalm-analyze.php security-checks\n";
        echo "  php psalm-analyze.php metrics\n";
        echo "  php psalm-analyze.php baseline\n";
    }
}

// Run the CLI tool
$cli = new PsalmCLI();
exit($cli->run($argv));
