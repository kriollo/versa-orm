#!/usr/bin/env php
<?php

declare(strict_types=1);

require_once __DIR__ . '/../../vendor/autoload.php';

use VersaORM\Tests\Quality\PHPStanAnalyzer;

/**
 * PHPStan Analysis CLI Tool.
 */
class PHPStanCLI
{
    private PHPStanAnalyzer $analyzer;

    public function __construct()
    {
        $this->analyzer = new PHPStanAnalyzer();
    }

    public function run(array $argv): int
    {
        $command = $argv[1] ?? 'analyze';

        switch ($command) {
            case 'analyze':
                return $this->runAnalysis($argv);

            case 'baseline':
                return $this->generateBaseline($argv);

            case 'full':
                return $this->runFullAnalysis($argv);

            case 'metrics':
                return $this->showMetrics();

            case 'help':
            default:
                $this->showHelp();

                return 0;
        }
    }

    private function runAnalysis(array $argv): int
    {
        echo "Running PHPStan analysis...\n";

        $options = $this->parseOptions($argv);
        $result = $this->analyzer->analyze($options);

        echo 'Analysis completed in ' . number_format($result['execution_time'], 2) . "s\n";
        echo 'Status: ' . ($result['passed'] ? 'PASSED' : 'FAILED') . "\n";

        if (!empty($result['errors'])) {
            echo "\nErrors found:\n";

            foreach ($result['errors'] as $error) {
                echo "  - {$error}\n";
            }
        }

        if (!empty($result['warnings'])) {
            echo "\nWarnings:\n";

            foreach ($result['warnings'] as $warning) {
                echo "  - {$warning}\n";
            }
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

    private function generateBaseline(array $argv): int
    {
        echo "Generating PHPStan baseline...\n";

        $memoryLimit = $this->getOption($argv, '--memory-limit', '512M');
        $result = $this->analyzer->generateBaseline($memoryLimit);

        if ($result['success']) {
            echo 'Baseline generated successfully: ' . $result['baseline_file'] . "\n";

            return 0;
        }
        echo "Failed to generate baseline:\n";
        echo $result['output'] . "\n";

        return 1;
    }

    private function runFullAnalysis(array $argv): int
    {
        echo "Running full PHPStan analysis (without baseline)...\n";

        $result = $this->analyzer->analyzeWithoutBaseline();

        echo "Analysis completed\n";
        echo 'Return code: ' . $result['return_code'] . "\n";

        if (isset($result['total_errors'])) {
            echo 'Total errors: ' . $result['total_errors'] . "\n";
        }

        if (isset($result['total_file_errors'])) {
            echo 'Files with errors: ' . $result['total_file_errors'] . "\n";
        }

        if (in_array('--verbose', $argv, true) || in_array('-v', $argv, true)) {
            echo "\nFull output:\n";
            echo $result['raw_output'] . "\n";
        }

        return $result['return_code'];
    }

    private function showMetrics(): int
    {
        echo "Calculating PHPStan quality metrics...\n";
        $metrics = $this->analyzer->getQualityMetrics();
        echo "\nQuality Metrics:\n";
        echo '  PHPStan Level: ' . $metrics['phpstan_level'] . "\n";
        echo '  Execution Time: ' . number_format($metrics['execution_time'], 2) . "s\n";
        echo '  Status: ' . ($metrics['passed'] ? 'PASSED' : 'FAILED') . "\n";
        echo '  Total Errors: ' . $metrics['total_errors'] . "\n";
        echo '  Files Analyzed: ' . $metrics['files_analyzed'] . "\n";
        echo '  Quality Score: ' . number_format($metrics['quality_score'], 1) . "/100\n";

        return $metrics['passed'] ? 0 : 1;
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

    private function getOption(array $argv, string $option, string $default = ''): string
    {
        foreach ($argv as $arg) {
            if (str_starts_with($arg, $option . '=')) {
                return substr($arg, strlen($option) + 1);
            }
        }

        return $default;
    }

    private function showHelp(): void
    {
        echo "PHPStan Analysis Tool\n\n";
        echo "Usage: php phpstan-analyze.php [command] [options]\n\n";
        echo "Commands:\n";
        echo "  analyze    Run PHPStan analysis (default)\n";
        echo "  baseline   Generate baseline for existing errors\n";
        echo "  full       Run analysis without baseline\n";
        echo "  metrics    Show quality metrics\n";
        echo "  help       Show this help message\n\n";
        echo "Options:\n";
        echo "  --html                Generate HTML report\n";
        echo "  --memory-limit=512M   Set memory limit\n";
        echo "  --error-format=table  Set error format (table, json, etc.)\n";
        echo "  --verbose, -v         Show verbose output\n\n";
        echo "Examples:\n";
        echo "  php phpstan-analyze.php analyze --html\n";
        echo "  php phpstan-analyze.php baseline --memory-limit=1G\n";
        echo "  php phpstan-analyze.php full --verbose\n";
        echo "  php phpstan-analyze.php metrics\n";
    }
}

// Run the CLI tool
$cli = new PHPStanCLI();
exit($cli->run($argv));
