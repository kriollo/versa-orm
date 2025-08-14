#!/usr/bin/env php
<?php

declare(strict_types=1);

require_once __DIR__ . '/../../vendor/autoload.php';

use VersaORM\Tests\Quality\PHPCSFixerAnalyzer;

/**
 * PHP-CS-Fixer Analysis CLI Tool.
 */
class PHPCSFixerCLI
{
    private PHPCSFixerAnalyzer $analyzer;

    public function __construct()
    {
        $this->analyzer = new PHPCSFixerAnalyzer();
    }

    public function run(array $argv): int
    {
        $command = $argv[1] ?? 'check';

        switch ($command) {
            case 'check':
                return $this->runCheck($argv);

            case 'fix':
                return $this->runFix($argv);

            case 'metrics':
                return $this->showMetrics();

            case 'validate-config':
                return $this->validateConfig();

            case 'install-hook':
                return $this->installPreCommitHook();

            case 'help':
            default:
                $this->showHelp();

                return 0;
        }
    }

    private function runCheck(array $argv): int
    {
        echo "Running PHP-CS-Fixer style check...\n";

        $options = $this->parseOptions($argv);
        $result = $this->analyzer->check($options);

        echo 'Analysis completed in ' . number_format($result['execution_time'], 2) . "s\n";
        echo 'Status: ' . ($result['passed'] ? 'PASSED' : 'FAILED') . "\n";
        echo 'Files processed: ' . $result['files_processed'] . "\n";
        echo 'Violations found: ' . count($result['violations']) . "\n";

        if (!empty($result['violations'])) {
            echo "\nStyle violations detected:\n";
            $fileGroups = [];

            foreach ($result['violations'] as $violation) {
                $file = $violation['file'];

                if (!isset($fileGroups[$file])) {
                    $fileGroups[$file] = [];
                }
                $fileGroups[$file][] = $violation;
            }

            foreach ($fileGroups as $file => $violations) {
                echo "  {$file} (" . count($violations) . " violations)\n";

                if (in_array('--verbose', $argv, true) || in_array('-v', $argv, true)) {
                    foreach ($violations as $violation) {
                        echo '    - ' . $violation['rule'] . ': ' . $violation['message'] . "\n";
                    }
                }
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

    private function runFix(array $argv): int
    {
        echo "Running PHP-CS-Fixer to fix style issues...\n";

        $options = $this->parseOptions($argv);
        $result = $this->analyzer->fix($options);

        echo 'Fix completed in ' . number_format($result['execution_time'], 2) . "s\n";
        echo 'Files processed: ' . $result['files_processed'] . "\n";
        echo 'Files fixed: ' . $result['files_fixed'] . "\n";

        if ($result['files_fixed'] > 0) {
            echo "\nFiles were modified. Please review the changes and commit them.\n";
        } else {
            echo "\nNo files needed fixing. Code style is already compliant.\n";
        }

        echo "\nDetailed report saved to: " . $result['report_file'] . "\n";

        // Generate HTML report if requested
        if (in_array('--html', $argv, true)) {
            $htmlReport = $this->analyzer->generateHTMLReport($result);
            $htmlFile = str_replace('.json', '.html', $result['report_file']);
            file_put_contents($htmlFile, $htmlReport);
            echo "HTML report saved to: {$htmlFile}\n";
        }

        return 0;
    }

    private function showMetrics(): int
    {
        echo "Calculating PHP-CS-Fixer quality metrics...\n";
        $metrics = $this->analyzer->getQualityMetrics();
        echo "\nCode Style Quality Metrics:\n";
        echo '  Execution Time: ' . number_format($metrics['execution_time'], 2) . "s\n";
        echo '  Status: ' . ($metrics['passed'] ? 'PASSED' : 'FAILED') . "\n";
        echo '  Files Processed: ' . $metrics['files_processed'] . "\n";
        echo '  Files with Violations: ' . $metrics['files_with_violations'] . "\n";
        echo '  Total Violations: ' . $metrics['total_violations'] . "\n";
        echo '  Quality Score: ' . number_format($metrics['quality_score'], 1) . "/100\n";

        if (!empty($metrics['violation_types'])) {
            echo "\nViolation Types:\n";
            arsort($metrics['violation_types']);

            foreach ($metrics['violation_types'] as $rule => $count) {
                echo "  {$rule}: {$count}\n";
            }
        }

        return $metrics['passed'] ? 0 : 1;
    }

    private function validateConfig(): int
    {
        echo "Validating PHP-CS-Fixer configuration...\n";
        $validation = $this->analyzer->validateConfig();

        if ($validation['valid']) {
            echo "Configuration is valid!\n";
            echo '  Rules count: ' . $validation['rules_count'] . "\n";
            echo '  Risky rules allowed: ' . ($validation['risky_allowed'] ? 'Yes' : 'No') . "\n";
            echo '  Using cache: ' . ($validation['using_cache'] ? 'Yes' : 'No') . "\n";

            return 0;
        }
        echo "Configuration is invalid!\n";
        echo 'Error: ' . $validation['error'] . "\n";

        return 1;
    }

    private function installPreCommitHook(): int
    {
        echo "Installing PHP-CS-Fixer pre-commit hook...\n";
        $result = $this->analyzer->createPreCommitHook();

        if ($result['success']) {
            echo "Pre-commit hook installed successfully!\n";
            echo 'Hook path: ' . $result['hook_path'] . "\n";
            echo "\nThe hook will automatically check code style before each commit.\n";
            echo "If style violations are found, the commit will be blocked.\n";
            echo "Run 'php tests/bin/php-cs-fixer-analyze.php fix' to fix issues.\n";

            return 0;
        }
        echo "Failed to install pre-commit hook!\n";
        echo 'Error: ' . $result['error'] . "\n";

        return 1;
    }

    private function parseOptions(array $argv): array
    {
        $options = [];
        $counter = count($argv);

        for ($i = 2; $i < $counter; ++$i) {
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
        echo "PHP-CS-Fixer Analysis Tool\n\n";
        echo "Usage: php php-cs-fixer-analyze.php [command] [options]\n\n";
        echo "Commands:\n";
        echo "  check             Check code style without fixing (default)\n";
        echo "  fix               Fix code style issues\n";
        echo "  metrics           Show code style quality metrics\n";
        echo "  validate-config   Validate PHP-CS-Fixer configuration\n";
        echo "  install-hook      Install pre-commit hook for automatic checking\n";
        echo "  help              Show this help message\n\n";
        echo "Options:\n";
        echo "  --html            Generate HTML report\n";
        echo "  --format=FORMAT   Set output format (txt, json, xml, etc.)\n";
        echo "  --verbose, -v     Show verbose output\n";
        echo "  --path=PATH       Analyze specific path\n\n";
        echo "Examples:\n";
        echo "  php php-cs-fixer-analyze.php check --html\n";
        echo "  php php-cs-fixer-analyze.php fix\n";
        echo "  php php-cs-fixer-analyze.php metrics\n";
        echo "  php php-cs-fixer-analyze.php validate-config\n";
        echo "  php php-cs-fixer-analyze.php install-hook\n";
    }
}

// Run the CLI tool
$cli = new PHPCSFixerCLI();
exit($cli->run($argv));
