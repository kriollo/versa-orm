<?php

declare(strict_types=1);

/**
 * QA Tools Integration Script
 *
 * Executes all QA tools in the correct order to avoid conflicts:
 * 1. Rector (code transformations)
 * 2. PHP-CS-Fixer (code style)
 * 3. PHPStan (static analysis)
 * 4. Psalm (security & complementary analysis)
 * 5. PHPUnit (tests)
 */
class QAIntegration
{
    private array $tools = [];

    private bool $fix = false;

    private bool $verbose = false;

    private array $onlyTools = [];

    private array $skipTools = [];

    public function __construct(array $args = [])
    {
        $this->initializeTools();
        $this->parseArgs($args);
    }

    private function initializeTools(): void
    {
        $this->tools = [
            'rector' => [
                'name' => 'Rector',
                'command' => $this->getToolCommand('rector', 'process --dry-run'),
                'fix_command' => $this->getToolCommand('rector', 'process'),
                'description' => 'Code modernization and refactoring',
            ],
            'pint' => [
                'name' => 'Pint',
                'command' => $this->getToolCommand('pint', '--test'),
                'fix_command' => $this->getToolCommand('pint', ''),
                'description' => 'Laravel Pint code style (PSR-12/Laravel)',
            ],
            'php-cs-fixer' => [
                'name' => 'PHP-CS-Fixer',
                'command' => $this->getToolCommand('php-cs-fixer', 'fix --dry-run --diff'),
                'fix_command' => $this->getToolCommand('php-cs-fixer', 'fix'),
                'description' => 'Code style formatting',
            ],
            'phpstan' => [
                'name' => 'PHPStan',
                'command' => $this->getToolCommand('phpstan', 'analyse --memory-limit=512M'),
                'fix_command' => null,
                'description' => 'Static analysis and type checking',
            ],
            'psalm' => [
                'name' => 'Psalm',
                'command' => $this->getToolCommand('psalm', '--show-info=false'),
                'fix_command' => null,
                'description' => 'Security analysis and complementary checks',
            ],
        ];
    }

    private function getToolCommand(string $tool, string $args): string
    {
        $isWindows = PHP_OS_FAMILY === 'Windows';
        $extension = $isWindows ? '.bat' : '';
        $separator = $isWindows ? '\\' : '/';

        return "vendor{$separator}bin{$separator}{$tool}{$extension} {$args}";
    }

    private function parseArgs(array $args): void
    {
        foreach ($args as $arg) {
            switch ($arg) {
                case '--fix':
                    $this->fix = true;
                    break;
                case '--verbose':
                case '-v':
                    $this->verbose = true;
                    break;
                default:
                    if (str_starts_with($arg, '--only=')) {
                        $this->onlyTools = explode(',', substr($arg, 7));
                    } elseif (str_starts_with($arg, '--skip=')) {
                        $this->skipTools = explode(',', substr($arg, 7));
                    }
                    break;
            }
        }
    }

    public function run(): int
    {
        $this->printHeader();

        $results = [];
        $overallSuccess = true;

        foreach ($this->tools as $toolKey => $tool) {
            if (! empty($this->onlyTools) && ! in_array($toolKey, $this->onlyTools)) {
                continue;
            }

            if (in_array($toolKey, $this->skipTools)) {
                continue;
            }

            $result = $this->runTool($toolKey, $tool);
            $results[$toolKey] = $result;

            if (! $result['success']) {
                $overallSuccess = false;

                // Stop on first failure unless fixing
                if (! $this->fix) {
                    break;
                }
            }
        }

        $this->printSummary($results, $overallSuccess);

        return $overallSuccess ? 0 : 1;
    }

    private function runTool(string $toolKey, array $tool): array
    {
        $this->printToolHeader($tool['name'], $tool['description']);

        $command = $this->fix && $tool['fix_command']
            ? $tool['fix_command']
            : $tool['command'];

        if ($this->verbose) {
            echo "  Command: {$command}\n";
        }

        $startTime = microtime(true);

        // Execute command
        $output = [];
        $returnCode = 0;
        exec($command . ' 2>&1', $output, $returnCode);

        $duration = microtime(true) - $startTime;
        $success = $returnCode === 0;

        // Print output
        if (! empty($output)) {
            foreach ($output as $line) {
                echo "  {$line}\n";
            }
        }

        $this->printToolResult($tool['name'], $success, $duration);

        return [
            'success' => $success,
            'duration' => $duration,
            'output' => $output,
            'return_code' => $returnCode,
        ];
    }

    private function printHeader(): void
    {
        echo "\n";
        echo "╔══════════════════════════════════════════════════════════════╗\n";
        echo "║                    QA Tools Integration                     ║\n";
        echo "╠══════════════════════════════════════════════════════════════╣\n";
        echo "║ Integrated execution of Rector, PHP-CS-Fixer, PHPStan,     ║\n";
        echo "║ Psalm in the correct order to avoid conflicts               ║\n";
        echo "╚══════════════════════════════════════════════════════════════╝\n";
        echo "\n";

        if ($this->fix) {
            echo "🔧 FIX MODE: Tools will make changes to your code\n";
        } else {
            echo "🔍 CHECK MODE: Tools will only report issues (use --fix to apply changes)\n";
        }
        echo "\n";
    }

    private function printToolHeader(string $name, string $description): void
    {
        echo "┌─ {$name} " . str_repeat('─', 60 - strlen($name)) . "┐\n";
        echo "│ {$description}" . str_repeat(' ', 58 - strlen($description)) . "│\n";
        echo '└' . str_repeat('─', 60) . "┘\n";
    }

    private function printToolResult(string $name, bool $success, float $duration): void
    {
        $status = $success ? '✅ PASSED' : '❌ FAILED';
        $time = number_format($duration, 2) . 's';

        echo "\n{$status} - {$name} ({$time})\n";
        echo str_repeat('─', 60) . "\n\n";
    }

    private function printSummary(array $results, bool $overallSuccess): void
    {
        echo "╔══════════════════════════════════════════════════════════════╗\n";
        echo "║                         SUMMARY                             ║\n";
        echo "╚══════════════════════════════════════════════════════════════╝\n";

        $totalTime = 0;
        foreach ($results as $toolKey => $result) {
            $tool = $this->tools[$toolKey];
            $status = $result['success'] ? '✅' : '❌';
            $time = number_format($result['duration'], 2) . 's';
            $totalTime += $result['duration'];

            echo "{$status} {$tool['name']}" . str_repeat(' ', 20 - strlen($tool['name'])) . "{$time}\n";
        }

        echo str_repeat('─', 60) . "\n";
        echo 'Total time: ' . number_format($totalTime, 2) . "s\n";

        if ($overallSuccess) {
            echo "\n🎉 All QA checks passed!\n";
        } else {
            echo "\n💥 Some QA checks failed. Review the output above.\n";
            if (! $this->fix) {
                echo "💡 Use --fix to automatically fix issues where possible.\n";
            }
        }
        echo "\n";
    }

    public static function showHelp(): void
    {
        echo "QA Tools Integration Script\n\n";
        echo "Usage: php qa-integration.php [options]\n\n";
        echo "Options:\n";
        echo "  --fix              Apply fixes automatically (where possible)\n";
        echo "  --verbose, -v      Show detailed output\n";
        echo "  --only=tool1,tool2 Run only specified tools\n";
        echo "  --skip=tool1,tool2 Skip specified tools\n";
        echo "  --help, -h         Show this help message\n\n";
        echo "Available tools: rector, pint, php-cs-fixer, phpstan, psalm\n\n";
        echo "Examples:\n";
        echo "  php qa-integration.php                    # Check all tools\n";
        echo "  php qa-integration.php --fix              # Fix all issues\n";
        echo "  php qa-integration.php --only=rector      # Run only Rector\n";
        echo "  php qa-integration.php --skip=psalm       # Skip Psalm\n";
        echo "\n";
    }
}

// Main execution
if (php_sapi_name() === 'cli') {
    $args = array_slice($argv, 1);

    if (in_array('--help', $args) || in_array('-h', $args)) {
        QAIntegration::showHelp();
        exit(0);
    }

    $qa = new QAIntegration($args);
    exit($qa->run());
}
