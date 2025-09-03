<?php

declare(strict_types=1);

/**
 * QA Master Runner for VersaORM.
 *
 * This script runs all quality assurance tools in the correct order
 * to avoid conflicts between them. It ensures that:
 *
 * 1. Rector runs first to modernize code
 * 2. PHP-CS-Fixer runs second to format code
 * 3. PHPStan runs third to analyze types
 * 4. Psalm runs fourth for additional analysis
 * 5. Tests run last to verify everything works
 *
 * Usage:
 *   php tests/bin/qa-master.php [options]
 *
 * Options:
 *   --skip-rector       Skip Rector refactoring
 *   --skip-cs-fixer     Skip PHP-CS-Fixer formatting
 *   --skip-phpstan      Skip PHPStan analysis
 *   --skip-psalm        Skip Psalm analysis
 *   --skip-tests        Skip running tests
 *   --dry-run           Show what would be done without executing
 *   --path=PATH         Analyze specific path only (src, tests, example)
 *   --output=FILE       Save combined report to file
 *   --help              Show this help message
 */

require_once dirname(__DIR__, 2) . '/vendor/autoload.php';

use VersaORM\Tests\Logging\TestLogger;

// Parse command line arguments
$options = parseArguments($argv);

if (isset($options['help'])) {
    showHelp();
    exit(0);
}

// Initialize logger
$logger = new TestLogger();
$logger->info('Starting QA Master Runner');

$results = [];
$overallSuccess = true;

try {
    echo "🚀 VersaORM Quality Assurance Master Runner\n";
    echo "==========================================\n\n";

    if (isset($options['dry-run'])) {
        echo "🔍 DRY RUN MODE - No changes will be made\n\n";
    }

    // Step 1: Rector (Code Modernization)
    if (!isset($options['skip-rector'])) {
        echo "📝 Step 1: Running Rector (Code Modernization)\n";
        echo "--------------------------------------------\n";

        $rectorResult = runRector($options, $logger);
        $results['rector'] = $rectorResult;

        if (!$rectorResult['success']) {
            $overallSuccess = false;
            echo "❌ Rector failed. Continuing with other tools...\n\n";
        } else {
            echo "✅ Rector completed successfully\n\n";
        }
    } else {
        echo "⏭️  Skipping Rector\n\n";
    }

    // Step 2: PHP-CS-Fixer (Code Formatting)
    if (!isset($options['skip-cs-fixer'])) {
        echo "🎨 Step 2: Running PHP-CS-Fixer (Code Formatting)\n";
        echo "------------------------------------------------\n";

        $csFixerResult = runPhpCsFixer($options, $logger);
        $results['php-cs-fixer'] = $csFixerResult;

        if (!$csFixerResult['success']) {
            $overallSuccess = false;
            echo "❌ PHP-CS-Fixer failed. Continuing with other tools...\n\n";
        } else {
            echo "✅ PHP-CS-Fixer completed successfully\n\n";
        }
    } else {
        echo "⏭️  Skipping PHP-CS-Fixer\n\n";
    }

    // Step 3: PHPStan (Static Analysis)
    if (!isset($options['skip-phpstan'])) {
        echo "🔍 Step 3: Running PHPStan (Static Analysis)\n";
        echo "-------------------------------------------\n";

        $phpstanResult = runPhpStan($options, $logger);
        $results['phpstan'] = $phpstanResult;

        if (!$phpstanResult['success']) {
            $overallSuccess = false;
            echo "❌ PHPStan found issues. Check the report for details.\n\n";
        } else {
            echo "✅ PHPStan analysis passed\n\n";
        }
    } else {
        echo "⏭️  Skipping PHPStan\n\n";
    }

    // Step 4: Psalm (Additional Analysis)
    if (!isset($options['skip-psalm'])) {
        echo "🔮 Step 4: Running Psalm (Additional Analysis)\n";
        echo "---------------------------------------------\n";

        $psalmResult = runPsalm($options, $logger);
        $results['psalm'] = $psalmResult;

        if (!$psalmResult['success']) {
            $overallSuccess = false;
            echo "❌ Psalm found issues. Check the report for details.\n\n";
        } else {
            echo "✅ Psalm analysis passed\n\n";
        }
    } else {
        echo "⏭️  Skipping Psalm\n\n";
    }

    // Step 5: Tests (Verification)
    if (!isset($options['skip-tests'])) {
        echo "🧪 Step 5: Running Tests (Verification)\n";
        echo "--------------------------------------\n";

        $testsResult = runTests($options, $logger);
        $results['tests'] = $testsResult;

        if (!$testsResult['success']) {
            $overallSuccess = false;
            echo "❌ Tests failed. Check the output for details.\n\n";
        } else {
            echo "✅ All tests passed\n\n";
        }
    } else {
        echo "⏭️  Skipping Tests\n\n";
    }

    // Generate summary report
    generateSummaryReport($results, $overallSuccess, $options);

    $logger->info('QA Master Runner completed');

    exit($overallSuccess ? 0 : 1);
} catch (Exception $e) {
    $logger->error('QA Master Runner failed: ' . $e->getMessage());
    echo '💥 FATAL ERROR: ' . $e->getMessage() . "\n";
    exit(1);
}

/**
 * Run Rector.
 */
function runRector(array $options, TestLogger $logger): array
{
    $command = buildCommand('rector', $options);

    if (isset($options['dry-run'])) {
        echo "Would run: {$command}\n";

        return ['success' => true, 'output' => 'DRY RUN', 'command' => $command];
    }

    $output = [];
    $returnCode = 0;

    exec($command, $output, $returnCode);

    $outputText = implode("\n", $output);

    return [
        'success' => $returnCode === 0,
        'output' => $outputText,
        'command' => $command,
        'return_code' => $returnCode,
    ];
}

/**
 * Run PHP-CS-Fixer.
 */
function runPhpCsFixer(array $options, TestLogger $logger): array
{
    $projectRoot = dirname(__DIR__, 2);
    $command = "{$projectRoot}/vendor/bin/php-cs-fixer";

    if (PHP_OS_FAMILY === 'Windows') {
        $command .= '.bat';
    }

    $command .= ' fix --config=.php-cs-fixer.dist.php';

    if (isset($options['dry-run'])) {
        $command .= ' --dry-run --diff';
        echo "Would run: {$command}\n";

        return ['success' => true, 'output' => 'DRY RUN', 'command' => $command];
    }

    $output = [];
    $returnCode = 0;

    exec($command, $output, $returnCode);

    $outputText = implode("\n", $output);

    return [
        'success' => $returnCode === 0,
        'output' => $outputText,
        'command' => $command,
        'return_code' => $returnCode,
    ];
}

/**
 * Run PHPStan.
 */
function runPhpStan(array $options, TestLogger $logger): array
{
    $command = 'php tests/bin/phpstan-analyze.php';

    if (isset($options['dry-run'])) {
        echo "Would run: {$command}\n";

        return ['success' => true, 'output' => 'DRY RUN', 'command' => $command];
    }

    $output = [];
    $returnCode = 0;

    exec($command, $output, $returnCode);

    $outputText = implode("\n", $output);

    return [
        'success' => $returnCode === 0,
        'output' => $outputText,
        'command' => $command,
        'return_code' => $returnCode,
    ];
}

/**
 * Run Psalm.
 */
function runPsalm(array $options, TestLogger $logger): array
{
    $command = 'php tests/bin/psalm-analyze.php';

    if (isset($options['dry-run'])) {
        echo "Would run: {$command}\n";

        return ['success' => true, 'output' => 'DRY RUN', 'command' => $command];
    }

    $output = [];
    $returnCode = 0;

    exec($command, $output, $returnCode);

    $outputText = implode("\n", $output);

    return [
        'success' => $returnCode === 0,
        'output' => $outputText,
        'command' => $command,
        'return_code' => $returnCode,
    ];
}

/**
 * Run Tests.
 */
function runTests(array $options, TestLogger $logger): array
{
    $projectRoot = dirname(__DIR__, 2);
    $command = 'php vendor/bin/phpunit --configuration=phpunit-sqlite-test.xml --no-coverage';

    if (isset($options['dry-run'])) {
        echo "Would run: {$command}\n";

        return ['success' => true, 'output' => 'DRY RUN', 'command' => $command];
    }

    // Set environment variable to disable Xdebug for faster execution
    putenv('XDEBUG_MODE=off');

    $output = [];
    $returnCode = 0;

    exec($command, $output, $returnCode);

    $outputText = implode("\n", $output);

    return [
        'success' => $returnCode === 0,
        'output' => $outputText,
        'command' => $command,
        'return_code' => $returnCode,
    ];
}

/**
 * Build command for tools that support path parameter.
 */
function buildCommand(string $tool, array $options): string
{
    $projectRoot = dirname(__DIR__, 2);

    switch ($tool) {
        case 'rector':
            $command = 'php tests/bin/rector-analyze.php';

            if (isset($options['dry-run'])) {
                $command .= ' --dry-run';
            }

            if (isset($options['path'])) {
                $command .= ' --path=' . $options['path'];
            }

            return $command;

        default:
            throw new Exception("Unknown tool: {$tool}");
    }
}

/**
 * Generate summary report.
 */
function generateSummaryReport(array $results, bool $overallSuccess, array $options): void
{
    echo "📊 Summary Report\n";
    echo "================\n\n";

    $totalTools = count($results);
    $successfulTools = count(array_filter($results, fn($r) => $r['success']));

    echo "Tools executed: {$totalTools}\n";
    echo "Successful: {$successfulTools}\n";
    echo 'Failed: ' . ($totalTools - $successfulTools) . "\n\n";

    echo "Individual Results:\n";
    foreach ($results as $tool => $result) {
        $status = $result['success'] ? '✅ PASS' : '❌ FAIL';
        echo "  {$tool}: {$status}\n";
    }

    echo "\nOverall Status: " . ($overallSuccess ? '✅ SUCCESS' : '❌ FAILED') . "\n\n";

    if (!$overallSuccess) {
        echo "💡 Recommendations:\n";
        echo "  1. Check individual tool outputs above for specific issues\n";
        echo "  2. Fix issues in the order they were run (Rector → PHP-CS-Fixer → PHPStan → Psalm → Tests)\n";
        echo "  3. Re-run this script after making fixes\n";
        echo "  4. Use --dry-run to preview changes before applying them\n\n";
    }

    // Save detailed report if requested
    if (isset($options['output'])) {
        $report = [
            'timestamp' => date('Y-m-d H:i:s'),
            'overall_success' => $overallSuccess,
            'tools_executed' => $totalTools,
            'successful_tools' => $successfulTools,
            'results' => $results,
        ];

        file_put_contents($options['output'], json_encode($report, JSON_PRETTY_PRINT));
        echo "📄 Detailed report saved to: {$options['output']}\n";
    }
}

/**
 * Parse command line arguments.
 */
function parseArguments(array $argv): array
{
    $options = [];

    for ($i = 1; $i < count($argv); $i++) {
        $arg = $argv[$i];

        if (str_starts_with($arg, '--')) {
            if (str_contains($arg, '=')) {
                [$key, $value] = explode('=', substr($arg, 2), 2);
                $options[$key] = $value;
            } else {
                $options[substr($arg, 2)] = true;
            }
        }
    }

    return $options;
}

/**
 * Show help message.
 */
function showHelp(): void
{
    echo "QA Master Runner for VersaORM\n";
    echo "=============================\n\n";
    echo "This script runs all quality assurance tools in the correct order to avoid conflicts.\n\n";
    echo "Usage: php tests/bin/qa-master.php [options]\n\n";
    echo "Options:\n";
    echo "  --skip-rector       Skip Rector refactoring\n";
    echo "  --skip-cs-fixer     Skip PHP-CS-Fixer formatting\n";
    echo "  --skip-phpstan      Skip PHPStan analysis\n";
    echo "  --skip-psalm        Skip Psalm analysis\n";
    echo "  --skip-tests        Skip running tests\n";
    echo "  --dry-run           Show what would be done without executing\n";
    echo "  --path=PATH         Analyze specific path only (src, tests, example)\n";
    echo "  --output=FILE       Save combined report to file\n";
    echo "  --help              Show this help message\n\n";
    echo "Execution Order:\n";
    echo "  1. Rector (modernizes code)\n";
    echo "  2. PHP-CS-Fixer (formats code)\n";
    echo "  3. PHPStan (analyzes types)\n";
    echo "  4. Psalm (additional analysis)\n";
    echo "  5. Tests (verifies functionality)\n\n";
    echo "Examples:\n";
    echo "  php tests/bin/qa-master.php\n";
    echo "  php tests/bin/qa-master.php --dry-run\n";
    echo "  php tests/bin/qa-master.php --skip-tests --path=src\n";
    echo "  php tests/bin/qa-master.php --output=qa-report.json\n";
}
