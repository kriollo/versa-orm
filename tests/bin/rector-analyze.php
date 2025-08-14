<?php

declare(strict_types=1);

/**
 * Rector Analysis Runner for VersaORM.
 *
 * This script runs Rector code refactoring analysis and applies transformations
 * to modernize and improve the codebase according to best practices.
 *
 * Usag
 *   php tests/bin/rector-analyze.php [options]
 *
 * Options:
 *   --dry-run           Show what would be changed without applying changes
 *   --path=PATH         Analyze specific path only (src, tests, example)
 *   --clear-cache       Clear Rector cache before running
 *   --output=FILE       Save analysis output to file
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
$logger->info('Starting Rector analysis');

try {
    // Clear cache if requested
    if (isset($options['clear-cache'])) {
        clearRectorCache();
        echo "Rector cache cleared.\n";
    }

    // Determine what to analyze
    if (isset($options['dry-run'])) {
        runDryRun($options, $logger);
    } else {
        runRectorAnalysis($options, $logger);
    }

    $logger->info('Rector analysis completed successfully');
} catch (Exception $e) {
    $logger->error('Rector analysis failed: ' . $e->getMessage());
    echo 'ERROR: ' . $e->getMessage() . "\n";
    exit(1);
}

/**
 * Run Rector in dry-run mode.
 */
function runDryRun(array $options, TestLogger $logger): void
{
    $logger->info('Running Rector dry-run analysis');

    $command = buildRectorCommand($options, true);

    echo "Rector Dry-Run Analysis\n";
    echo "======================\n\n";
    echo "Command: {$command}\n\n";

    $output = [];
    $returnCode = 0;

    exec($command, $output, $returnCode);

    $outputText = implode("\n", $output);

    if ($returnCode === 0) {
        echo "✅ No changes needed - code is already optimized!\n";
    } else {
        echo "📋 Rector found improvements that can be made:\n\n";
        echo $outputText . "\n";

        // Parse and categorize changes
        $changes = parseRectorOutput($outputText);
        displayChangeSummary($changes);
    }

    // Save output if requested
    if (isset($options['output'])) {
        file_put_contents($options['output'], $outputText);
        echo "\nAnalysis output saved to: {$options['output']}\n";
    }
}

/**
 * Run Rector analysis and apply changes.
 */
function runRectorAnalysis(array $options, TestLogger $logger): void
{
    $logger->info('Running Rector analysis with changes');

    $command = buildRectorCommand($options, false);

    echo "Rector Code Refactoring\n";
    echo "======================\n\n";
    echo "Command: {$command}\n\n";

    $output = [];
    $returnCode = 0;

    exec($command, $output, $returnCode);

    $outputText = implode("\n", $output);

    if ($returnCode === 0) {
        echo "✅ Rector completed successfully!\n";

        // Parse and show what was changed
        $changes = parseRectorOutput($outputText);

        if ($changes !== []) {
            echo "\n📝 Changes applied:\n";
            displayChangeSummary($changes);

            echo "\n⚠️  Important: Please review the changes and run tests to ensure everything works correctly.\n";
            echo "💡 Recommended next steps:\n";
            echo "   1. Review changed files: git diff\n";
            echo "   2. Run tests: php vendor/bin/phpunit\n";
            echo "   3. Run static analysis: php tests/bin/phpstan-analyze.php\n";
            echo "   4. Check code style: php tests/bin/php-cs-fixer-analyze.php\n";
        } else {
            echo "No changes were needed - code is already optimized!\n";
        }
    } else {
        echo "❌ Rector encountered issues:\n";
        echo $outputText . "\n";

        throw new Exception("Rector analysis failed with return code: {$returnCode}");
    }

    // Save output if requested
    if (isset($options['output'])) {
        file_put_contents($options['output'], $outputText);
        echo "\nAnalysis output saved to: {$options['output']}\n";
    }
}

/**
 * Build Rector command.
 */
function buildRectorCommand(array $options, bool $dryRun): string
{
    $projectRoot = dirname(__DIR__, 2);
    $rectorBinary = "{$projectRoot}/vendor/bin/rector";

    // Use .bat extension on Windows
    if (PHP_OS_FAMILY === 'Windows') {
        $rectorBinary .= '.bat';
    }

    $command = $rectorBinary . ' process';

    // Add dry-run flag
    if ($dryRun) {
        $command .= ' --dry-run';
    }

    // Add specific path if provided
    if (isset($options['path'])) {
        $path = $options['path'];
        $validPaths = ['src', 'tests', 'example'];

        if (!in_array($path, $validPaths, true)) {
            throw new Exception('Invalid path. Valid paths: ' . implode(', ', $validPaths));
        }

        $command .= ' ' . escapeshellarg("{$projectRoot}/{$path}");
    }

    // Add configuration file
    $command .= ' --config=' . escapeshellarg("{$projectRoot}/rector.php");

    // Add verbose output
    $command .= ' --no-progress-bar';

    return $command;
}

/**
 * Parse Rector output to extract changes.
 */
function parseRectorOutput(string $output): array
{
    $changes = [
        'files_changed' => 0,
        'rules_applied' => [],
        'categories' => [
            'type_declarations' => 0,
            'code_quality' => 0,
            'dead_code' => 0,
            'early_return' => 0,
            'coding_style' => 0,
            'php_upgrades' => 0,
            'other' => 0,
        ],
    ];

    // Extract number of files changed
    if (preg_match('/(\d+) files? changed/', $output, $matches)) {
        $changes['files_changed'] = (int) $matches[1];
    }

    // Extract applied rules
    $lines = explode("\n", $output);

    foreach ($lines as $line) {
        if (str_contains($line, 'Applied') || str_contains($line, '✓')) {
            // Try to categorize the rule
            $rule = trim($line);
            $changes['rules_applied'][] = $rule;

            // Categorize rules
            if (str_contains($rule, 'Type') || str_contains($rule, 'Return')) {
                ++$changes['categories']['type_declarations'];
            } elseif (str_contains($rule, 'Quality') || str_contains($rule, 'Simplify')) {
                ++$changes['categories']['code_quality'];
            } elseif (str_contains($rule, 'Dead') || str_contains($rule, 'Unused')) {
                ++$changes['categories']['dead_code'];
            } elseif (str_contains($rule, 'Early') || str_contains($rule, 'Return')) {
                ++$changes['categories']['early_return'];
            } elseif (str_contains($rule, 'Style') || str_contains($rule, 'Format')) {
                ++$changes['categories']['coding_style'];
            } elseif (str_contains($rule, 'Php') || str_contains($rule, 'PHP')) {
                ++$changes['categories']['php_upgrades'];
            } else {
                ++$changes['categories']['other'];
            }
        }
    }

    return $changes;
}

/**
 * Display change summary.
 */
function displayChangeSummary(array $changes): void
{
    echo "📊 Summary:\n";
    echo "  Files changed: {$changes['files_changed']}\n";
    echo '  Rules applied: ' . count($changes['rules_applied']) . "\n\n";

    echo "📋 Categories:\n";

    foreach ($changes['categories'] as $category => $count) {
        if ($count > 0) {
            $categoryName = ucwords(str_replace('_', ' ', $category));
            echo "  {$categoryName}: {$count}\n";
        }
    }

    if (!empty($changes['rules_applied'])) {
        echo "\n🔧 Applied rules:\n";

        foreach (array_slice($changes['rules_applied'], 0, 10) as $rule) {
            echo "  • {$rule}\n";
        }

        if (count($changes['rules_applied']) > 10) {
            $remaining = count($changes['rules_applied']) - 10;
            echo "  ... and {$remaining} more\n";
        }
    }
}

/**
 * Clear Rector cache.
 */
function clearRectorCache(): void
{
    $cacheDir = dirname(__DIR__, 2) . '/var/cache/rector';

    if (is_dir($cacheDir)) {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($cacheDir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($files as $fileinfo) {
            $todo = ($fileinfo->isDir() ? 'rmdir' : 'unlink');
            $todo($fileinfo->getRealPath());
        }

        rmdir($cacheDir);
    }
}

/**
 * Parse command line arguments.
 */
function parseArguments(array $argv): array
{
    $options = [];
    $counter = count($argv);

    for ($i = 1; $i < $counter; ++$i) {
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
    echo "Rector Analysis Runner for VersaORM\n";
    echo "===================================\n\n";
    echo "Usage: php tests/bin/rector-analyze.php [options]\n\n";
    echo "Options:\n";
    echo "  --dry-run           Show what would be changed without applying changes\n";
    echo "  --path=PATH         Analyze specific path only (src, tests, example)\n";
    echo "  --clear-cache       Clear Rector cache before running\n";
    echo "  --output=FILE       Save analysis output to file\n";
    echo "  --help              Show this help message\n\n";
    echo "Examples:\n";
    echo "  php tests/bin/rector-analyze.php --dry-run\n";
    echo "  php tests/bin/rector-analyze.php --path=src\n";
    echo "  php tests/bin/rector-analyze.php --clear-cache --dry-run\n";
    echo "  php tests/bin/rector-analyze.php --output=rector-report.txt\n\n";
    echo "What Rector does:\n";
    echo "  • Modernizes PHP code to newer versions\n";
    echo "  • Adds type declarations automatically\n";
    echo "  • Improves code quality and readability\n";
    echo "  • Removes dead code and unused imports\n";
    echo "  • Applies coding standards and best practices\n";
    echo "  • Refactors complex conditions to early returns\n";
}
