<?php

declare(strict_types=1);

/**
 * Coverage Dashboard Generator for VersaORM.
 *
 * This script generates a comprehensive HTML dashboard with all coverage metrics,
 * feature analysis, alerts, and actionable insights.
 *
 * Usage:
 *   php tests/bin/generate-coverage-dashboard.php [options]
 *
 * Options:
 *   --output=FILE       Output file path (default: tests/reports/coverage/dashboard.html)
 *   --help              Show this help message
 */

require_once dirname(__DIR__, 2) . '/vendor/autoload.php';

use VersaORM\Tests\Logging\TestLogger;
use VersaORM\Tests\Quality\CoverageDashboard;

// Parse command line arguments
$options = parseArguments($argv);

if (isset($options['help'])) {
    showHelp();
    exit(0);
}

// Initialize logger
$logger = new TestLogger();
$logger->info('Starting coverage dashboard generation');

try {
    // Initialize dashboard generator
    $dashboard = new CoverageDashboard();

    // Generate dashboard
    $dashboardPath = $dashboard->generateDashboard();

    // Handle custom output path
    if (isset($options['output'])) {
        $customPath = $options['output'];

        if (copy($dashboardPath, $customPath)) {
            echo "Dashboard generated successfully: {$customPath}\n";
        } else {
            echo "Dashboard generated at: {$dashboardPath}\n";
            echo "Warning: Could not copy to custom path: {$customPath}\n";
        }
    } else {
        echo "Dashboard generated successfully: {$dashboardPath}\n";
    }

    // Show quick stats
    echo "\nQuick Stats:\n";
    echo "============\n";

    // Try to extract some basic stats from the generated dashboard
    if (file_exists($dashboardPath)) {
        $content = file_get_contents($dashboardPath);

        // Extract overall coverage (this is a simple regex approach)
        if (preg_match('/Overall Coverage.*?(\d+\.?\d*)%/', $content, $matches)) {
            $coverage = $matches[1];
            echo "Overall Coverage: {$coverage}%\n";

            if ($coverage >= 95) {
                echo "Status: ✅ EXCELLENT\n";
            } elseif ($coverage >= 90) {
                echo "Status: ✅ GOOD\n";
            } elseif ($coverage >= 80) {
                echo "Status: ⚠️  NEEDS IMPROVEMENT\n";
            } else {
                echo "Status: ❌ CRITICAL\n";
            }
        }

        echo 'Dashboard Size: ' . number_format(filesize($dashboardPath)) . " bytes\n";
    }

    echo "\nOpen the dashboard in your browser to view detailed coverage analysis.\n";

    $logger->info('Coverage dashboard generation completed successfully');
} catch (Exception $e) {
    $logger->error('Coverage dashboard generation failed: ' . $e->getMessage());
    echo 'ERROR: ' . $e->getMessage() . "\n";
    exit(1);
}

/**
 * Parse command line arguments.
 */
function parseArguments(array $argv): array
{
    $options = [];
    $counter = count($argv);

    for ($i = 1; $i < $counter; $i++) {
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
    echo "Coverage Dashboard Generator for VersaORM\n";
    echo "=========================================\n\n";
    echo "Usage: php tests/bin/generate-coverage-dashboard.php [options]\n\n";
    echo "Options:\n";
    echo "  --output=FILE       Output file path (default: tests/reports/coverage/dashboard.html)\n";
    echo "  --help              Show this help message\n\n";
    echo "This script generates a comprehensive HTML dashboard with:\n";
    echo "  - Overall coverage metrics\n";
    echo "  - Coverage by database engine (MySQL, PostgreSQL, SQLite)\n";
    echo "  - Coverage by feature (CRUD, relationships, security, etc.)\n";
    echo "  - Interactive charts and visualizations\n";
    echo "  - Alerts and recommendations\n";
    echo "  - Actionable insights for improvement\n\n";
    echo "Examples:\n";
    echo "  php tests/bin/generate-coverage-dashboard.php\n";
    echo "  php tests/bin/generate-coverage-dashboard.php --output=coverage-report.html\n";
}
