<?php

declare(strict_types=1);

/**
 * Coverage Analysis Runner for VersaORM.
 *
 * This script runs comprehensive code coverage analysis across all database engines,
 * generates detailed reports, validates coverage thresholds, and provides actionable
 * insights for improving test coverage.
 *
 * Usage:
 *   php tests/bin/coverage-analyze.php [options]
 *
 * Options:
 *   --engine=ENGINE     Run coverage for specific engine (mysql, postgresql, sqlite)
 *   --minimum=PERCENT   Set minimum coverage threshold (default: 95)
 *   --gaps-only         Generate only coverage gaps report
 *   --alerts-only       Generate only coverage alerts
 *   --format=FORMAT     Output format (json, text, html) (default: text)
 *   --output=FILE       Output file path (optional)
 *   --help              Show this help message
 */

require_once dirname(__DIR__, 2) . '/vendor/autoload.php';

use VersaORM\Tests\Logging\TestLogger;
use VersaORM\Tests\Quality\CoverageAnalyzer;

// Parse command line arguments
$options = parseArguments($argv);

if (isset($options['help'])) {
    showHelp();
    exit(0);
}

// Initialize logger
$logger = new TestLogger();
$logger->info('Starting coverage analysis');

try {
    // Initialize coverage analyzer
    $config = [
        'minimum_coverage' => (float) ($options['minimum'] ?? 95.0),
    ];

    $analyzer = new CoverageAnalyzer($config);

    // Determine what analysis to run
    if (isset($options['gaps-only'])) {
        runGapsAnalysis($analyzer, $options, $logger);
    } elseif (isset($options['alerts-only'])) {
        runAlertsAnalysis($analyzer, $options, $logger);
    } elseif (isset($options['engine'])) {
        runEngineAnalysis($analyzer, $options, $logger);
    } else {
        runFullAnalysis($analyzer, $options, $logger);
    }

    $logger->info('Coverage analysis completed successfully');

} catch (Exception $e) {
    $logger->error('Coverage analysis failed: ' . $e->getMessage());
    echo 'ERROR: ' . $e->getMessage() . "\n";
    exit(1);
}

/**
 * Run full coverage analysis.
 */
function runFullAnalysis(CoverageAnalyzer $analyzer, array $options, TestLogger $logger): void
{
    $logger->info('Running full coverage analysis');

    $result = $analyzer->runFullCoverageAnalysis();

    // Output results
    outputResults($result, $options);

    // Generate additional reports
    if (!isset($options['no-gaps'])) {
        $logger->info('Generating coverage gaps report');
        $gapsReport = $analyzer->generateCoverageGapsReport();
        echo "\nCoverage gaps report generated: " . $gapsReport['report_path'] . "\n";
    }

    if (!isset($options['no-alerts'])) {
        $logger->info('Generating coverage alerts');
        $alerts = $analyzer->generateCoverageAlerts();

        if (!empty($alerts)) {
            echo "\nCoverage Alerts:\n";

            foreach ($alerts as $alert) {
                echo "  [{$alert['severity']}] {$alert['message']}\n";
            }
        }
    }

    // Exit with appropriate code
    exit($result->passed ? 0 : 1);
}

/**
 * Run coverage analysis for specific engine.
 */
function runEngineAnalysis(CoverageAnalyzer $analyzer, array $options, TestLogger $logger): void
{
    $engine = $options['engine'];
    $logger->info("Running coverage analysis for {$engine}");

    try {
        $result = $analyzer->runCoverageForEngine($engine);

        echo "Coverage Analysis Results for {$engine}:\n";
        echo "  Coverage: {$result['coverage_percentage']}%\n";
        echo '  Status: ' . ($result['success'] ? 'SUCCESS' : 'FAILED') . "\n";

        if (isset($result['coverage_data'])) {
            $data = $result['coverage_data'];
            echo "  Total Lines: {$data['total_lines']}\n";
            echo "  Covered Lines: {$data['covered_lines']}\n";
            echo "  Uncovered Lines: {$data['uncovered_lines']}\n";
            echo "  Files Analyzed: {$data['files_analyzed']}\n";
        }

        // Validate threshold
        $threshold = $analyzer->validateCoverageThreshold($result['coverage_percentage']);
        echo "  Threshold Check: {$threshold['status']}\n";

        if (isset($options['output'])) {
            file_put_contents($options['output'], json_encode($result, JSON_PRETTY_PRINT));
            echo "  Results saved to: {$options['output']}\n";
        }

        exit($threshold['passed'] ? 0 : 1);

    } catch (Exception $e) {
        echo "ERROR: Failed to analyze coverage for {$engine}: " . $e->getMessage() . "\n";
        exit(1);
    }
}

/**
 * Run gaps analysis only.
 */
function runGapsAnalysis(CoverageAnalyzer $analyzer, array $options, TestLogger $logger): void
{
    $logger->info('Running coverage gaps analysis');

    $gapsReport = $analyzer->generateCoverageGapsReport();

    echo "Coverage Gaps Report:\n";
    echo "Report saved to: {$gapsReport['report_path']}\n\n";

    if (!empty($gapsReport['consolidated_gaps'])) {
        echo "Files with coverage gaps:\n";

        foreach ($gapsReport['consolidated_gaps'] as $gap) {
            echo "  {$gap['file']}: {$gap['worst_coverage']}% (avg: {$gap['average_coverage']}%)\n";
        }
    } else {
        echo "No coverage gaps found!\n";
    }

    if (isset($options['output'])) {
        file_put_contents($options['output'], json_encode($gapsReport, JSON_PRETTY_PRINT));
        echo "\nResults saved to: {$options['output']}\n";
    }
}

/**
 * Run alerts analysis only.
 */
function runAlertsAnalysis(CoverageAnalyzer $analyzer, array $options, TestLogger $logger): void
{
    $logger->info('Running coverage alerts analysis');

    $alerts = $analyzer->generateCoverageAlerts();

    if (empty($alerts)) {
        echo "No coverage alerts found!\n";
        exit(0);
    }

    echo "Coverage Alerts:\n";

    foreach ($alerts as $alert) {
        echo "  [{$alert['severity']}] {$alert['type']}: {$alert['message']}\n";

        if (isset($alert['files'])) {
            foreach ($alert['files'] as $file) {
                echo "    - {$file['file']}: {$file['coverage']}%\n";
            }
        }
    }

    if (isset($options['output'])) {
        file_put_contents($options['output'], json_encode($alerts, JSON_PRETTY_PRINT));
        echo "\nResults saved to: {$options['output']}\n";
    }

    // Exit with error code if there are high/critical alerts
    $hasHighSeverity = false;

    foreach ($alerts as $alert) {
        if (in_array($alert['severity'], ['high', 'critical'], true)) {
            $hasHighSeverity = true;
            break;
        }
    }

    exit($hasHighSeverity ? 1 : 0);
}

/**
 * Output results based on format.
 *
 * @param mixed $result
 */
function outputResults($result, array $options): void
{
    $format = $options['format'] ?? 'text';

    switch ($format) {
        case 'json':
            $output = json_encode([
                'tool'      => $result->tool,
                'score'     => $result->score,
                'passed'    => $result->passed,
                'issues'    => $result->issues,
                'metrics'   => $result->metrics,
                'timestamp' => $result->timestamp->format('Y-m-d H:i:s'),
            ], JSON_PRETTY_PRINT);
            break;

        case 'html':
            $output = generateHtmlOutput($result);
            break;

        default: // text
            $output = generateTextOutput($result);
            break;
    }

    if (isset($options['output'])) {
        file_put_contents($options['output'], $output);
        echo "Results saved to: {$options['output']}\n";
    } else {
        echo $output;
    }
}

/**
 * Generate text output.
 *
 * @param mixed $result
 */
function generateTextOutput($result): string
{
    $output = "Coverage Analysis Results\n";
    $output .= "========================\n\n";
    $output .= "Overall Coverage: {$result->score}%\n";
    $output .= 'Status: ' . ($result->passed ? 'PASS' : 'FAIL') . "\n";
    $output .= "Minimum Required: {$result->metrics['minimum_required']}%\n";
    $output .= "Total Lines: {$result->metrics['total_lines']}\n";
    $output .= "Covered Lines: {$result->metrics['covered_lines']}\n\n";

    if (!empty($result->issues)) {
        $output .= "Issues:\n";

        foreach ($result->issues as $issue) {
            $output .= "  - {$issue}\n";
        }
        $output .= "\n";
    }

    $output .= "Engine Results:\n";

    foreach ($result->metrics['engine_results'] as $engine => $engineResult) {
        if ($engineResult['success']) {
            $output .= "  {$engine}: {$engineResult['coverage_percentage']}%\n";
        } else {
            $output .= "  {$engine}: ERROR - {$engineResult['error']}\n";
        }
    }

    return $output;
}

/**
 * Generate HTML output.
 *
 * @param mixed $result
 */
function generateHtmlOutput($result): string
{
    $status      = $result->passed ? 'PASS' : 'FAIL';
    $statusClass = $result->passed ? 'success' : 'error';

    $html = "<!DOCTYPE html>\n<html>\n<head>\n";
    $html .= "<title>Coverage Analysis Results</title>\n";
    $html .= "<style>\n";
    $html .= "body { font-family: Arial, sans-serif; margin: 20px; }\n";
    $html .= ".success { color: green; }\n";
    $html .= ".error { color: red; }\n";
    $html .= ".warning { color: orange; }\n";
    $html .= "table { border-collapse: collapse; width: 100%; }\n";
    $html .= "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n";
    $html .= "th { background-color: #f2f2f2; }\n";
    $html .= "</style>\n";
    $html .= "</head>\n<body>\n";

    $html .= "<h1>Coverage Analysis Results</h1>\n";
    $html .= "<p><strong>Overall Coverage:</strong> {$result->score}%</p>\n";
    $html .= "<p><strong>Status:</strong> <span class=\"{$statusClass}\">{$status}</span></p>\n";
    $html .= "<p><strong>Minimum Required:</strong> {$result->metrics['minimum_required']}%</p>\n";

    $html .= "<h2>Engine Results</h2>\n";
    $html .= "<table>\n<tr><th>Engine</th><th>Coverage</th><th>Status</th></tr>\n";

    foreach ($result->metrics['engine_results'] as $engine => $engineResult) {
        if ($engineResult['success']) {
            $engineStatus = $engineResult['coverage_percentage'] >= $result->metrics['minimum_required'] ? 'PASS' : 'FAIL';
            $engineClass  = $engineStatus === 'PASS' ? 'success' : 'error';
            $html .= "<tr><td>{$engine}</td><td>{$engineResult['coverage_percentage']}%</td><td class=\"{$engineClass}\">{$engineStatus}</td></tr>\n";
        } else {
            $html .= "<tr><td>{$engine}</td><td>-</td><td class=\"error\">ERROR</td></tr>\n";
        }
    }

    $html .= "</table>\n";
    $html .= "</body>\n</html>";

    return $html;
}

/**
 * Parse command line arguments.
 */
function parseArguments(array $argv): array
{
    $options = [];

    for ($i = 1; $i < count($argv); ++$i) {
        $arg = $argv[$i];

        if (strpos($arg, '--') === 0) {
            if (strpos($arg, '=') !== false) {
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
    echo "Coverage Analysis Runner for VersaORM\n";
    echo "=====================================\n\n";
    echo "Usage: php tests/bin/coverage-analyze.php [options]\n\n";
    echo "Options:\n";
    echo "  --engine=ENGINE     Run coverage for specific engine (mysql, postgresql, sqlite)\n";
    echo "  --minimum=PERCENT   Set minimum coverage threshold (default: 95)\n";
    echo "  --gaps-only         Generate only coverage gaps report\n";
    echo "  --alerts-only       Generate only coverage alerts\n";
    echo "  --format=FORMAT     Output format (json, text, html) (default: text)\n";
    echo "  --output=FILE       Output file path (optional)\n";
    echo "  --no-gaps           Skip gaps report generation\n";
    echo "  --no-alerts         Skip alerts generation\n";
    echo "  --help              Show this help message\n\n";
    echo "Examples:\n";
    echo "  php tests/bin/coverage-analyze.php\n";
    echo "  php tests/bin/coverage-analyze.php --engine=mysql\n";
    echo "  php tests/bin/coverage-analyze.php --minimum=90 --format=json\n";
    echo "  php tests/bin/coverage-analyze.php --gaps-only --output=gaps.json\n";
}
