<?php

declare(strict_types=1);

/**
 * Feature Coverage Analysis Runner for VersaORM.
 *
 * This script analyzes code coverage by specific features and functionalities,
 * tracks coverage gaps, generates alerts for uncovered code, and provides
 * actionable insights for improving test coverage.
 *
 * Usage:
 *   php tests/bin/feature-coverage-analyze.php [options]
 *
 * Options:
 *   --feature=FEATURE   Analyze specific feature only
 *   --gaps-only         Generate only coverage gaps report
 *   --alerts-only       Generate only coverage alerts
 *   --format=FORMAT     Output format (json, text, html) (default: text)
 *   --output=FILE       Output file path (optional)
 *   --help              Show this help message
 */

require_once dirname(__DIR__, 2) . '/vendor/autoload.php';

use VersaORM\Tests\Logging\TestLogger;
use VersaORM\Tests\Quality\FeatureCoverageAnalyzer;

// Parse command line arguments
$options = parseArguments($argv);

if (isset($options['help'])) {
    showHelp();
    exit(0);
}

// Initialize logger
$logger = new TestLogger();
$logger->info('Starting feature coverage analysis');

try {
    // Initialize feature coverage analyzer
    $analyzer = new FeatureCoverageAnalyzer();

    // Determine what analysis to run
    if (isset($options['gaps-only'])) {
        runGapsAnalysis($analyzer, $options, $logger);
    } elseif (isset($options['alerts-only'])) {
        runAlertsAnalysis($analyzer, $options, $logger);
    } elseif (isset($options['feature'])) {
        runFeatureAnalysis($analyzer, $options, $logger);
    } else {
        runFullAnalysis($analyzer, $options, $logger);
    }

    $logger->info('Feature coverage analysis completed successfully');

} catch (Exception $e) {
    $logger->error('Feature coverage analysis failed: ' . $e->getMessage());
    echo 'ERROR: ' . $e->getMessage() . "\n";
    exit(1);
}

/**
 * Run full feature coverage analysis.
 */
function runFullAnalysis(FeatureCoverageAnalyzer $analyzer, array $options, TestLogger $logger): void
{
    $logger->info('Running full feature coverage analysis');

    $result = $analyzer->analyzeFeatureCoverage();

    // Output results
    outputResults($result, $options);

    // Generate additional reports
    if (!isset($options['no-gaps'])) {
        $logger->info('Generating feature coverage gaps report');
        $gapsReport = $analyzer->generateFeatureCoverageGapsReport();
        echo "\nFeature coverage gaps report generated: tests/reports/coverage/feature-gaps-report.json\n";
    }

    if (!isset($options['no-alerts'])) {
        $logger->info('Generating feature coverage alerts');
        $alerts = $analyzer->generateFeatureCoverageAlerts();

        if (!empty($alerts)) {
            echo "\nFeature Coverage Alerts:\n";

            foreach ($alerts as $alert) {
                echo "  [{$alert['severity']}] {$alert['message']}\n";
            }
        }
    }

    // Exit with appropriate code
    exit($result->passed ? 0 : 1);
}

/**
 * Run analysis for specific feature.
 */
function runFeatureAnalysis(FeatureCoverageAnalyzer $analyzer, array $options, TestLogger $logger): void
{
    $feature = $options['feature'];
    $logger->info("Running coverage analysis for feature: {$feature}");

    try {
        $result = $analyzer->trackFeatureCoverage($feature);

        echo "Feature Coverage Analysis Results for '{$feature}':\n";
        echo "  Description: {$result['description']}\n";
        echo "  Average Coverage: {$result['average_coverage']}%\n";
        echo "  Required Coverage: {$result['minimum_required']}%\n";
        echo "  Status: {$result['status']}\n";
        echo "  Engines Analyzed: {$result['engines_analyzed']}\n";
        echo "  Engines Passed: {$result['engines_passed']}\n\n";

        echo "Engine Results:\n";

        foreach ($result['engine_results'] as $engine => $engineResult) {
            if (isset($engineResult['error'])) {
                echo "  {$engine}: ERROR - {$engineResult['error']}\n";
            } else {
                echo "  {$engine}: {$engineResult['coverage']}% ({$engineResult['test_files_found']} test files)\n";
            }
        }

        if (isset($options['output'])) {
            file_put_contents($options['output'], json_encode($result, JSON_PRETTY_PRINT));
            echo "\nResults saved to: {$options['output']}\n";
        }

        exit($result['status'] === 'PASS' ? 0 : 1);

    } catch (Exception $e) {
        echo "ERROR: Failed to analyze feature '{$feature}': " . $e->getMessage() . "\n";
        exit(1);
    }
}

/**
 * Run gaps analysis only.
 */
function runGapsAnalysis(FeatureCoverageAnalyzer $analyzer, array $options, TestLogger $logger): void
{
    $logger->info('Running feature coverage gaps analysis');

    $gapsReport = $analyzer->generateFeatureCoverageGapsReport();

    echo "Feature Coverage Gaps Report:\n";
    echo "============================\n\n";
    echo "Total Features: {$gapsReport['total_features']}\n";
    echo "Features with Gaps: {$gapsReport['features_with_gaps']}\n";
    echo "Worst Gap: {$gapsReport['summary']['worst_gap']}%\n";
    echo 'Average Gap: ' . round($gapsReport['summary']['average_gap'], 2) . "%\n\n";

    if (!empty($gapsReport['gaps'])) {
        echo "Features with Coverage Gaps:\n";

        foreach ($gapsReport['gaps'] as $gap) {
            echo "  {$gap['feature']}: {$gap['current_coverage']}% (gap: {$gap['gap_percentage']}%)\n";
            echo "    Description: {$gap['description']}\n";
            echo '    Engines with gaps: ' . count($gap['engines_with_gaps']) . "\n";
        }
        echo "\n";
    }

    if (!empty($gapsReport['recommendations'])) {
        echo "Recommendations:\n";

        foreach ($gapsReport['recommendations'] as $rec) {
            echo "  [{$rec['priority']}] {$rec['feature']}: {$rec['action']}\n";
            echo "    Reason: {$rec['reason']}\n";
        }
    }

    if (isset($options['output'])) {
        file_put_contents($options['output'], json_encode($gapsReport, JSON_PRETTY_PRINT));
        echo "\nResults saved to: {$options['output']}\n";
    }
}

/**
 * Run alerts analysis only.
 */
function runAlertsAnalysis(FeatureCoverageAnalyzer $analyzer, array $options, TestLogger $logger): void
{
    $logger->info('Running feature coverage alerts analysis');

    $alerts = $analyzer->generateFeatureCoverageAlerts();

    if (empty($alerts)) {
        echo "No feature coverage alerts found!\n";
        exit(0);
    }

    echo "Feature Coverage Alerts:\n";
    echo "=======================\n\n";

    $alertsBySeverity = [];

    foreach ($alerts as $alert) {
        $alertsBySeverity[$alert['severity']][] = $alert;
    }

    $severityOrder = ['critical', 'high', 'medium', 'low'];

    foreach ($severityOrder as $severity) {
        if (isset($alertsBySeverity[$severity])) {
            echo strtoupper($severity) . " ALERTS:\n";

            foreach ($alertsBySeverity[$severity] as $alert) {
                echo "  {$alert['type']}: {$alert['message']}\n";

                if (isset($alert['feature'])) {
                    echo "    Feature: {$alert['feature']}\n";
                }

                if (isset($alert['engines_affected'])) {
                    echo '    Engines: ' . implode(', ', $alert['engines_affected']) . "\n";
                }

                if (isset($alert['missing_files'])) {
                    echo '    Missing files: ' . implode(', ', $alert['missing_files']) . "\n";
                }

                echo "\n";
            }
        }
    }

    if (isset($options['output'])) {
        file_put_contents($options['output'], json_encode($alerts, JSON_PRETTY_PRINT));
        echo "Results saved to: {$options['output']}\n";
    }

    // Exit with error code if there are high/critical alerts
    $hasHighSeverity = isset($alertsBySeverity['critical']) || isset($alertsBySeverity['high']);
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
    $output = "Feature Coverage Analysis Results\n";
    $output .= "=================================\n\n";
    $output .= "Overall Score: {$result->score}%\n";
    $output .= 'Status: ' . ($result->passed ? 'PASS' : 'FAIL') . "\n";
    $output .= "Features Analyzed: {$result->metrics['features_analyzed']}\n";
    $output .= "Features Meeting Threshold: {$result->metrics['features_meeting_threshold']}\n\n";

    if (!empty($result->issues)) {
        $output .= "Issues:\n";

        foreach ($result->issues as $issue) {
            $output .= "  - {$issue}\n";
        }
        $output .= "\n";
    }

    $output .= "Feature Results:\n";

    foreach ($result->metrics['feature_results'] as $featureName => $featureResult) {
        $output .= "  {$featureName}: {$featureResult['average_coverage']}% ({$featureResult['status']})\n";
        $output .= "    Required: {$featureResult['minimum_required']}%\n";
        $output .= "    Engines passed: {$featureResult['engines_passed']}/{$featureResult['engines_analyzed']}\n";
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
    $html .= "<title>Feature Coverage Analysis Results</title>\n";
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

    $html .= "<h1>Feature Coverage Analysis Results</h1>\n";
    $html .= "<p><strong>Overall Score:</strong> {$result->score}%</p>\n";
    $html .= "<p><strong>Status:</strong> <span class=\"{$statusClass}\">{$status}</span></p>\n";
    $html .= "<p><strong>Features Analyzed:</strong> {$result->metrics['features_analyzed']}</p>\n";

    $html .= "<h2>Feature Results</h2>\n";
    $html .= "<table>\n<tr><th>Feature</th><th>Coverage</th><th>Required</th><th>Status</th><th>Engines Passed</th></tr>\n";

    foreach ($result->metrics['feature_results'] as $featureName => $featureResult) {
        $featureStatus = $featureResult['status'];
        $featureClass  = $featureStatus === 'PASS' ? 'success' : 'error';
        $html .= '<tr>';
        $html .= "<td>{$featureName}</td>";
        $html .= "<td>{$featureResult['average_coverage']}%</td>";
        $html .= "<td>{$featureResult['minimum_required']}%</td>";
        $html .= "<td class=\"{$featureClass}\">{$featureStatus}</td>";
        $html .= "<td>{$featureResult['engines_passed']}/{$featureResult['engines_analyzed']}</td>";
        $html .= "</tr>\n";
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
    echo "Feature Coverage Analysis Runner for VersaORM\n";
    echo "=============================================\n\n";
    echo "Usage: php tests/bin/feature-coverage-analyze.php [options]\n\n";
    echo "Options:\n";
    echo "  --feature=FEATURE   Analyze specific feature only\n";
    echo "  --gaps-only         Generate only coverage gaps report\n";
    echo "  --alerts-only       Generate only coverage alerts\n";
    echo "  --format=FORMAT     Output format (json, text, html) (default: text)\n";
    echo "  --output=FILE       Output file path (optional)\n";
    echo "  --no-gaps           Skip gaps report generation\n";
    echo "  --no-alerts         Skip alerts generation\n";
    echo "  --help              Show this help message\n\n";
    echo "Available Features:\n";
    echo "  - crud_operations\n";
    echo "  - relationships\n";
    echo "  - query_builder\n";
    echo "  - transactions\n";
    echo "  - security\n";
    echo "  - validation\n";
    echo "  - type_mapping\n\n";
    echo "Examples:\n";
    echo "  php tests/bin/feature-coverage-analyze.php\n";
    echo "  php tests/bin/feature-coverage-analyze.php --feature=security\n";
    echo "  php tests/bin/feature-coverage-analyze.php --gaps-only --format=json\n";
    echo "  php tests/bin/feature-coverage-analyze.php --alerts-only --output=alerts.json\n";
}
