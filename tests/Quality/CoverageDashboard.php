<?php

declare(strict_types=1);

namespace VersaORM\Tests\Quality;

use Exception;
use VersaORM\Tests\Logging\TestLogger;

use function count;
use function dirname;

/**
 * Coverage Dashboard Generator for VersaORM.
 *
 * Generates comprehensive HTML dashboards with coverage metrics,
 * trends, alerts, and actionable insights for improving test coverage.
 */
class CoverageDashboard
{
    private TestLogger $logger;

    private string $projectRoot;

    public function __construct()
    {
        $this->logger = new TestLogger();
        $this->projectRoot = dirname(__DIR__, 2);
    }

    /**
     * Generate comprehensive coverage dashboard.
     */
    public function generateDashboard(): string
    {
        $this->logger->info('Generating coverage dashboard');

        // Collect all coverage data
        $coverageData = $this->collectCoverageData();
        $featureData = $this->collectFeatureData();
        $this->collectTrendsData();
        $alertsData = $this->collectAlertsData();

        // Generate HTML dashboard
        $html = $this->generateHtmlDashboard($coverageData, $featureData, $alertsData);

        // Save dashboard
        $dashboardPath = "{$this->projectRoot}/tests/reports/coverage/dashboard.html";
        file_put_contents($dashboardPath, $html);

        $this->logger->info("Coverage dashboard generated: {$dashboardPath}");

        return $dashboardPath;
    }

    /**
     * Collect coverage data from all engines.
     */
    private function collectCoverageData(): array
    {
        $engines = ['mysql', 'postgresql', 'sqlite'];
        $data = [
            'engines' => [],
            'overall' => [
                'coverage' => 0,
                'total_lines' => 0,
                'covered_lines' => 0,
                'files_analyzed' => 0,
            ],
        ];

        $totalCoverage = 0;
        $validEngines = 0;

        foreach ($engines as $engine) {
            try {
                $engineData = $this->getCoverageDataForEngine($engine);
                $data['engines'][$engine] = $engineData;

                if ($engineData['coverage'] > 0) {
                    $totalCoverage += $engineData['coverage'];
                    $validEngines++;
                    $data['overall']['total_lines'] += $engineData['total_lines'];
                    $data['overall']['covered_lines'] += $engineData['covered_lines'];
                    $data['overall']['files_analyzed'] += $engineData['files_analyzed'];
                }
            } catch (Exception $e) {
                $this->logger->warning("Failed to collect coverage data for {$engine}: " . $e->getMessage());
                $data['engines'][$engine] = [
                    'coverage' => 0,
                    'error' => $e->getMessage(),
                    'status' => 'ERROR',
                ];
            }
        }

        $data['overall']['coverage'] = $validEngines > 0 ? $totalCoverage / $validEngines : 0;

        return $data;
    }

    /**
     * Collect feature coverage data.
     */
    private function collectFeatureData(): array
    {
        try {
            $analyzer = new FeatureCoverageAnalyzer();
            $result = $analyzer->analyzeFeatureCoverage();

            return [
                'features' => $result->metrics['feature_results'] ?? [],
                'overall' => $result->metrics['overall_results'] ?? [],
                'gaps' => $result->metrics['gaps_report'] ?? [],
            ];
        } catch (Exception $e) {
            $this->logger->warning('Failed to collect feature data: ' . $e->getMessage());

            return [
                'features' => [],
                'overall' => [],
                'gaps' => [],
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Collect trends data.
     */
    private function collectTrendsData(): array
    {
        $trendsFile = "{$this->projectRoot}/tests/reports/coverage/trends.json";

        if (file_exists($trendsFile)) {
            $trends = json_decode(file_get_contents($trendsFile), true);

            return $trends ?? [];
        }

        return [
            'coverage_history' => [],
            'feature_history' => [],
            'alerts_history' => [],
        ];
    }

    /**
     * Collect alerts data.
     */
    private function collectAlertsData(): array
    {
        try {
            $coverageAnalyzer = new CoverageAnalyzer();
            $featureAnalyzer = new FeatureCoverageAnalyzer();

            $coverageAlerts = $coverageAnalyzer->generateCoverageAlerts();
            $featureAlerts = $featureAnalyzer->generateFeatureCoverageAlerts();

            return [
                'coverage_alerts' => $coverageAlerts,
                'feature_alerts' => $featureAlerts,
                'total_alerts' => count($coverageAlerts) + count($featureAlerts),
                'critical_alerts' => $this->countAlertsBySeverity(array_merge($coverageAlerts, $featureAlerts), 'critical'),
                'high_alerts' => $this->countAlertsBySeverity(array_merge($coverageAlerts, $featureAlerts), 'high'),
            ];
        } catch (Exception $e) {
            $this->logger->warning('Failed to collect alerts data: ' . $e->getMessage());

            return [
                'coverage_alerts' => [],
                'feature_alerts' => [],
                'total_alerts' => 0,
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Get coverage data for specific engine.
     */
    private function getCoverageDataForEngine(string $engine): array
    {
        $cloverFile = "{$this->projectRoot}/tests/reports/coverage/{$engine}/clover.xml";

        if (! file_exists($cloverFile)) {
            throw new Exception("Coverage data not found for {$engine}");
        }

        $xml = simplexml_load_file($cloverFile);

        if ($xml === false) {
            throw new Exception("Failed to parse coverage data for {$engine}");
        }

        $metrics = $xml->project->metrics;
        $totalLines = (int) $metrics['statements'];
        $coveredLines = (int) $metrics['coveredstatements'];
        $coverage = $totalLines > 0 ? ($coveredLines / $totalLines) * 100 : 0;

        return [
            'coverage' => round($coverage, 2),
            'total_lines' => $totalLines,
            'covered_lines' => $coveredLines,
            'files_analyzed' => (int) $metrics['files'],
            'classes_analyzed' => (int) $metrics['classes'],
            'methods_analyzed' => (int) $metrics['methods'],
            'status' => $coverage >= 95 ? 'PASS' : 'FAIL',
        ];
    }

    /**
     * Count alerts by severity.
     */
    private function countAlertsBySeverity(array $alerts, string $severity): int
    {
        return count(array_filter($alerts, static fn ($alert): bool => $alert['severity'] === $severity));
    }

    /**
     * Generate HTML dashboard.
     */
    private function generateHtmlDashboard(array $coverageData, array $featureData, array $alertsData): string
    {
        $html = $this->getHtmlTemplate();

        // Replace placeholders with actual data
        $html = str_replace('{{OVERALL_COVERAGE}}', (string) round($coverageData['overall']['coverage'], 1), $html);
        $html = str_replace('{{OVERALL_STATUS}}', $coverageData['overall']['coverage'] >= 95 ? 'PASS' : 'FAIL', $html);
        $html = str_replace('{{OVERALL_STATUS_CLASS}}', $coverageData['overall']['coverage'] >= 95 ? 'success' : 'error', $html);
        $html = str_replace('{{TOTAL_LINES}}', number_format($coverageData['overall']['total_lines']), $html);
        $html = str_replace('{{COVERED_LINES}}', number_format($coverageData['overall']['covered_lines']), $html);
        $html = str_replace('{{FILES_ANALYZED}}', number_format($coverageData['overall']['files_analyzed']), $html);

        // Engine results
        $html = str_replace('{{ENGINE_RESULTS}}', $this->generateEngineResultsHtml($coverageData['engines']), $html);

        // Feature results
        $html = str_replace('{{FEATURE_RESULTS}}', $this->generateFeatureResultsHtml($featureData['features']), $html);

        // Alerts
        $html = str_replace('{{TOTAL_ALERTS}}', (string) $alertsData['total_alerts'], $html);
        $html = str_replace('{{CRITICAL_ALERTS}}', (string) ($alertsData['critical_alerts'] ?? 0), $html);
        $html = str_replace('{{HIGH_ALERTS}}', (string) ($alertsData['high_alerts'] ?? 0), $html);
        $html = str_replace('{{ALERTS_LIST}}', $this->generateAlertsHtml($alertsData), $html);

        // Coverage chart data
        $html = str_replace('{{COVERAGE_CHART_DATA}}', $this->generateCoverageChartData($coverageData), $html);

        // Feature chart data
        $html = str_replace('{{FEATURE_CHART_DATA}}', $this->generateFeatureChartData($featureData), $html);

        // Timestamp
        return str_replace('{{TIMESTAMP}}', date('Y-m-d H:i:s'), $html);
    }

    /**
     * Generate engine results HTML.
     */
    private function generateEngineResultsHtml(array $engines): string
    {
        $html = '';

        foreach ($engines as $engine => $data) {
            $statusClass = isset($data['error']) ? 'error' : ($data['status'] === 'PASS' ? 'success' : 'error');
            $coverage = isset($data['error']) ? 'ERROR' : $data['coverage'] . '%';

            $html .= '<tr>';
            $html .= '<td>' . ucfirst($engine) . '</td>';
            $html .= "<td>{$coverage}</td>";
            $html .= "<td class=\"{$statusClass}\">" . ($data['status'] ?? 'ERROR') . '</td>';
            $html .= '<td>' . number_format($data['total_lines'] ?? 0) . '</td>';
            $html .= '<td>' . number_format($data['covered_lines'] ?? 0) . '</td>';
            $html .= '</tr>';
        }

        return $html;
    }

    /**
     * Generate feature results HTML.
     */
    private function generateFeatureResultsHtml(array $features): string
    {
        $html = '';

        foreach ($features as $featureName => $data) {
            $statusClass = $data['status'] === 'PASS' ? 'success' : 'error';

            $html .= '<tr>';
            $html .= '<td>' . ucwords(str_replace('_', ' ', $featureName)) . '</td>';
            $html .= "<td>{$data['average_coverage']}%</td>";
            $html .= "<td>{$data['minimum_required']}%</td>";
            $html .= "<td class=\"{$statusClass}\">{$data['status']}</td>";
            $html .= "<td>{$data['engines_passed']}/{$data['engines_analyzed']}</td>";
            $html .= '</tr>';
        }

        return $html;
    }

    /**
     * Generate alerts HTML.
     */
    private function generateAlertsHtml(array $alertsData): string
    {
        $html = '';
        $allAlerts = array_merge($alertsData['coverage_alerts'] ?? [], $alertsData['feature_alerts'] ?? []);

        // Sort by severity
        usort($allAlerts, static function (array $a, array $b): int {
            $severityOrder = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];

            return ($severityOrder[$a['severity']] ?? 4) <=> ($severityOrder[$b['severity']] ?? 4);
        });

        foreach ($allAlerts as $alert) {
            $severityClass = $alert['severity'];

            $html .= '<tr>';
            $html .= "<td><span class=\"severity {$severityClass}\">" . strtoupper($alert['severity']) . '</span></td>';
            $html .= "<td>{$alert['type']}</td>";
            $html .= "<td>{$alert['message']}</td>";
            $html .= '</tr>';
        }

        return $html !== '' && $html !== '0' ? $html : '<tr><td colspan="3">No alerts found</td></tr>';
    }

    /**
     * Generate coverage chart data.
     */
    private function generateCoverageChartData(array $coverageData): string
    {
        $engines = [];
        $coverages = [];

        foreach ($coverageData['engines'] as $engine => $data) {
            if (! isset($data['error'])) {
                $engines[] = "'" . ucfirst($engine) . "'";
                $coverages[] = $data['coverage'];
            }
        }

        return json_encode([
            'labels' => $engines,
            'data' => $coverages,
        ]);
    }

    /**
     * Generate feature chart data.
     */
    private function generateFeatureChartData(array $featureData): string
    {
        $features = [];
        $coverages = [];

        foreach ($featureData['features'] as $featureName => $data) {
            $features[] = "'" . ucwords(str_replace('_', ' ', $featureName)) . "'";
            $coverages[] = $data['average_coverage'];
        }

        return json_encode([
            'labels' => $features,
            'data' => $coverages,
        ]);
    }

    /**
     * Get HTML template.
     */
    private function getHtmlTemplate(): string
    {
        return '<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VersaORM Coverage Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        .metric {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .metric-value {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .metric-label {
            color: #666;
            font-size: 0.9em;
        }
        .success { color: #28a745; }
        .error { color: #dc3545; }
        .warning { color: #ffc107; }
        .content {
            padding: 30px;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #333;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
            font-weight: 600;
        }
        .chart-container {
            position: relative;
            height: 300px;
            margin: 20px 0;
        }
        .severity {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .severity.critical {
            background: #dc3545;
            color: white;
        }
        .severity.high {
            background: #fd7e14;
            color: white;
        }
        .severity.medium {
            background: #ffc107;
            color: black;
        }
        .severity.low {
            background: #6c757d;
            color: white;
        }
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #ddd;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>VersaORM Coverage Dashboard</h1>
            <p>Comprehensive code coverage analysis and quality metrics</p>
            <p>Generated on {{TIMESTAMP}}</p>
        </div>

        <div class="metrics">
            <div class="metric">
                <div class="metric-value {{OVERALL_STATUS_CLASS}}">{{OVERALL_COVERAGE}}%</div>
                <div class="metric-label">Overall Coverage</div>
            </div>
            <div class="metric">
                <div class="metric-value">{{TOTAL_LINES}}</div>
                <div class="metric-label">Total Lines</div>
            </div>
            <div class="metric">
                <div class="metric-value">{{COVERED_LINES}}</div>
                <div class="metric-label">Covered Lines</div>
            </div>
            <div class="metric">
                <div class="metric-value">{{FILES_ANALYZED}}</div>
                <div class="metric-label">Files Analyzed</div>
            </div>
        </div>

        <div class="content">
            <div class="section">
                <h2>Coverage by Database Engine</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Engine</th>
                            <th>Coverage</th>
                            <th>Status</th>
                            <th>Total Lines</th>
                            <th>Covered Lines</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{ENGINE_RESULTS}}
                    </tbody>
                </table>
                <div class="chart-container">
                    <canvas id="coverageChart"></canvas>
                </div>
            </div>

            <div class="section">
                <h2>Coverage by Feature</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Feature</th>
                            <th>Coverage</th>
                            <th>Required</th>
                            <th>Status</th>
                            <th>Engines Passed</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{FEATURE_RESULTS}}
                    </tbody>
                </table>
                <div class="chart-container">
                    <canvas id="featureChart"></canvas>
                </div>
            </div>

            <div class="section">
                <h2>Alerts and Issues</h2>
                <div class="metrics">
                    <div class="metric">
                        <div class="metric-value">{{TOTAL_ALERTS}}</div>
                        <div class="metric-label">Total Alerts</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value error">{{CRITICAL_ALERTS}}</div>
                        <div class="metric-label">Critical</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value warning">{{HIGH_ALERTS}}</div>
                        <div class="metric-label">High Priority</div>
                    </div>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Type</th>
                            <th>Message</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{ALERTS_LIST}}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="footer">
            <p>VersaORM Coverage Dashboard - Ensuring 100% code quality</p>
        </div>
    </div>

    <script>
        // Coverage by Engine Chart
        const coverageData = {{COVERAGE_CHART_DATA}};
        const coverageCtx = document.getElementById("coverageChart").getContext("2d");
        new Chart(coverageCtx, {
            type: "bar",
            data: {
                labels: coverageData.labels,
                datasets: [{
                    label: "Coverage %",
                    data: coverageData.data,
                    backgroundColor: ["#28a745", "#17a2b8", "#ffc107"],
                    borderColor: ["#1e7e34", "#117a8b", "#e0a800"],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });

        // Feature Coverage Chart
        const featureData = {{FEATURE_CHART_DATA}};
        const featureCtx = document.getElementById("featureChart").getContext("2d");
        new Chart(featureCtx, {
            type: "radar",
            data: {
                labels: featureData.labels,
                datasets: [{
                    label: "Feature Coverage %",
                    data: featureData.data,
                    backgroundColor: "rgba(102, 126, 234, 0.2)",
                    borderColor: "rgba(102, 126, 234, 1)",
                    borderWidth: 2,
                    pointBackgroundColor: "rgba(102, 126, 234, 1)"
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        beginAtZero: true,
                        max: 100
                    }
                }
            }
        });
    </script>
</body>
</html>';
    }
}
