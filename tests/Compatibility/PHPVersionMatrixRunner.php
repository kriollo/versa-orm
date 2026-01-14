<?php

declare(strict_types=1);

namespace VersaORM\Tests\Compatibility;

use DateTime;
use Exception;
use RuntimeException;
use VersaORM\Tests\Results\Report;
use VersaORM\Tests\Results\TestResult;

use function count;
use function dirname;
use function in_array;

use const PHP_VERSION_ID;

/**
 * PHPVersionMatrixRunner - Ejecuta tests en matriz de compatibilidad PHP.
 *
 * Esta clase coordina la ejecución de tests de compatibilidad para diferentes
 * versiones de PHP y genera reportes consolidados.
 */
class PHPVersionMatrixRunner
{
    private PHPVersionTestExecutor $executor;

    private PHPVersionDetector $detector;

    private array $supportedVersions = ['7.4', '8.0', '8.1', '8.2', '8.3'];

    public function __construct(array $config = [])
    {
        $this->executor = new PHPVersionTestExecutor($config);
        $this->detector = new PHPVersionDetector();
    }

    /**
     * Ejecuta la matriz completa de tests de compatibilidad.
     */
    public function runCompatibilityMatrix(): Report
    {
        $startTime = microtime(true);
        $currentVersion = $this->detector->getCurrentVersion()['short_version'];

        // Solo podemos ejecutar tests para la versión actual
        if (!in_array($currentVersion, $this->supportedVersions, true)) {
            throw new RuntimeException("Current PHP version {$currentVersion} is not supported");
        }

        $results = [
            'current_version_tests' => $this->executor->runAllCompatibilityTests(),
            'version_matrix_analysis' => $this->analyzeVersionMatrix(),
            'compatibility_report' => $this->generateCompatibilityMatrix(),
        ];

        $executionTime = microtime(true) - $startTime;

        return new Report([
            'report_id' => 'php_matrix_' . date('Y-m-d_H-i-s'),
            'test_type' => 'php_compatibility_matrix',
            'php_version' => PHP_VERSION,
            'results' => $results,
            'summary' => $this->generateMatrixSummary($results),
            'execution_time' => $executionTime,
            'timestamp' => new DateTime(),
            'recommendations' => $this->generateMatrixRecommendations($results),
        ]);
    }

    /**
     * Ejecuta tests específicos para la versión actual.
     */
    public function runCurrentVersionTests(): Report
    {
        return $this->executor->runAllCompatibilityTests();
    }

    /**
     * Genera reporte detallado de la versión actual.
     */
    public function generateCurrentVersionReport(): array
    {
        return $this->executor->generateVersionReport();
    }

    /**
     * Exporta matriz de compatibilidad a JSON.
     */
    public function exportMatrixToJson(?string $filepath = null): string
    {
        $report = $this->runCompatibilityMatrix();
        $json = $report->toJson();

        if ($filepath !== null && $filepath !== '' && $filepath !== '0') {
            $directory = dirname($filepath);

            if (!is_dir($directory)) {
                mkdir($directory, 0755, true);
            }
            file_put_contents($filepath, $json);
        }

        return $json;
    }

    /**
     * Exporta matriz de compatibilidad a HTML.
     */
    public function exportMatrixToHtml(?string $filepath = null): string
    {
        $report = $this->runCompatibilityMatrix();
        $html = $this->generateMatrixHtml($report);

        if ($filepath !== null && $filepath !== '' && $filepath !== '0') {
            $directory = dirname($filepath);

            if (!is_dir($directory)) {
                mkdir($directory, 0755, true);
            }
            file_put_contents($filepath, $html);
        }

        return $html;
    }

    /**
     * Analiza la matriz de versiones PHP.
     */
    private function analyzeVersionMatrix(): TestResult
    {
        $startTime = microtime(true);
        $tests = [];
        $currentVersion = $this->detector->getCurrentVersion();

        try {
            // Análisis de la versión actual
            $tests['current_version_analysis'] = [
                'status' => 'pass',
                'message' => "Running on PHP {$currentVersion['full_version']}",
                'details' => $currentVersion,
            ];

            // Análisis de soporte
            $supportInfo = $this->detector->getCurrentVersionSupport();
            $tests['version_support_analysis'] = [
                'status' => $supportInfo !== null && $supportInfo !== [] ? 'pass' : 'fail',
                'message' =>
                    $supportInfo !== null && $supportInfo !== [] ? 'Version is supported' : 'Version is not supported',
                'details' => $supportInfo,
            ];

            // Análisis de características por versión
            foreach ($this->supportedVersions as $version) {
                $versionId = (int) str_replace('.', '', $version . '00');
                $isCurrentOrLower = $versionId <= PHP_VERSION_ID;

                $tests["version_{$version}_compatibility"] = [
                    'status' => $isCurrentOrLower ? 'pass' : 'skip',
                    'message' => $isCurrentOrLower
                        ? "PHP {$version} features are available"
                        : "PHP {$version} features are not available (current version is lower)",
                    'details' => [
                        'version' => $version,
                        'version_id' => $versionId,
                        'current_version_id' => PHP_VERSION_ID,
                        'available' => $isCurrentOrLower,
                    ],
                ];
            }

            // Análisis de EOL (End of Life)
            foreach ($this->supportedVersions as $version) {
                $versionInfo = PHPVersionDetector::$supportedVersions[$version] ?? null;

                if ($versionInfo && isset($versionInfo['eol_date'])) {
                    $eolDate = new DateTime($versionInfo['eol_date']);
                    $now = new DateTime();
                    $isEol = $eolDate < $now;

                    $tests["version_{$version}_eol_status"] = [
                        'status' => $isEol ? 'warning' : 'pass',
                        'message' => $isEol
                            ? "PHP {$version} reached EOL on {$versionInfo['eol_date']}"
                            : "PHP {$version} is supported until {$versionInfo['eol_date']}",
                        'details' => [
                            'version' => $version,
                            'eol_date' => $versionInfo['eol_date'],
                            'is_eol' => $isEol,
                            'days_until_eol' => $isEol ? 0 : $now->diff($eolDate)->days,
                        ],
                    ];
                }
            }
        } catch (Exception $e) {
            $tests['matrix_analysis_error'] = [
                'status' => 'fail',
                'message' => 'Matrix analysis failed: ' . $e->getMessage(),
                'details' => ['exception' => $e->getMessage()],
            ];
        }

        return new TestResult([
            'test_type' => 'version_matrix_analysis',
            'engine' => 'php',
            'total_tests' => count($tests),
            'passed_tests' => count(array_filter($tests, static fn($t): bool => $t['status'] === 'pass')),
            'failed_tests' => count(array_filter($tests, static fn($t): bool => $t['status'] === 'fail')),
            'skipped_tests' => count(array_filter($tests, static fn($t): bool => $t['status'] === 'skip')),
            'execution_time' => microtime(true) - $startTime,
            'failures' => array_filter($tests, static fn($t): bool => $t['status'] === 'fail'),
            'metrics' => ['tests' => $tests],
            'timestamp' => new DateTime(),
        ]);
    }

    /**
     * Genera matriz de compatibilidad.
     */
    private function generateCompatibilityMatrix(): array
    {
        $matrix = [];
        $currentVersionId = PHP_VERSION_ID;
        $currentVersion = $this->detector->getCurrentVersion()['short_version'];

        foreach ($this->supportedVersions as $version) {
            $versionId = (int) str_replace('.', '', $version . '00');
            $versionInfo = PHPVersionDetector::$supportedVersions[$version] ?? null;

            $matrix[$version] = [
                'version' => $version,
                'version_id' => $versionId,
                'is_current' => $version === $currentVersion,
                'is_available' => $currentVersionId >= $versionId,
                'support_info' => $versionInfo,
                'features' => $versionInfo['features'] ?? [],
                'status' => $versionInfo['status'] ?? 'unknown',
                'eol_date' => $versionInfo['eol_date'] ?? null,
                'test_status' => $this->getVersionTestStatus($version, $currentVersionId, $versionId),
            ];
        }

        return [
            'current_php_version' => PHP_VERSION,
            'current_version_short' => $currentVersion,
            'current_version_id' => $currentVersionId,
            'supported_versions' => $this->supportedVersions,
            'matrix' => $matrix,
            'summary' => $this->generateMatrixCompatibilitySummary($matrix),
        ];
    }

    /**
     * Obtiene el estado de test para una versión específica.
     */
    private function getVersionTestStatus(string $version, int $currentVersionId, int $versionId): array
    {
        if ($currentVersionId >= $versionId) {
            return [
                'can_test' => true,
                'status' => 'testable',
                'message' => "Can test PHP {$version} features on current version",
            ];
        }

        return [
            'can_test' => false,
            'status' => 'not_testable',
            'message' => "Cannot test PHP {$version} features (requires newer PHP version)",
        ];
    }

    /**
     * Genera resumen de compatibilidad de matriz.
     */
    private function generateMatrixCompatibilitySummary(array $matrix): array
    {
        $testableVersions = 0;
        $supportedVersions = 0;
        $eolVersions = 0;
        $availableFeatures = [];

        foreach ($matrix as $info) {
            if ($info['test_status']['can_test']) {
                $testableVersions++;
            }

            if ($info['status'] === 'supported') {
                $supportedVersions++;
            }

            if ($info['eol_date']) {
                $eolDate = new DateTime($info['eol_date']);
                $now = new DateTime();

                if ($eolDate < $now) {
                    $eolVersions++;
                }
            }

            if ($info['is_available']) {
                $availableFeatures = array_merge($availableFeatures, $info['features']);
            }
        }

        return [
            'total_versions' => count($matrix),
            'testable_versions' => $testableVersions,
            'supported_versions' => $supportedVersions,
            'eol_versions' => $eolVersions,
            'available_features_count' => count(array_unique($availableFeatures)),
            'available_features' => array_unique($availableFeatures),
            'compatibility_score' => ($testableVersions / count($matrix)) * 100,
        ];
    }

    /**
     * Genera resumen de la matriz completa.
     */
    private function generateMatrixSummary(array $results): array
    {
        $totalTests = 0;
        $totalPassed = 0;
        $totalFailed = 0;
        $totalSkipped = 0;
        $totalTime = 0;

        foreach ($results as $result) {
            if ($result instanceof TestResult || $result instanceof Report) {
                if ($result instanceof TestResult) {
                    $totalTests += $result->total_tests;
                    $totalPassed += $result->passed_tests;
                    $totalFailed += $result->failed_tests;
                    $totalSkipped += $result->skipped_tests;
                    $totalTime += $result->execution_time;
                } elseif ($result instanceof Report) {
                    $summary = $result->summary;
                    $totalTests += $summary['total_tests'] ?? 0;
                    $totalPassed += $summary['passed_tests'] ?? 0;
                    $totalFailed += $summary['failed_tests'] ?? 0;
                    $totalSkipped += $summary['skipped_tests'] ?? 0;
                    $totalTime += $result->execution_time;
                }
            }
        }

        return [
            'total_tests' => $totalTests,
            'passed_tests' => $totalPassed,
            'failed_tests' => $totalFailed,
            'skipped_tests' => $totalSkipped,
            'success_rate' => $totalTests > 0 ? ($totalPassed / $totalTests) * 100 : 0,
            'total_execution_time' => $totalTime,
            'php_version' => PHP_VERSION,
            'overall_status' => $totalFailed === 0 ? 'pass' : 'fail',
            'matrix_type' => 'php_compatibility',
        ];
    }

    /**
     * Genera recomendaciones para la matriz.
     */
    private function generateMatrixRecommendations(array $results): array
    {
        $recommendations = [];
        $currentVersion = $this->detector->getCurrentVersion()['short_version'];

        // Recomendaciones basadas en la versión actual
        if (isset($results['compatibility_report']['matrix'][$currentVersion])) {
            $versionInfo = $results['compatibility_report']['matrix'][$currentVersion];

            if (isset($versionInfo['eol_date'])) {
                $eolDate = new DateTime($versionInfo['eol_date']);
                $now = new DateTime();
                $diff = $now->diff($eolDate);

                if ($eolDate < $now) {
                    $recommendations[] = [
                        'type' => 'error',
                        'message' => "PHP {$currentVersion} has reached end-of-life. Upgrade immediately for security updates.",
                    ];
                } elseif ($diff->days < 365) {
                    $recommendations[] = [
                        'type' => 'warning',
                        'message' => "PHP {$currentVersion} will reach end-of-life in {$diff->days} days. Plan for upgrade.",
                    ];
                }
            }
        }

        // Recomendaciones sobre versiones más nuevas
        $newerVersions = array_filter($this->supportedVersions, static fn($version): bool|int => version_compare(
            $version,
            $currentVersion,
            '>',
        ));

        if ($newerVersions !== []) {
            $latestVersion = max($newerVersions);
            $recommendations[] = [
                'type' => 'info',
                'message' => "Consider upgrading to PHP {$latestVersion} for latest features and performance improvements.",
            ];
        }

        // Recomendaciones basadas en fallos de tests
        if (isset($results['current_version_tests']) && $results['current_version_tests'] instanceof Report) {
            $failedTests = $results['current_version_tests']->getFailedTests();

            if ($failedTests > 0) {
                $recommendations[] = [
                    'type' => 'error',
                    'message' => "There are {$failedTests} failing tests on PHP {$currentVersion}. Review and fix before deployment.",
                ];
            }
        }

        return $recommendations;
    }

    /**
     * Genera HTML específico para la matriz.
     */
    private function generateMatrixHtml(Report $report): string
    {
        $html = "<!DOCTYPE html>\n<html>\n<head>\n";
        $html .= "<title>PHP Compatibility Matrix - {$report->php_version}</title>\n";
        $html .= "<style>\n";
        $html .= "body { font-family: Arial, sans-serif; margin: 20px; }\n";
        $html .= ".header { background: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 20px; }\n";
        $html .= ".matrix-table { width: 100%; border-collapse: collapse; margin: 20px 0; }\n";
        $html .= ".matrix-table th, .matrix-table td { border: 1px solid #ddd; padding: 12px; text-align: center; }\n";
        $html .= ".matrix-table th { background-color: #f2f2f2; font-weight: bold; }\n";
        $html .= ".current { background-color: #e8f5e8; font-weight: bold; }\n";
        $html .= ".testable { background-color: #f0f8ff; }\n";
        $html .= ".not-testable { background-color: #ffe4e1; }\n";
        $html .= ".eol { background-color: #ffebcd; }\n";
        $html .= ".pass { color: green; font-weight: bold; }\n";
        $html .= ".fail { color: red; font-weight: bold; }\n";
        $html .= ".warning { color: orange; font-weight: bold; }\n";
        $html .= ".info { color: blue; }\n";
        $html .= ".summary { background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 20px 0; }\n";
        $html .= ".features { margin: 10px 0; }\n";
        $html .= ".feature-tag { display: inline-block; background: #e1ecf4; padding: 2px 6px; margin: 2px; border-radius: 3px; font-size: 0.9em; }\n";
        $html .= "</style>\n";
        $html .= "</head>\n<body>\n";

        // Header
        $html .= "<div class='header'>\n";
        $html .= "<h1>PHP Compatibility Matrix</h1>\n";
        $html .= "<p><strong>Current PHP Version:</strong> {$report->php_version}</p>\n";
        $html .= "<p><strong>Generated:</strong> {$report->timestamp->format('Y-m-d H:i:s')}</p>\n";
        $html .= '<p><strong>Execution Time:</strong> ' . number_format($report->execution_time, 2) . "s</p>\n";
        $html .= "</div>\n";

        // Summary
        $summary = $report->summary;
        $html .= "<div class='summary'>\n";
        $html .= "<h2>Summary</h2>\n";
        $html .= "<p><strong>Total Tests:</strong> {$summary['total_tests']}</p>\n";
        $html .= "<p><strong>Passed:</strong> <span class='pass'>{$summary['passed_tests']}</span></p>\n";
        $html .= "<p><strong>Failed:</strong> <span class='fail'>{$summary['failed_tests']}</span></p>\n";
        $html .= '<p><strong>Success Rate:</strong> ' . number_format($summary['success_rate'], 1) . "%</p>\n";
        $html .=
            "<p><strong>Overall Status:</strong> <span class='{$summary['overall_status']}'>"
            . strtoupper($summary['overall_status'])
            . "</span></p>\n";
        $html .= "</div>\n";

        // Compatibility Matrix Table
        if (isset($report->results['compatibility_report']['matrix'])) {
            $matrix = $report->results['compatibility_report']['matrix'];

            $html .= "<h2>PHP Version Compatibility Matrix</h2>\n";
            $html .= "<table class='matrix-table'>\n";
            $html .= "<thead>\n<tr>\n";
            $html .= "<th>PHP Version</th>\n";
            $html .= "<th>Status</th>\n";
            $html .= "<th>Test Status</th>\n";
            $html .= "<th>EOL Date</th>\n";
            $html .= "<th>Features Count</th>\n";
            $html .= "<th>Available Features</th>\n";
            $html .= "</tr>\n</thead>\n<tbody>\n";

            foreach ($matrix as $version => $info) {
                $rowClass = '';

                if ($info['is_current']) {
                    $rowClass = 'current';
                } elseif ($info['test_status']['can_test']) {
                    $rowClass = 'testable';
                } else {
                    $rowClass = 'not-testable';
                }

                // Check if EOL
                if ($info['eol_date']) {
                    $eolDate = new DateTime($info['eol_date']);
                    $now = new DateTime();

                    if ($eolDate < $now) {
                        $rowClass .= ' eol';
                    }
                }

                $html .= "<tr class='{$rowClass}'>\n";
                $html .= "<td><strong>PHP {$version}</strong>" . ($info['is_current'] ? ' (Current)' : '') . "</td>\n";
                $html .= "<td>{$info['status']}</td>\n";
                $html .= "<td>{$info['test_status']['status']}</td>\n";
                $html .= "<td>{$info['eol_date']}</td>\n";
                $html .= '<td>' . count($info['features']) . "</td>\n";
                $html .= "<td><div class='features'>";

                foreach ($info['features'] as $feature) {
                    $html .= "<span class='feature-tag'>{$feature}</span>";
                }
                $html .= "</div></td>\n";
                $html .= "</tr>\n";
            }

            $html .= "</tbody>\n</table>\n";
        }

        // Recommendations
        if ($report->recommendations !== []) {
            $html .= "<h2>Recommendations</h2>\n<ul>\n";

            foreach ($report->recommendations as $recommendation) {
                $type = $recommendation['type'] ?? 'info';
                $message = htmlspecialchars($recommendation['message'] ?? '');
                $html .= "<li class='{$type}'><strong>" . strtoupper($type) . ":</strong> {$message}</li>\n";
            }
            $html .= "</ul>\n";
        }

        return $html . "</body>\n</html>";
    }
}
