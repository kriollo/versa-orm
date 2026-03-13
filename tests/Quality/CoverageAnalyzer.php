<?php

declare(strict_types=1);

namespace VersaORM\Tests\Quality;

use DateTime;
use Exception;
use SimpleXMLElement;
use VersaORM\Tests\Logging\TestLogger;
use VersaORM\Tests\Results\QualityResult;

use function count;
use function dirname;
use function in_array;
use function is_string;
use function sprintf;

/**
 * Coverage Analyzer for VersaORM.
 *
 * Handles code coverage analysis with PHrates reports,
 * validates minimum coverage thresholds, and provides detailed
 * coverage metrics by database engine and functionality.
 */
class CoverageAnalyzer
{
    private TestLogger $logger;

    private array $config;

    private string $projectRoot;

    private float $minimumCoverage;

    public function __construct(array $config = [])
    {
        $this->logger = new TestLogger();
        $this->config = array_merge($this->getDefaultConfig(), $config);
        $this->projectRoot = dirname(__DIR__, 2);
        $this->minimumCoverage = $this->config['minimum_coverage'] ?? 95.0;
    }

    /**
     * Run coverage analysis for all database engines.
     */
    public function runFullCoverageAnalysis(): QualityResult
    {
        $this->logger->info('Starting full coverage analysis');

        $engines = ['mysql', 'postgresql', 'sqlite'];
        $results = [];
        $overallCoverage = 0.0;
        $totalLines = 0;
        $coveredLines = 0;

        foreach ($engines as $engine) {
            try {
                $engineResult = $this->runCoverageForEngine($engine);
                $results[$engine] = $engineResult;

                // Aggregate coverage data
                if (isset($engineResult['coverage_data'])) {
                    $totalLines += $engineResult['coverage_data']['total_lines'] ?? 0;
                    $coveredLines += $engineResult['coverage_data']['covered_lines'] ?? 0;
                }
            } catch (Exception $e) {
                $this->logger->error("Coverage analysis failed for {$engine}: " . $e->getMessage());
                $results[$engine] = [
                    'success' => false,
                    'error' => $e->getMessage(),
                    'coverage_percentage' => 0.0,
                ];
            }
        }

        $overallCoverage = $totalLines > 0 ? ($coveredLines / $totalLines) * 100 : 0.0;

        // Generate consolidated report
        $consolidatedReport = $this->generateConsolidatedReport($results, $overallCoverage);

        // Validate coverage threshold
        $passed = $overallCoverage >= $this->minimumCoverage;

        $result = new QualityResult(
            tool: 'coverage',
            score: (int) $overallCoverage,
            issues: $passed ? [] : ["Coverage {$overallCoverage}% is below minimum {$this->minimumCoverage}%"],
            metrics: [
                'overall_coverage' => $overallCoverage,
                'minimum_required' => $this->minimumCoverage,
                'total_lines' => $totalLines,
                'covered_lines' => $coveredLines,
                'engine_results' => $results,
                'consolidated_report' => $consolidatedReport,
            ],
            passed: $passed,
            output: json_encode($results, JSON_PRETTY_PRINT),
            timestamp: new DateTime(),
        );

        $this->logger->info("Coverage analysis completed. Overall coverage: {$overallCoverage}%");

        return $result;
    }

    /**
     * Run coverage analysis for a specific database engine.
     */
    public function runCoverageForEngine(string $engine): array
    {
        $this->logger->info("Running coverage analysis for {$engine}");

        $configFile = $this->getPhpUnitConfigForEngine($engine);
        $reportsDir = "{$this->projectRoot}/tests/reports/coverage/{$engine}";

        // Ensure reports directory exists
        if (!is_dir($reportsDir)) {
            mkdir($reportsDir, 0o775, true);
        }

        // Run PHPUnit with coverage
        $command = $this->buildCoverageCommand($configFile, $engine);
        $output = [];
        $returnCode = 0;

        exec($command, $output, $returnCode);

        if ($returnCode !== 0) {
            throw new Exception("PHPUnit coverage failed for {$engine}: " . implode("\n", $output));
        }

        // Parse coverage results
        $coverageData = $this->parseCoverageResults($engine);

        return [
            'success' => true,
            'engine' => $engine,
            'coverage_percentage' => $coverageData['coverage_percentage'],
            'coverage_data' => $coverageData,
            'reports_generated' => $this->getGeneratedReports($engine),
            'command_output' => implode("\n", $output),
        ];
    }

    /**
     * Generate coverage gaps report.
     */
    public function generateCoverageGapsReport(): array
    {
        $this->logger->info('Generating coverage gaps report');

        $gaps = [];
        $engines = ['mysql', 'postgresql', 'sqlite'];

        foreach ($engines as $engine) {
            $engineGaps = $this->findCoverageGapsForEngine($engine);

            if ($engineGaps !== []) {
                $gaps[$engine] = $engineGaps;
            }
        }

        // Generate consolidated gaps report
        $consolidatedGaps = $this->consolidateCoverageGaps($gaps);

        // Save gaps report
        $gapsReportPath = "{$this->projectRoot}/tests/reports/coverage/gaps-report.json";
        file_put_contents($gapsReportPath, json_encode([
            'timestamp' => date('Y-m-d H:i:s'),
            'gaps_by_engine' => $gaps,
            'consolidated_gaps' => $consolidatedGaps,
            'recommendations' => $this->generateCoverageRecommendations($consolidatedGaps),
        ], JSON_PRETTY_PRINT));

        return [
            'gaps_by_engine' => $gaps,
            'consolidated_gaps' => $consolidatedGaps,
            'report_path' => $gapsReportPath,
        ];
    }

    /**
     * Validate minimum coverage threshold.
     */
    public function validateCoverageThreshold(float $coverage): array
    {
        $passed = $coverage >= $this->minimumCoverage;

        return [
            'passed' => $passed,
            'current_coverage' => $coverage,
            'minimum_required' => $this->minimumCoverage,
            'difference' => $coverage - $this->minimumCoverage,
            'status' => $passed ? 'PASS' : 'FAIL',
        ];
    }

    /**
     * Generate alerts for uncovered code.
     */
    public function generateCoverageAlerts(): array
    {
        $alerts = [];
        $engines = ['mysql', 'postgresql', 'sqlite'];

        foreach ($engines as $engine) {
            try {
                $coverageData = $this->parseCoverageResults($engine);

                if ($coverageData['coverage_percentage'] < $this->minimumCoverage) {
                    $alerts[] = [
                        'type' => 'coverage_below_threshold',
                        'severity' => 'high',
                        'engine' => $engine,
                        'current_coverage' => $coverageData['coverage_percentage'],
                        'minimum_required' => $this->minimumCoverage,
                        'message' => "Coverage for {$engine} ({$coverageData['coverage_percentage']}%) is below minimum threshold ({$this->minimumCoverage}%)",
                    ];
                }

                // Check for critical uncovered files
                $criticalUncovered = $this->findCriticalUncoveredFiles($engine);

                if ($criticalUncovered !== []) {
                    $alerts[] = [
                        'type' => 'critical_files_uncovered',
                        'severity' => 'critical',
                        'engine' => $engine,
                        'files' => $criticalUncovered,
                        'message' => "Critical files have insufficient coverage in {$engine}",
                    ];
                }
            } catch (Exception $e) {
                $alerts[] = [
                    'type' => 'coverage_analysis_error',
                    'severity' => 'high',
                    'engine' => $engine,
                    'error' => $e->getMessage(),
                    'message' => "Failed to analyze coverage for {$engine}",
                ];
            }
        }

        return $alerts;
    }

    /**
     * Build PHPUnit command for coverage analysis.
     */
    private function buildCoverageCommand(string $configFile, string $engine): string
    {
        $phpunitBinary = $this->findPhpUnitBinary();

        return sprintf(
            '%s --configuration=%s --coverage-html=%s --coverage-xml=%s --coverage-clover=%s --coverage-text=%s 2>&1',
            $phpunitBinary,
            escapeshellarg($configFile),
            escapeshellarg("{$this->projectRoot}/tests/reports/coverage/{$engine}/html"),
            escapeshellarg("{$this->projectRoot}/tests/reports/coverage/{$engine}/xml"),
            escapeshellarg("{$this->projectRoot}/tests/reports/coverage/{$engine}/clover.xml"),
            escapeshellarg("{$this->projectRoot}/tests/reports/coverage/{$engine}/coverage.txt"),
        );
    }

    /**
     * Parse coverage results from generated reports.
     */
    private function parseCoverageResults(string $engine): array
    {
        $cloverFile = "{$this->projectRoot}/tests/reports/coverage/{$engine}/clover.xml";

        if (!file_exists($cloverFile)) {
            throw new Exception("Clover coverage file not found for {$engine}");
        }

        $xml = simplexml_load_file($cloverFile);

        if ($xml === false) {
            throw new Exception("Failed to parse clover coverage file for {$engine}");
        }

        // Try to get metrics from project level first
        $totalLines = 0;
        $coveredLines = 0;
        $filesAnalyzed = 0;
        $classesAnalyzed = 0;
        $methodsAnalyzed = 0;
        $coveredMethods = 0;

        if (isset($xml->project->metrics)) {
            $metrics = $xml->project->metrics;
            $totalLines = (int) $metrics['statements'];
            $coveredLines = (int) $metrics['coveredstatements'];
            $filesAnalyzed = (int) $metrics['files'];
            $classesAnalyzed = (int) $metrics['classes'];
            $methodsAnalyzed = (int) $metrics['methods'];
            $coveredMethods = (int) $metrics['coveredmethods'];
        } else {
            // Calculate metrics by aggregating file data
            foreach ($xml->project->file as $file) {
                $filesAnalyzed++;

                if (property_exists($file, 'class') && $file->class !== null) {
                    foreach ($file->class as $class) {
                        $classesAnalyzed++;

                        if (property_exists($class, 'metrics') && $class->metrics !== null) {
                            $classMetrics = $class->metrics;
                            $totalLines += (int) $classMetrics['statements'];
                            $coveredLines += (int) $classMetrics['coveredstatements'];
                            $methodsAnalyzed += (int) $classMetrics['methods'];
                            $coveredMethods += (int) $classMetrics['coveredmethods'];
                        }
                    }
                }
            }
        }

        $coveragePercentage = $totalLines > 0 ? ($coveredLines / $totalLines) * 100 : 0.0;

        return [
            'coverage_percentage' => round($coveragePercentage, 2),
            'total_lines' => $totalLines,
            'covered_lines' => $coveredLines,
            'uncovered_lines' => $totalLines - $coveredLines,
            'files_analyzed' => $filesAnalyzed,
            'classes_analyzed' => $classesAnalyzed,
            'methods_analyzed' => $methodsAnalyzed,
            'covered_methods' => $coveredMethods,
            'file_details' => $this->parseFileDetails($xml),
        ];
    }

    /**
     * Parse file-level coverage details.
     */
    private function parseFileDetails(SimpleXMLElement $xml): array
    {
        $files = [];

        // Handle different XML structures - some have package, some don't
        $fileElements = null;

        if (property_exists($xml->project->package, 'file') && $xml->project->package->file !== null) {
            $fileElements = $xml->project->package->file;
        } elseif (isset($xml->project->file)) {
            $fileElements = $xml->project->file;
        }

        if ($fileElements === null) {
            return $files;
        }

        foreach ($fileElements as $file) {
            $fileName = (string) $file['name'];

            // Get metrics from class or file level
            $metrics = null;

            if (property_exists($file, 'metrics') && $file->metrics !== null) {
                $metrics = $file->metrics;
            } elseif (isset($file->class->metrics)) {
                $metrics = $file->class->metrics;
            }

            if ($metrics === null) {
                continue;
            }

            $totalLines = (int) $metrics['statements'];
            $coveredLines = (int) $metrics['coveredstatements'];
            $coverage = $totalLines > 0 ? ($coveredLines / $totalLines) * 100 : 0.0;

            $files[] = [
                'name' => $fileName,
                'coverage_percentage' => round($coverage, 2),
                'total_lines' => $totalLines,
                'covered_lines' => $coveredLines,
                'uncovered_lines' => $totalLines - $coveredLines,
            ];
        }

        return $files;
    }

    /**
     * Find coverage gaps for a specific engine.
     */
    private function findCoverageGapsForEngine(string $engine): array
    {
        try {
            $coverageData = $this->parseCoverageResults($engine);
            $gaps = [];

            foreach ($coverageData['file_details'] as $file) {
                if ($file['coverage_percentage'] >= $this->minimumCoverage) {
                    continue;
                }

                $gaps[] = [
                    'file' => $file['name'],
                    'current_coverage' => $file['coverage_percentage'],
                    'gap' => $this->minimumCoverage - $file['coverage_percentage'],
                    'uncovered_lines' => $file['uncovered_lines'],
                ];
            }

            return $gaps;
        } catch (Exception $e) {
            $this->logger->error("Failed to find coverage gaps for {$engine}: " . $e->getMessage());

            return [];
        }
    }

    /**
     * Consolidate coverage gaps across engines.
     */
    private function consolidateCoverageGaps(array $gapsByEngine): array
    {
        $consolidated = [];

        foreach ($gapsByEngine as $engine => $gaps) {
            foreach ($gaps as $gap) {
                $fileName = $gap['file'];

                if (!isset($consolidated[$fileName])) {
                    $consolidated[$fileName] = [
                        'file' => $fileName,
                        'engines' => [],
                        'worst_coverage' => 100.0,
                        'average_coverage' => 0.0,
                    ];
                }

                $consolidated[$fileName]['engines'][$engine] = [
                    'coverage' => $gap['current_coverage'],
                    'gap' => $gap['gap'],
                    'uncovered_lines' => $gap['uncovered_lines'],
                ];

                $consolidated[$fileName]['worst_coverage'] = min(
                    $consolidated[$fileName]['worst_coverage'],
                    $gap['current_coverage'],
                );
            }
        }

        // Calculate average coverage for each file
        foreach ($consolidated as &$fileData) {
            $totalCoverage = 0;
            $engineCount = count($fileData['engines']);

            foreach ($fileData['engines'] as $engineData) {
                $totalCoverage += $engineData['coverage'];
            }

            $fileData['average_coverage'] = $engineCount > 0 ? $totalCoverage / $engineCount : 0.0;
        }

        // Sort by worst coverage
        uasort($consolidated, static fn($a, $b): int => $a['worst_coverage'] <=> $b['worst_coverage']);

        return array_values($consolidated);
    }

    /**
     * Generate coverage improvement recommendations.
     */
    private function generateCoverageRecommendations(array $consolidatedGaps): array
    {
        $recommendations = [];

        foreach ($consolidatedGaps as $gap) {
            if ($gap['worst_coverage'] < 50.0) {
                $recommendations[] = [
                    'priority' => 'high',
                    'file' => $gap['file'],
                    'action' => 'Create comprehensive test suite',
                    'reason' => "Coverage is critically low ({$gap['worst_coverage']}%)",
                ];
            } elseif ($gap['worst_coverage'] < 80.0) {
                $recommendations[] = [
                    'priority' => 'medium',
                    'file' => $gap['file'],
                    'action' => 'Add edge case tests',
                    'reason' => "Coverage needs improvement ({$gap['worst_coverage']}%)",
                ];
            } else {
                $recommendations[] = [
                    'priority' => 'low',
                    'file' => $gap['file'],
                    'action' => 'Add minor test cases',
                    'reason' => "Coverage is close to target ({$gap['worst_coverage']}%)",
                ];
            }
        }

        return $recommendations;
    }

    /**
     * Find critical uncovered files.
     */
    private function findCriticalUncoveredFiles(string $engine): array
    {
        $criticalFiles = [
            'src/VersaORM.php',
            'src/VersaModel.php',
            'src/QueryBuilder.php',
            'src/ErrorHandler.php',
        ];

        $uncovered = [];

        try {
            $coverageData = $this->parseCoverageResults($engine);

            foreach ($coverageData['file_details'] as $file) {
                $relativePath = str_replace($this->projectRoot . '/', '', $file['name']);

                if (in_array($relativePath, $criticalFiles, true) && $file['coverage_percentage'] < 90.0) {
                    $uncovered[] = [
                        'file' => $relativePath,
                        'coverage' => $file['coverage_percentage'],
                        'severity' => $file['coverage_percentage'] < 50.0 ? 'critical' : 'high',
                    ];
                }
            }
        } catch (Exception $e) {
            $this->logger->error("Failed to find critical uncovered files for {$engine}: " . $e->getMessage());
        }

        return $uncovered;
    }

    /**
     * Generate consolidated coverage report.
     */
    private function generateConsolidatedReport(array $results, float $overallCoverage): array
    {
        $report = [
            'timestamp' => date('Y-m-d H:i:s'),
            'overall_coverage' => $overallCoverage,
            'minimum_required' => $this->minimumCoverage,
            'status' => $overallCoverage >= $this->minimumCoverage ? 'PASS' : 'FAIL',
            'engines' => [],
        ];

        foreach ($results as $engine => $result) {
            if ($result['success']) {
                $report['engines'][$engine] = [
                    'coverage_percentage' => $result['coverage_percentage'],
                    'status' => $result['coverage_percentage'] >= $this->minimumCoverage ? 'PASS' : 'FAIL',
                    'total_lines' => $result['coverage_data']['total_lines'] ?? 0,
                    'covered_lines' => $result['coverage_data']['covered_lines'] ?? 0,
                    'files_analyzed' => $result['coverage_data']['files_analyzed'] ?? 0,
                ];
            } else {
                $report['engines'][$engine] = [
                    'status' => 'ERROR',
                    'error' => $result['error'],
                ];
            }
        }

        return $report;
    }

    /**
     * Get PHPUnit configuration file for engine.
     */
    private function getPhpUnitConfigForEngine(string $engine): string
    {
        $configFiles = [
            'mysql' => 'phpunit-mysql.xml',
            'postgresql' => 'phpunit-postgresql.xml',
            'sqlite' => 'phpunit-sqlite.xml',
        ];

        if (!isset($configFiles[$engine])) {
            throw new Exception("Unknown database engine: {$engine}");
        }

        $configFile = "{$this->projectRoot}/{$configFiles[$engine]}";

        if (!file_exists($configFile)) {
            throw new Exception("PHPUnit configuration file not found: {$configFile}");
        }

        return $configFile;
    }

    /**
     * Find PHPUnit binary.
     */
    private function findPhpUnitBinary(): string
    {
        $possiblePaths = [
            "{$this->projectRoot}/vendor/bin/phpunit",
            "{$this->projectRoot}/vendor/bin/phpunit.bat",
            'phpunit',
        ];

        foreach ($possiblePaths as $path) {
            if (!(file_exists($path) || is_string($path) && $path === 'phpunit')) {
                continue;
            }

            return $path;
        }

        throw new Exception('PHPUnit binary not found');
    }

    /**
     * Get list of generated reports for an engine.
     */
    private function getGeneratedReports(string $engine): array
    {
        $reportsDir = "{$this->projectRoot}/tests/reports/coverage/{$engine}";
        $reports = [];

        $expectedReports = [
            'html' => "{$reportsDir}/html/index.html",
            'xml' => "{$reportsDir}/xml/index.xml",
            'clover' => "{$reportsDir}/clover.xml",
            'text' => "{$reportsDir}/coverage.txt",
        ];

        foreach ($expectedReports as $type => $path) {
            $reports[$type] = [
                'path' => $path,
                'exists' => file_exists($path),
                'size' => file_exists($path) ? filesize($path) : 0,
            ];
        }

        return $reports;
    }

    /**
     * Get default configuration.
     */
    private function getDefaultConfig(): array
    {
        return [
            'minimum_coverage' => 95.0,
            'critical_files' => [
                'src/VersaORM.php',
                'src/VersaModel.php',
                'src/QueryBuilder.php',
                'src/ErrorHandler.php',
            ],
            'exclude_patterns' => [
                '*/vendor/*',
                '*/tests/*',
                '*/example/*',
            ],
            'report_formats' => ['html', 'xml', 'clover', 'text'],
        ];
    }
}
