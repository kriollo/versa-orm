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
use function is_string;
use function sprintf;

/**
 * Feature Coverage Analyzer for VersaORM.
 *
 * Analyzes code coverage by specific features and functionalities,
 * tracks coverage gaps, generates alerts for uncovered code,
 * and provides detailed insights for improving test coverage.
 */
class FeatureCoverageAnalyzer
{
    private TestLogger $logger;

    private array $config;

    private string $projectRoot;

    private array $featureDefinitions;

    public function __construct(array $config = [])
    {
        $this->logger = new TestLogger();
        $this->projectRoot = dirname(__DIR__, 2);
        $this->config = $this->loadConfiguration($config);
        $this->featureDefinitions = $this->config['feature_coverage'] ?? [];
    }

    /**
     * Analyze coverage by feature across all engines.
     */
    public function analyzeFeatureCoverage(): QualityResult
    {
        $this->logger->info('Starting feature coverage analysis');

        $engines = ['mysql', 'postgresql', 'sqlite'];
        $featureResults = [];
        $overallResults = [];
        $alerts = [];

        foreach ($this->featureDefinitions as $featureName => $featureConfig) {
            $this->logger->info("Analyzing coverage for feature: {$featureName}");

            $featureResult = $this->analyzeFeatureAcrossEngines($featureName, $featureConfig, $engines);
            $featureResults[$featureName] = $featureResult;

            // Check if feature meets minimum coverage
            if ($featureResult['average_coverage'] < $featureConfig['minimum_coverage']) {
                $alerts[] = [
                    'type' => 'feature_coverage_gap',
                    'severity' => 'medium',
                    'feature' => $featureName,
                    'current_coverage' => $featureResult['average_coverage'],
                    'required_coverage' => $featureConfig['minimum_coverage'],
                    'gap' => $featureConfig['minimum_coverage'] - $featureResult['average_coverage'],
                    'message' => "Feature {$featureName} has coverage gap: {$featureResult['average_coverage']}% (required: {$featureConfig['minimum_coverage']}%)",
                ];
            }
        }

        // Calculate overall feature coverage metrics
        $overallResults = $this->calculateOverallFeatureMetrics($featureResults);

        // Generate feature coverage gaps report
        $gapsReport = $this->generateFeatureCoverageGapsReport();

        // Determine if analysis passed
        $passed = $alerts === [] && $overallResults['features_meeting_threshold'] >= count($this->featureDefinitions) * 0.8;

        $result = new QualityResult(
            tool: 'feature-coverage',
            score: (int) $overallResults['average_coverage'],
            issues: array_column($alerts, 'message'),
            metrics: [
                'feature_results' => $featureResults,
                'overall_results' => $overallResults,
                'gaps_report' => $gapsReport,
                'alerts' => $alerts,
                'features_analyzed' => count($this->featureDefinitions),
                'features_meeting_threshold' => $overallResults['features_meeting_threshold'],
            ],
            passed: $passed,
            output: json_encode($featureResults, JSON_PRETTY_PRINT),
            timestamp: new DateTime(),
        );

        $this->logger->info('Feature coverage analysis completed');

        return $result;
    }

    /**
     * Track coverage for a specific feature.
     */
    public function trackFeatureCoverage(string $featureName): array
    {
        if (! isset($this->featureDefinitions[$featureName])) {
            throw new Exception("Feature '{$featureName}' not defined in configuration");
        }

        $featureConfig = $this->featureDefinitions[$featureName];
        $engines = ['mysql', 'postgresql', 'sqlite'];

        return $this->analyzeFeatureAcrossEngines($featureName, $featureConfig, $engines);
    }

    /**
     * Generate coverage gaps report by feature.
     */
    public function generateFeatureCoverageGapsReport(): array
    {
        $this->logger->info('Generating feature coverage gaps report');

        $gaps = [];
        $recommendations = [];

        foreach ($this->featureDefinitions as $featureName => $featureConfig) {
            $featureResult = $this->trackFeatureCoverage($featureName);

            if ($featureResult['average_coverage'] < $featureConfig['minimum_coverage']) {
                $gap = [
                    'feature' => $featureName,
                    'description' => $featureConfig['description'],
                    'current_coverage' => $featureResult['average_coverage'],
                    'required_coverage' => $featureConfig['minimum_coverage'],
                    'gap_percentage' => $featureConfig['minimum_coverage'] - $featureResult['average_coverage'],
                    'engines_with_gaps' => [],
                    'test_files' => $featureConfig['test_files'] ?? [],
                ];

                // Identify engines with gaps
                foreach ($featureResult['engine_results'] as $engine => $engineResult) {
                    if ($engineResult['coverage'] < $featureConfig['minimum_coverage']) {
                        $gap['engines_with_gaps'][] = [
                            'engine' => $engine,
                            'coverage' => $engineResult['coverage'],
                            'gap' => $featureConfig['minimum_coverage'] - $engineResult['coverage'],
                        ];
                    }
                }

                $gaps[] = $gap;

                // Generate recommendations
                $recommendations[] = $this->generateFeatureRecommendation($featureName, $gap);
            }
        }

        // Sort gaps by severity (largest gap first)
        usort($gaps, static fn ($a, $b): int => $b['gap_percentage'] <=> $a['gap_percentage']);

        $report = [
            'timestamp' => date('Y-m-d H:i:s'),
            'total_features' => count($this->featureDefinitions),
            'features_with_gaps' => count($gaps),
            'gaps' => $gaps,
            'recommendations' => $recommendations,
            'summary' => [
                'worst_gap' => $gaps === [] ? 0 : max(array_column($gaps, 'gap_percentage')),
                'average_gap' => $gaps === [] ? 0 : array_sum(array_column($gaps, 'gap_percentage')) / count($gaps),
                'features_needing_attention' => count($gaps),
            ],
        ];

        // Save report
        $reportPath = "{$this->projectRoot}/tests/reports/coverage/feature-gaps-report.json";
        file_put_contents($reportPath, json_encode($report, JSON_PRETTY_PRINT));

        return $report;
    }

    /**
     * Generate alerts for uncovered features.
     */
    public function generateFeatureCoverageAlerts(): array
    {
        $alerts = [];

        foreach ($this->featureDefinitions as $featureName => $featureConfig) {
            try {
                $featureResult = $this->trackFeatureCoverage($featureName);

                // Check overall feature coverage
                if ($featureResult['average_coverage'] < $featureConfig['minimum_coverage']) {
                    $severity = $this->determineSeverity($featureResult['average_coverage'], $featureConfig['minimum_coverage']);

                    $alerts[] = [
                        'type' => 'feature_coverage_below_threshold',
                        'severity' => $severity,
                        'feature' => $featureName,
                        'current_coverage' => $featureResult['average_coverage'],
                        'required_coverage' => $featureConfig['minimum_coverage'],
                        'gap' => $featureConfig['minimum_coverage'] - $featureResult['average_coverage'],
                        'engines_affected' => array_keys($featureResult['engine_results']),
                        'message' => "Feature '{$featureName}' coverage ({$featureResult['average_coverage']}%) is below threshold ({$featureConfig['minimum_coverage']}%)",
                    ];
                }

                // Check engine-specific coverage
                foreach ($featureResult['engine_results'] as $engine => $engineResult) {
                    if ($engineResult['coverage'] < $featureConfig['minimum_coverage'] * 0.8) { // 80% of minimum
                        $alerts[] = [
                            'type' => 'engine_feature_coverage_critical',
                            'severity' => 'high',
                            'feature' => $featureName,
                            'engine' => $engine,
                            'current_coverage' => $engineResult['coverage'],
                            'required_coverage' => $featureConfig['minimum_coverage'],
                            'message' => "Feature '{$featureName}' has critically low coverage in {$engine}: {$engineResult['coverage']}%",
                        ];
                    }
                }

                // Check for missing test files
                $missingTestFiles = $this->findMissingTestFiles($featureConfig['test_files'] ?? []);

                if ($missingTestFiles !== []) {
                    $alerts[] = [
                        'type' => 'missing_test_files',
                        'severity' => 'medium',
                        'feature' => $featureName,
                        'missing_files' => $missingTestFiles,
                        'message' => "Feature '{$featureName}' has missing test files: " . implode(', ', $missingTestFiles),
                    ];
                }
            } catch (Exception $e) {
                $alerts[] = [
                    'type' => 'feature_analysis_error',
                    'severity' => 'high',
                    'feature' => $featureName,
                    'error' => $e->getMessage(),
                    'message' => "Failed to analyze coverage for feature '{$featureName}': " . $e->getMessage(),
                ];
            }
        }

        return $alerts;
    }

    /**
     * Analyze feature coverage across multiple engines.
     */
    private function analyzeFeatureAcrossEngines(string $featureName, array $featureConfig, array $engines): array
    {
        $engineResults = [];
        $totalCoverage = 0;
        $validEngines = 0;

        foreach ($engines as $engine) {
            try {
                $engineCoverage = $this->analyzeFeatureForEngine($featureName, $featureConfig, $engine);
                $engineResults[$engine] = $engineCoverage;

                if ($engineCoverage['coverage'] > 0) {
                    $totalCoverage += $engineCoverage['coverage'];
                    $validEngines++;
                }
            } catch (Exception $e) {
                $this->logger->warning("Failed to analyze feature '{$featureName}' for engine '{$engine}': " . $e->getMessage());
                $engineResults[$engine] = [
                    'coverage' => 0,
                    'error' => $e->getMessage(),
                    'test_files_found' => 0,
                    'lines_covered' => 0,
                    'total_lines' => 0,
                ];
            }
        }

        $averageCoverage = $validEngines > 0 ? $totalCoverage / $validEngines : 0;

        return [
            'feature' => $featureName,
            'description' => $featureConfig['description'],
            'minimum_required' => $featureConfig['minimum_coverage'],
            'average_coverage' => round($averageCoverage, 2),
            'engine_results' => $engineResults,
            'status' => $averageCoverage >= $featureConfig['minimum_coverage'] ? 'PASS' : 'FAIL',
            'engines_analyzed' => count($engines),
            'engines_passed' => count(array_filter($engineResults, static fn ($result): bool => $result['coverage'] >= $featureConfig['minimum_coverage'])),
        ];
    }

    /**
     * Analyze feature coverage for a specific engine.
     */
    private function analyzeFeatureForEngine(string $featureName, array $featureConfig, string $engine): array
    {
        $testFiles = $featureConfig['test_files'] ?? [];
        $engineTestFiles = $this->filterTestFilesForEngine($testFiles, $engine);

        if ($engineTestFiles === []) {
            return [
                'coverage' => 0,
                'test_files_found' => 0,
                'lines_covered' => 0,
                'total_lines' => 0,
                'note' => "No test files found for {$engine}",
            ];
        }

        // Get coverage data for the engine
        $coverageData = $this->getCoverageDataForEngine($engine);

        // Calculate feature-specific coverage
        $featureCoverage = $this->calculateFeatureCoverageFromData($coverageData, $featureName);

        return [
            'coverage' => $featureCoverage['coverage_percentage'],
            'test_files_found' => count($engineTestFiles),
            'lines_covered' => $featureCoverage['lines_covered'],
            'total_lines' => $featureCoverage['total_lines'],
            'test_files' => $engineTestFiles,
        ];
    }

    /**
     * Filter test files for specific engine.
     */
    private function filterTestFilesForEngine(array $testFiles, string $engine): array
    {
        $engineTestFiles = [];

        foreach ($testFiles as $testFile) {
            // Check if test file exists for this engine
            $engineSpecificFile = str_replace(['testMysql/', 'testPostgreSQL/', 'testSQLite/'], 'test' . ucfirst($engine) . '/', $testFile);

            // Handle PostgreSQL naming
            if ($engine === 'postgresql') {
                $engineSpecificFile = str_replace('testPostgresql/', 'testPostgreSQL/', $engineSpecificFile);
            }

            $fullPath = "{$this->projectRoot}/{$engineSpecificFile}";

            if (file_exists($fullPath)) {
                $engineTestFiles[] = $engineSpecificFile;
            }
        }

        return $engineTestFiles;
    }

    /**
     * Get coverage data for specific engine.
     */
    private function getCoverageDataForEngine(string $engine): array
    {
        $cloverFile = "{$this->projectRoot}/tests/reports/coverage/{$engine}/clover.xml";

        if (! file_exists($cloverFile)) {
            // Try to generate coverage if it doesn't exist
            $this->generateCoverageForEngine($engine);
        }

        if (! file_exists($cloverFile)) {
            throw new Exception("Coverage data not available for {$engine}");
        }

        $xml = simplexml_load_file($cloverFile);

        if ($xml === false) {
            throw new Exception("Failed to parse coverage data for {$engine}");
        }

        return $this->parseCoverageXml($xml);
    }

    /**
     * Generate coverage for specific engine.
     */
    private function generateCoverageForEngine(string $engine): void
    {
        $this->logger->info("Generating coverage data for {$engine}");

        $configFiles = [
            'mysql' => 'phpunit-mysql.xml',
            'postgresql' => 'phpunit-postgresql.xml',
            'sqlite' => 'phpunit-sqlite.xml',
        ];

        if (! isset($configFiles[$engine])) {
            throw new Exception("Unknown engine: {$engine}");
        }

        $configFile = "{$this->projectRoot}/{$configFiles[$engine]}";
        $phpunitBinary = $this->findPhpUnitBinary();

        $command = sprintf(
            '%s --configuration=%s --coverage-clover=%s --no-output 2>&1',
            $phpunitBinary,
            escapeshellarg($configFile),
            escapeshellarg("{$this->projectRoot}/tests/reports/coverage/{$engine}/clover.xml"),
        );

        exec($command, $output, $returnCode);

        if ($returnCode !== 0) {
            throw new Exception("Failed to generate coverage for {$engine}: " . implode("\n", $output));
        }
    }

    /**
     * Parse coverage XML data.
     */
    private function parseCoverageXml(SimpleXMLElement $xml): array
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

            $files[$fileName] = [
                'statements' => (int) $metrics['statements'],
                'coveredstatements' => (int) $metrics['coveredstatements'],
                'methods' => (int) $metrics['methods'],
                'coveredmethods' => (int) $metrics['coveredmethods'],
                'lines' => [],
            ];

            // Parse line coverage
            if (property_exists($file, 'line') && $file->line !== null) {
                foreach ($file->line as $line) {
                    $lineNum = (int) $line['num'];
                    $count = (int) $line['count'];
                    $files[$fileName]['lines'][$lineNum] = $count;
                }
            }
        }

        return $files;
    }

    /**
     * Calculate feature coverage from coverage data.
     */
    private function calculateFeatureCoverageFromData(array $coverageData, string $featureName): array
    {
        // This is a simplified approach - in a real implementation, you would
        // need to map test files to source code coverage more precisely

        $totalLines = 0;
        $coveredLines = 0;

        // Get all source files that might be related to this feature
        $relevantSourceFiles = $this->getRelevantSourceFilesForFeature($featureName);

        foreach ($relevantSourceFiles as $sourceFile) {
            $fullPath = "{$this->projectRoot}/{$sourceFile}";

            foreach ($coverageData as $coveredFile => $fileData) {
                if (str_contains($coveredFile, $sourceFile) || str_contains($sourceFile, basename($coveredFile))) {
                    $totalLines += $fileData['statements'];
                    $coveredLines += $fileData['coveredstatements'];
                    break;
                }
            }
        }

        $coveragePercentage = $totalLines > 0 ? ($coveredLines / $totalLines) * 100 : 0;

        return [
            'coverage_percentage' => round($coveragePercentage, 2),
            'total_lines' => $totalLines,
            'lines_covered' => $coveredLines,
            'relevant_files' => $relevantSourceFiles,
        ];
    }

    /**
     * Get relevant source files for a feature.
     */
    private function getRelevantSourceFilesForFeature(string $featureName): array
    {
        // Map features to source files
        $featureToSourceMap = [
            'crud_operations' => ['src/VersaORM.php', 'src/VersaModel.php'],
            'relationships' => ['src/VersaModel.php', 'src/Relations/'],
            'query_builder' => ['src/QueryBuilder.php'],
            'transactions' => ['src/VersaORM.php'],
            'security' => ['src/VersaORM.php', 'src/QueryBuilder.php', 'src/ErrorHandler.php'],
            'validation' => ['src/VersaModel.php', 'src/Traits/'],
            'type_mapping' => ['src/VersaORM.php', 'src/VersaModel.php'],
        ];

        return $featureToSourceMap[$featureName] ?? ['src/VersaORM.php'];
    }

    /**
     * Calculate overall feature metrics.
     */
    private function calculateOverallFeatureMetrics(array $featureResults): array
    {
        $totalFeatures = count($featureResults);
        $featuresMeetingThreshold = 0;
        $totalCoverage = 0;

        foreach ($featureResults as $result) {
            $totalCoverage += $result['average_coverage'];

            if ($result['status'] === 'PASS') {
                $featuresMeetingThreshold++;
            }
        }

        return [
            'total_features' => $totalFeatures,
            'features_meeting_threshold' => $featuresMeetingThreshold,
            'features_below_threshold' => $totalFeatures - $featuresMeetingThreshold,
            'average_coverage' => $totalFeatures > 0 ? round($totalCoverage / $totalFeatures, 2) : 0,
            'pass_rate' => $totalFeatures > 0 ? round(($featuresMeetingThreshold / $totalFeatures) * 100, 2) : 0,
        ];
    }

    /**
     * Generate recommendation for feature improvement.
     */
    private function generateFeatureRecommendation(string $featureName, array $gap): array
    {
        $priority = 'medium';
        $action = 'Add more test cases';

        if ($gap['gap_percentage'] > 20) {
            $priority = 'high';
            $action = 'Create comprehensive test suite';
        } elseif ($gap['gap_percentage'] > 10) {
            $priority = 'medium';
            $action = 'Add edge case tests';
        } else {
            $priority = 'low';
            $action = 'Add minor test cases';
        }

        return [
            'feature' => $featureName,
            'priority' => $priority,
            'action' => $action,
            'gap_percentage' => $gap['gap_percentage'],
            'engines_affected' => count($gap['engines_with_gaps']),
            'suggested_test_files' => $gap['test_files'],
            'reason' => "Feature coverage is {$gap['gap_percentage']}% below target",
        ];
    }

    /**
     * Determine alert severity based on coverage gap.
     */
    private function determineSeverity(float $currentCoverage, float $requiredCoverage): string
    {
        $gap = $requiredCoverage - $currentCoverage;

        if ($gap > 20) {
            return 'critical';
        }

        if ($gap > 10) {
            return 'high';
        }

        if ($gap > 5) {
            return 'medium';
        }

        return 'low';
    }

    /**
     * Find missing test files.
     */
    private function findMissingTestFiles(array $testFiles): array
    {
        $missing = [];

        foreach ($testFiles as $testFile) {
            $fullPath = "{$this->projectRoot}/{$testFile}";

            if (! file_exists($fullPath)) {
                $missing[] = $testFile;
            }
        }

        return $missing;
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
            if (file_exists($path) || (is_string($path) && $path === 'phpunit')) {
                return $path;
            }
        }

        throw new Exception('PHPUnit binary not found');
    }

    /**
     * Load configuration.
     */
    private function loadConfiguration(array $overrides = []): array
    {
        $configFile = "{$this->projectRoot}/tests/config/coverage-config.php";

        $config = file_exists($configFile) ? require $configFile : $this->getDefaultConfiguration();

        return array_merge($config, $overrides);
    }

    /**
     * Get default configuration.
     */
    private function getDefaultConfiguration(): array
    {
        return [
            'feature_coverage' => [
                'crud_operations' => [
                    'description' => 'Create, Read, Update, Delete operations',
                    'minimum_coverage' => 98.0,
                    'test_files' => [
                        'testMysql/VersaORMTest.php',
                        'testPostgreSQL/VersaORMTest.php',
                        'testSQLite/QueryBuilderTest.php',
                    ],
                ],
            ],
        ];
    }
}
