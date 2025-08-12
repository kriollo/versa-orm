<?php

declare(strict_types=1);

namespace VersaORM\Tests\Results;

use DateTime;

/**
 * Report - Representa un reporte completo de testing
 */
class Report
{
    public string $report_id;
    public string $test_type;
    public string $php_version;
    public array $results;
    public array $summary;
    public float $execution_time;
    public DateTime $timestamp;
    public array $recommendations;

    public function __construct(array $data)
    {
        $this->report_id = $data['report_id'] ?? uniqid('report_', true);
        $this->test_type = $data['test_type'] ?? 'unknown';
        $this->php_version = $data['php_version'] ?? PHP_VERSION;
        $this->results = $data['results'] ?? [];
        $this->summary = $data['summary'] ?? [];
        $this->execution_time = $data['execution_time'] ?? 0.0;
        $this->timestamp = $data['timestamp'] ?? new DateTime();
        $this->recommendations = $data['recommendations'] ?? [];
    }

    /**
     * Obtiene el estado general del reporte
     */
    public function getOverallStatus(): string
    {
        return $this->summary['overall_status'] ?? 'unknown';
    }

    /**
     * Verifica si el reporte es exitoso
     */
    public function isSuccessful(): bool
    {
        return $this->getOverallStatus() === 'pass';
    }

    /**
     * Obtiene el número total de tests
     */
    public function getTotalTests(): int
    {
        return $this->summary['total_tests'] ?? 0;
    }

    /**
     * Obtiene el número de tests que pasaron
     */
    public function getPassedTests(): int
    {
        return $this->summary['passed_tests'] ?? 0;
    }

    /**
     * Obtiene el número de tests que fallaron
     */
    public function getFailedTests(): int
    {
        return $this->summary['failed_tests'] ?? 0;
    }

    /**
     * Obtiene la tasa de éxito
     */
    public function getSuccessRate(): float
    {
        return $this->summary['success_rate'] ?? 0.0;
    }

    /**
     * Convierte a array
     */
    public function toArray(): array
    {
        return [
            'report_id' => $this->report_id,
            'test_type' => $this->test_type,
            'php_version' => $this->php_version,
            'results' => array_map(function ($result) {
                return $result instanceof TestResult ? $result->toArray() : $result;
            }, $this->results),
            'summary' => $this->summary,
            'execution_time' => $this->execution_time,
            'timestamp' => $this->timestamp->format('Y-m-d H:i:s'),
            'recommendations' => $this->recommendations,
            'overall_status' => $this->getOverallStatus(),
            'is_successful' => $this->isSuccessful(),
        ];
    }

    /**
     * Obtiene un resumen ejecutivo del reporte
     */
    public function getExecutiveSummary(): array
    {
        $totalTests = $this->getTotalTests();
        $passedTests = $this->getPassedTests();
        $failedTests = $this->getFailedTests();
        $successRate = $this->getSuccessRate();

        // Contar alertas críticas
        $criticalAlerts = 0;
        foreach ($this->recommendations as $recommendation) {
            if (is_array($recommendation) && isset($recommendation['level']) && $recommendation['level'] === 'error') {
                $criticalAlerts++;
            }
        }

        return [
            'overall_status' => $this->getOverallStatus(),
            'total_tests' => $totalTests,
            'passed_tests' => $passedTests,
            'failed_tests' => $failedTests,
            'success_rate' => $successRate,
            'execution_time' => $this->execution_time,
            'php_version' => $this->php_version,
            'test_type' => $this->test_type,
            'timestamp' => $this->timestamp->format('Y-m-d H:i:s'),
            'has_failures' => $failedTests > 0,
            'quality_score' => $this->getQualityScore(),
            'recommendations_count' => count($this->recommendations),
            'critical_alerts' => $criticalAlerts,
        ];
    }

    /**
     * Obtiene la puntuación de calidad si está disponible
     */
    public function getQualityScore(): ?int
    {
        if (isset($this->results['quality_analysis']) &&
            is_object($this->results['quality_analysis']) &&
            property_exists($this->results['quality_analysis'], 'score')) {
            return $this->results['quality_analysis']->score;
        }
        return null;
    }

    /**
     * Obtiene las recomendaciones del reporte
     */
    public function getRecommendations(): array
    {
        $recommendations = [];

        // Agregar recomendaciones del array de recomendaciones
        foreach ($this->recommendations as $recommendation) {
            if (is_array($recommendation) && isset($recommendation['message'])) {
                $recommendations[] = $recommendation['message'];
            } elseif (is_string($recommendation)) {
                $recommendations[] = $recommendation;
            }
        }

        // Agregar recomendaciones basadas en resultados de calidad
        if (isset($this->results['quality_analysis']) &&
            is_object($this->results['quality_analysis']) &&
            method_exists($this->results['quality_analysis'], 'getRecommendations')) {
            $qualityRecommendations = $this->results['quality_analysis']->getRecommendations();
            $recommendations = array_merge($recommendations, $qualityRecommendations);
        }

        return array_unique($recommendations);
    }

    /**
     * Convierte a JSON
     */
    public function toJson(): string
    {
        return json_encode($this->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    }

    /**
     * Guarda el reporte en un archivo
     */
    public function saveToFile(string $filepath): bool
    {
        $directory = dirname($filepath);
        if (!is_dir($directory)) {
            mkdir($directory, 0755, true);
        }

        return file_put_contents($filepath, $this->toJson()) !== false;
    }

    /**
     * Genera reporte HTML básico
     */
    public function toHtml(): string
    {
        $html = "<!DOCTYPE html>\n<html>\n<head>\n";
        $html .= "<title>PHP Compatibility Report - {$this->php_version}</title>\n";
        $html .= "<style>\n";
        $html .= "body { font-family: Arial, sans-serif; margin: 20px; }\n";
        $html .= ".header { background: #f5f5f5; padding: 20px; border-radius: 5px; }\n";
        $html .= ".summary { margin: 20px 0; }\n";
        $html .= ".pass { color: green; }\n";
        $html .= ".fail { color: red; }\n";
        $html .= ".warning { color: orange; }\n";
        $html .= ".info { color: blue; }\n";
        $html .= "table { border-collapse: collapse; width: 100%; }\n";
        $html .= "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n";
        $html .= "th { background-color: #f2f2f2; }\n";
        $html .= "</style>\n";
        $html .= "</head>\n<body>\n";

        // Header
        $html .= "<div class='header'>\n";
        $html .= "<h1>PHP Compatibility Report</h1>\n";
        $html .= "<p><strong>PHP Version:</strong> {$this->php_version}</p>\n";
        $html .= "<p><strong>Generated:</strong> {$this->timestamp->format('Y-m-d H:i:s')}</p>\n";
        $html .= "<p><strong>Execution Time:</strong> " . number_format($this->execution_time, 2) . "s</p>\n";
        $html .= "</div>\n";

        // Summary
        $html .= "<div class='summary'>\n";
        $html .= "<h2>Summary</h2>\n";
        $html .= "<p><strong>Total Tests:</strong> {$this->getTotalTests()}</p>\n";
        $html .= "<p><strong>Passed:</strong> <span class='pass'>{$this->getPassedTests()}</span></p>\n";
        $html .= "<p><strong>Failed:</strong> <span class='fail'>{$this->getFailedTests()}</span></p>\n";
        $html .= "<p><strong>Success Rate:</strong> " . number_format($this->getSuccessRate(), 1) . "%</p>\n";
        $html .= "<p><strong>Overall Status:</strong> <span class='{$this->getOverallStatus()}'>" .
                 strtoupper($this->getOverallStatus()) . "</span></p>\n";
        $html .= "</div>\n";

        // Results
        $html .= "<h2>Test Results</h2>\n";
        foreach ($this->results as $testType => $result) {
            if ($result instanceof TestResult) {
                $html .= "<h3>" . ucfirst(str_replace('_', ' ', $testType)) . "</h3>\n";
                $html .= "<p>Tests: {$result->total_tests}, ";
                $html .= "Passed: <span class='pass'>{$result->passed_tests}</span>, ";
                $html .= "Failed: <span class='fail'>{$result->failed_tests}</span></p>\n";

                if (!empty($result->failures)) {
                    $html .= "<h4>Failures:</h4>\n<ul>\n";
                    foreach ($result->failures as $failure) {
                        $html .= "<li class='fail'>{$failure['message']}</li>\n";
                    }
                    $html .= "</ul>\n";
                }
            }
        }

        // Recommendations
        if (!empty($this->recommendations)) {
            $html .= "<h2>Recommendations</h2>\n<ul>\n";
            foreach ($this->recommendations as $recommendation) {
                $type = $recommendation['type'] ?? 'info';
                $message = htmlspecialchars($recommendation['message'] ?? '');
                $html .= "<li class='{$type}'>{$message}</li>\n";
            }
            $html .= "</ul>\n";
        }

        $html .= "</body>\n</html>";
        return $html;
    }
}
