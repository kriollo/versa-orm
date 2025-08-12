<?php

declare(strict_types=1);

namespace VersaORM\Tests\Metrics;

use DateTime;

/**
 * Sistema de recolección de métricas para el framework de testing
 *
 * Recolecta, almacena y analiza métricas de rendimiento, calidad y ejecución
 * del sistema de QA para generar insights y tendencias.
 */
class MetricsCollector
{
    private bool $enabled;
    private string $outputDir;
    private int $retentionDays;
    private array $metrics = [];
    private string $currentMetricsFile;

    public function __construct(array $config = [])
    {
        $this->enabled = $config['enabled'] ?? true;
        $this->outputDir = $config['output_dir'] ?? 'tests/metrics';
        $this->retentionDays = $config['retention_days'] ?? 30;

        if ($this->enabled) {
            $this->ensureMetricsDirectory();
            $this->currentMetricsFile = $this->getCurrentMetricsFile();
            $this->cleanupOldMetrics();
        }
    }

    /**
     * Registra el tiempo de ejecución de una operación
     */
    public function recordExecutionTime(string $operation, float $time): void
    {
        if (!$this->enabled) {
            return;
        }

        $this->recordMetric('execution_time', [
            'operation' => $operation,
            'time_seconds' => $time,
            'timestamp' => (new DateTime())->format('Y-m-d H:i:s.u')
        ]);
    }

    /**
     * Registra métricas de memoria
     */
    public function recordMemoryUsage(string $operation, int $peakMemory, int $currentMemory): void
    {
        if (!$this->enabled) {
            return;
        }

        $this->recordMetric('memory_usage', [
            'operation' => $operation,
            'peak_memory_bytes' => $peakMemory,
            'current_memory_bytes' => $currentMemory,
            'peak_memory_formatted' => $this->formatBytes($peakMemory),
            'current_memory_formatted' => $this->formatBytes($currentMemory),
            'timestamp' => (new DateTime())->format('Y-m-d H:i:s.u')
        ]);
    }

    /**
     * Registra métricas de tests
     */
    public function recordTestMetrics(string $testType, string $engine, array $metrics): void
    {
        if (!$this->enabled) {
            return;
        }

        $this->recordMetric('test_execution', [
            'test_type' => $testType,
            'engine' => $engine,
            'metrics' => $metrics,
            'timestamp' => (new DateTime())->format('Y-m-d H:i:s.u')
        ]);
    }

    /**
     * Registra métricas de calidad
     */
    public function recordQualityMetrics(string $tool, int $score, int $issueCount, array $details = []): void
    {
        if (!$this->enabled) {
            return;
        }

        $this->recordMetric('quality_analysis', [
            'tool' => $tool,
            'score' => $score,
            'issue_count' => $issueCount,
            'details' => $details,
            'timestamp' => (new DateTime())->format('Y-m-d H:i:s.u')
        ]);
    }

    /**
     * Registra métricas de benchmark
     */
    public function recordBenchmarkMetrics(string $benchmark, string $engine, array $metrics): void
    {
        if (!$this->enabled) {
            return;
        }

        $this->recordMetric('benchmark', [
            'benchmark_name' => $benchmark,
            'engine' => $engine,
            'metrics' => $metrics,
            'timestamp' => (new DateTime())->format('Y-m-d H:i:s.u')
        ]);
    }

    /**
     * Registra una métrica personalizada
     */
    public function recordCustomMetric(string $name, array $data): void
    {
        if (!$this->enabled) {
            return;
        }

        $this->recordMetric('custom', [
            'metric_name' => $name,
            'data' => $data,
            'timestamp' => (new DateTime())->format('Y-m-d H:i:s.u')
        ]);
    }

    /**
     * Método interno para registrar métricas
     */
    private function recordMetric(string $type, array $data): void
    {
        $metric = [
            'type' => $type,
            'data' => $data,
            'recorded_at' => (new DateTime())->format('Y-m-d H:i:s.u')
        ];

        $this->metrics[] = $metric;
        $this->persistMetric($metric);
    }

    /**
     * Persiste una métrica al archivo
     */
    private function persistMetric(array $metric): void
    {
        $jsonLine = json_encode($metric, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . PHP_EOL;
        file_put_contents($this->currentMetricsFile, $jsonLine, FILE_APPEND | LOCK_EX);
    }

    /**
     * Obtiene métricas por tipo y rango de fechas
     */
    public function getMetrics(string $type = null, DateTime $from = null, DateTime $to = null): array
    {
        if (!$this->enabled) {
            return [];
        }

        $allMetrics = $this->loadAllMetrics();

        return array_filter($allMetrics, function ($metric) use ($type, $from, $to) {
            // Filtrar por tipo
            if ($type && $metric['type'] !== $type) {
                return false;
            }

            // Filtrar por rango de fechas
            if ($from || $to) {
                $metricTime = new DateTime($metric['recorded_at']);

                if ($from && $metricTime < $from) {
                    return false;
                }

                if ($to && $metricTime > $to) {
                    return false;
                }
            }

            return true;
        });
    }

    /**
     * Obtiene estadísticas de rendimiento
     */
    public function getPerformanceStats(int $days = 7): array
    {
        $from = new DateTime("-{$days} days");
        $executionMetrics = $this->getMetrics('execution_time', $from);
        $memoryMetrics = $this->getMetrics('memory_usage', $from);

        $stats = [
            'period_days' => $days,
            'total_executions' => count($executionMetrics),
            'execution_times' => [],
            'memory_usage' => [],
            'operations' => []
        ];

        // Analizar tiempos de ejecución
        $executionTimes = array_map(fn($m) => $m['data']['time_seconds'], $executionMetrics);
        if (!empty($executionTimes)) {
            $stats['execution_times'] = [
                'min' => min($executionTimes),
                'max' => max($executionTimes),
                'avg' => array_sum($executionTimes) / count($executionTimes),
                'median' => $this->calculateMedian($executionTimes)
            ];
        }

        // Analizar uso de memoria
        $memoryUsages = array_map(fn($m) => $m['data']['peak_memory_bytes'], $memoryMetrics);
        if (!empty($memoryUsages)) {
            $stats['memory_usage'] = [
                'min_bytes' => min($memoryUsages),
                'max_bytes' => max($memoryUsages),
                'avg_bytes' => (int) (array_sum($memoryUsages) / count($memoryUsages)),
                'min_formatted' => $this->formatBytes(min($memoryUsages)),
                'max_formatted' => $this->formatBytes(max($memoryUsages)),
                'avg_formatted' => $this->formatBytes((int) (array_sum($memoryUsages) / count($memoryUsages)))
            ];
        }

        // Analizar operaciones más frecuentes
        $operations = array_count_values(array_map(fn($m) => $m['data']['operation'], $executionMetrics));
        arsort($operations);
        $stats['operations'] = array_slice($operations, 0, 10, true);

        return $stats;
    }

    /**
     * Obtiene tendencias de calidad
     */
    public function getQualityTrends(int $days = 30): array
    {
        $from = new DateTime("-{$days} days");
        $qualityMetrics = $this->getMetrics('quality_analysis', $from);

        $trends = [
            'period_days' => $days,
            'total_analyses' => count($qualityMetrics),
            'tools' => [],
            'score_trend' => [],
            'issue_trend' => []
        ];

        // Agrupar por herramienta
        $toolMetrics = [];
        foreach ($qualityMetrics as $metric) {
            $tool = $metric['data']['tool'];
            if (!isset($toolMetrics[$tool])) {
                $toolMetrics[$tool] = [];
            }
            $toolMetrics[$tool][] = $metric;
        }

        // Analizar cada herramienta
        foreach ($toolMetrics as $tool => $metrics) {
            $scores = array_map(fn($m) => $m['data']['score'], $metrics);
            $issues = array_map(fn($m) => $m['data']['issue_count'], $metrics);

            $trends['tools'][$tool] = [
                'total_runs' => count($metrics),
                'avg_score' => array_sum($scores) / count($scores),
                'min_score' => min($scores),
                'max_score' => max($scores),
                'avg_issues' => array_sum($issues) / count($issues),
                'min_issues' => min($issues),
                'max_issues' => max($issues)
            ];
        }

        return $trends;
    }

    /**
     * Genera un resumen de métricas
     */
    public function getSummary(): array
    {
        if (!$this->enabled) {
            return ['enabled' => false];
        }

        $allMetrics = $this->loadAllMetrics();
        $metricsByType = [];

        foreach ($allMetrics as $metric) {
            $type = $metric['type'];
            if (!isset($metricsByType[$type])) {
                $metricsByType[$type] = 0;
            }
            $metricsByType[$type]++;
        }

        return [
            'enabled' => true,
            'total_metrics' => count($allMetrics),
            'metrics_by_type' => $metricsByType,
            'current_file' => $this->currentMetricsFile,
            'output_directory' => $this->outputDir,
            'retention_days' => $this->retentionDays,
            'file_count' => count(glob($this->outputDir . '/metrics-*.jsonl'))
        ];
    }

    /**
     * Carga todas las métricas desde archivos
     */
    private function loadAllMetrics(): array
    {
        $allMetrics = [];
        $metricFiles = glob($this->outputDir . '/metrics-*.jsonl');

        foreach ($metricFiles as $file) {
            $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                $metric = json_decode($line, true);
                if ($metric) {
                    $allMetrics[] = $metric;
                }
            }
        }

        return $allMetrics;
    }

    /**
     * Asegura que el directorio de métricas existe
     */
    private function ensureMetricsDirectory(): void
    {
        if (!is_dir($this->outputDir)) {
            mkdir($this->outputDir, 0755, true);
        }
    }

    /**
     * Obtiene el archivo de métricas actual
     */
    private function getCurrentMetricsFile(): string
    {
        $date = date('Y-m-d');
        return $this->outputDir . "/metrics-{$date}.jsonl";
    }

    /**
     * Limpia métricas antiguas
     */
    private function cleanupOldMetrics(): void
    {
        $cutoffDate = new DateTime("-{$this->retentionDays} days");
        $metricFiles = glob($this->outputDir . '/metrics-*.jsonl');

        foreach ($metricFiles as $file) {
            $filename = basename($file);
            if (preg_match('/metrics-(\d{4}-\d{2}-\d{2})\.jsonl/', $filename, $matches)) {
                $fileDate = DateTime::createFromFormat('Y-m-d', $matches[1]);
                if ($fileDate && $fileDate < $cutoffDate) {
                    unlink($file);
                }
            }
        }
    }

    /**
     * Calcula la mediana de un array de números
     */
    private function calculateMedian(array $numbers): float
    {
        sort($numbers);
        $count = count($numbers);

        if ($count % 2 === 0) {
            return ($numbers[$count / 2 - 1] + $numbers[$count / 2]) / 2;
        } else {
            return $numbers[intval($count / 2)];
        }
    }

    /**
     * Formatea bytes en unidades legibles
     */
    private function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];

        for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
            $bytes /= 1024;
        }

        return round($bytes, 2) . ' ' . $units[$i];
    }

    /**
     * Exporta métricas a formato CSV
     */
    public function exportToCsv(string $type = null, DateTime $from = null, DateTime $to = null): string
    {
        $metrics = $this->getMetrics($type, $from, $to);

        if (empty($metrics)) {
            return '';
        }

        $csv = "type,recorded_at,data\n";
        foreach ($metrics as $metric) {
            $dataJson = json_encode($metric['data'], JSON_UNESCAPED_UNICODE);
            $csv .= "{$metric['type']},{$metric['recorded_at']},\"{$dataJson}\"\n";
        }

        return $csv;
    }
}
