<?php

declare(strict_types=1);

namespace VersaORM\Tests\Results;

use DateTime;

use function count;
use function sprintf;

/**
 * Clase que representa el resultado de benchmarks de rendimiento.
 *
 * Contiene métricas de rendimiento, comparaciones con otros ORMs
 * y datos de análisis de performance.
 */
class BenchmarkResult
{
    private string $benchmarkName;

    private string $engine;

    private array $metrics;

    private array $comparisons;

    private array $dataPoints;

    private float $executionTime;

    private DateTime $timestamp;

    public function __construct(
        string $benchmarkName,
        string $engine,
        array $metrics,
        array $comparisons,
        array $dataPoints,
        float $executionTime,
        DateTime $timestamp,
    ) {
        $this->benchmarkName = $benchmarkName;
        $this->engine = $engine;
        $this->metrics = $metrics;
        $this->comparisons = $comparisons;
        $this->dataPoints = $dataPoints;
        $this->executionTime = $executionTime;
        $this->timestamp = $timestamp;
    }

    /**
     * Obtiene el throughput en operaciones por segundo.
     */
    public function getThroughput(): float
    {
        return $this->metrics['throughput'] ?? 0.0;
    }

    /**
     * Obtiene la latencia promedio en segundos.
     */
    public function getLatency(): float
    {
        return $this->metrics['latency'] ?? 0.0;
    }

    /**
     * Obtiene el uso de memoria en bytes.
     */
    public function getMemoryUsage(): int
    {
        return $this->metrics['memory_usage'] ?? 0;
    }

    /**
     * Obtiene el uso de memoria formateado.
     */
    public function getFormattedMemoryUsage(): string
    {
        $bytes = $this->getMemoryUsage();
        $units = ['B', 'KB', 'MB', 'GB'];

        for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
            $bytes /= 1024;
        }

        return round($bytes, 2) . ' ' . $units[$i];
    }

    /**
     * Compara el rendimiento con otro ORM.
     */
    public function getComparisonWith(string $orm): ?array
    {
        return $this->comparisons[$orm] ?? null;
    }

    /**
     * Calcula el factor de mejora respecto a otro ORM.
     */
    public function getImprovementFactor(string $orm): ?float
    {
        $comparison = $this->getComparisonWith($orm);

        if ($comparison === null || $comparison === [] || ! isset($comparison['throughput'])) {
            return null;
        }

        $ourThroughput = $this->getThroughput();
        $theirThroughput = $comparison['throughput'];

        if ($theirThroughput === 0) {
            return null;
        }

        return $ourThroughput / $theirThroughput;
    }

    /**
     * Obtiene un resumen textual del benchmark.
     */
    public function getSummary(): string
    {
        return sprintf(
            '%s on %s: %.2f ops/sec, %.3fs latency, %s memory in %.3fs',
            $this->benchmarkName,
            $this->engine,
            $this->getThroughput(),
            $this->getLatency(),
            $this->getFormattedMemoryUsage(),
            $this->executionTime,
        );
    }

    /**
     * Convierte el resultado a array para serialización.
     */
    public function toArray(): array
    {
        return [
            'benchmark_name' => $this->benchmarkName,
            'engine' => $this->engine,
            'metrics' => $this->metrics,
            'comparisons' => $this->comparisons,
            'data_points' => $this->dataPoints,
            'execution_time' => $this->executionTime,
            'throughput' => $this->getThroughput(),
            'latency' => $this->getLatency(),
            'memory_usage' => $this->getMemoryUsage(),
            'formatted_memory' => $this->getFormattedMemoryUsage(),
            'timestamp' => $this->timestamp->format('Y-m-d H:i:s'),
        ];
    }
}
