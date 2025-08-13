<?php

declare(strict_types=1);

namespace VersaORM\Tests\Results;

use DateTime;

/**
 * TestResult - Representa el resultado de una ejecución de tests
 */
class TestResult
{
    public string $test_type;
    public string $engine;
    public int $total_tests;
    public int $passed_tests;
    public int $failed_tests;
    public int $skipped_tests;
    public float $execution_time;
    public array $failures;
    public array $metrics;
    public DateTime $timestamp;

    public function __construct(array $data)
    {
        $this->test_type = $data['test_type'] ?? 'unknown';
        $this->engine = $data['engine'] ?? 'unknown';
        $this->total_tests = $data['total_tests'] ?? 0;
        $this->passed_tests = $data['passed_tests'] ?? 0;
        $this->failed_tests = $data['failed_tests'] ?? 0;
        $this->skipped_tests = $data['skipped_tests'] ?? 0;
        $this->execution_time = $data['execution_time'] ?? 0.0;
        $this->failures = $data['failures'] ?? [];
        $this->metrics = $data['metrics'] ?? [];
        $this->timestamp = $data['timestamp'] ?? new DateTime();
    }

    /**
     * Obtiene la tasa de éxito
     */
    public function getSuccessRate(): float
    {
        if ($this->total_tests === 0) {
            return 0.0;
        }

        return ($this->passed_tests / $this->total_tests) * 100;
    }

    /**
     * Verifica si todos los tests pasaron
     */
    public function isSuccessful(): bool
    {
        return $this->failed_tests === 0 && $this->total_tests > 0;
    }

    /**
     * Obtiene un resumen legible del resultado
     */
    public function getSummary(): string
    {
        $status = $this->isSuccessful() ? '✅ EXITOSO' : '❌ FALLIDO';
        $successRate = number_format($this->getSuccessRate(), 2);

        $summary = "=== Resumen de Tests ({$this->engine}) ===\n";
        $summary .= "Estado: {$status}\n";
        $summary .= "Total: {$this->total_tests} | Exitosos: {$this->passed_tests} | Fallidos: {$this->failed_tests} | Omitidos: {$this->skipped_tests}\n";
        $summary .= "Tasa de éxito: {$successRate}%\n";
        $summary .= "Tiempo de ejecución: " . number_format($this->execution_time, 2) . "s\n";

        if (!empty($this->failures)) {
            $summary .= "\n⚠️  Fallas:\n";
            foreach ($this->failures as $failure) {
                if (is_string($failure)) {
                    $summary .= "- {$failure}\n";
                } elseif (is_array($failure) && isset($failure['message'])) {
                    $summary .= "- {$failure['message']}\n";
                }
            }
        }

        return $summary;
    }

    /**
     * Convierte a array
     */
    public function toArray(): array
    {
        return [
            'test_type' => $this->test_type,
            'engine' => $this->engine,
            'total_tests' => $this->total_tests,
            'passed_tests' => $this->passed_tests,
            'failed_tests' => $this->failed_tests,
            'skipped_tests' => $this->skipped_tests,
            'execution_time' => $this->execution_time,
            'success_rate' => $this->getSuccessRate(),
            'is_successful' => $this->isSuccessful(),
            'failures' => $this->failures,
            'metrics' => $this->metrics,
            'timestamp' => $this->timestamp->format('Y-m-d H:i:s'),
        ];
    }
}
