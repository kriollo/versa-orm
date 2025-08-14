<?php

declare(strict_types=1);

namespace VersaORM\Tests\Results;

use DateTime;

use function count;
use function is_array;
use function is_string;
use function sprintf;

/**
 * Clase que representa el resultado de análisis de calidad de código.
 *
 * Contiene información sobre herramientas de análisis estático,
 * puntuaciones de calidad, issues encontrados y métricas.
 */
class QualityResult
{
    public function __construct(public string $tool, public int $score, public array $issues, public array $metrics, public bool $passed, public string $output, public DateTime $timestamp)
    {
    }

    /**
     * Obtiene el nivel de calidad basado en la puntuación.
     */
    public function getQualityLevel(): string
    {
        if ($this->score >= 95) {
            return 'excellent';
        }

        if ($this->score >= 85) {
            return 'good';
        }

        if ($this->score >= 70) {
            return 'fair';
        }

        if ($this->score >= 50) {
            return 'poor';
        }

        return 'critical';
    }

    /**
     * Obtiene el número total de issues.
     */
    public function getIssueCount(): int
    {
        return count($this->issues);
    }

    /**
     * Determina si hay issues críticos.
     */
    public function hasCriticalIssues(): bool
    {
        foreach ($this->issues as $issue) {
            if (is_array($issue) && isset($issue['severity']) && $issue['severity'] === 'critical') {
                return true;
            }

            if (is_string($issue) && str_contains(strtolower($issue), 'critical')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Filtra issues por severidad.
     */
    public function getIssuesBySeverity(string $severity): array
    {
        return array_filter($this->issues, static function ($issue) use ($severity): bool {
            if (is_array($issue) && isset($issue['severity'])) {
                return $issue['severity'] === $severity;
            }

            return false;
        });
    }

    /**
     * Obtiene métricas específicas de una herramienta.
     */
    public function getToolMetrics(string $tool): array
    {
        return $this->metrics[$tool] ?? [];
    }

    /**
     * Obtiene un resumen textual del análisis.
     */
    public function getSummary(): string
    {
        $level = $this->getQualityLevel();
        $issueCount = $this->getIssueCount();
        $status = $this->passed ? 'PASSED' : 'FAILED';

        return sprintf(
            '%s analysis: %s (score: %d/100, level: %s, issues: %d)',
            ucfirst($this->tool),
            $status,
            $this->score,
            $level,
            $issueCount,
        );
    }

    /**
     * Genera recomendaciones basadas en los resultados.
     */
    public function getRecommendations(): array
    {
        $recommendations = [];

        if ($this->score < 70) {
            $recommendations[] = 'Consider refactoring code to improve quality score';
        }

        if ($this->hasCriticalIssues()) {
            $recommendations[] = 'Address critical issues immediately';
        }

        if ($this->getIssueCount() > 10) {
            $recommendations[] = 'High number of issues detected, consider systematic code review';
        }

        $level = $this->getQualityLevel();

        if ($level === 'poor' || $level === 'critical') {
            $recommendations[] = 'Code quality is below acceptable standards, immediate action required';
        }

        return $recommendations;
    }

    /**
     * Convierte el resultado a array para serialización.
     */
    public function toArray(): array
    {
        return [
            'tool' => $this->tool,
            'score' => $this->score,
            'quality_level' => $this->getQualityLevel(),
            'passed' => $this->passed,
            'issue_count' => $this->getIssueCount(),
            'has_critical_issues' => $this->hasCriticalIssues(),
            'issues' => $this->issues,
            'metrics' => $this->metrics,
            'recommendations' => $this->getRecommendations(),
            'output' => $this->output,
            'timestamp' => $this->timestamp->format('Y-m-d H:i:s'),
        ];
    }
}
