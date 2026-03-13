<?php

declare(strict_types=1);

namespace VersaORM\Tests\Interfaces;

use VersaORM\Tests\Results\BenchmarkResult;
use VersaORM\Tests\Results\QualityResult;
use VersaORM\Tests\Results\Report;
use VersaORM\Tests\Results\TestResult;

/**
 * Interface para el TestManager principal.
 *
 * Define el contrato para coordinar la ejecución de todos los tipos de tests
 * y generar reportes consolidados del sistema de QA.
 */
interface TestManagerInterface
{
    /**
     * Ejecuta la suite completa de tests con todas las validaciones.
     *
     * @param array $options Opciones de configuración para la ejecución
     *
     * @return Report Reporte consolidado con todos los resultados
     */
    public function runFullSuite(array $options = []): Report;

    /**
     * Ejecuta tests unitarios para un motor específico o todos.
     *
     * @param string $engine Motor de BD ('mysql', 'postgresql', 'sqlite', 'all')
     *
     * @return TestResult Resultado de los tests unitarios
     */
    public function runUnitTests(string $engine = 'all'): TestResult;

    /**
     * Ejecuta tests de integración para un motor específico o todos.
     *
     * @param string $engine Motor de BD ('mysql', 'postgresql', 'sqlite', 'all')
     *
     * @return TestResult Resultado de los tests de integración
     */
    public function runIntegrationTests(string $engine = 'all'): TestResult;

    /**
     * Ejecuta suite de benchmarks con comparaciones opcionales.
     *
     * @param array $comparisons Lista de ORMs para comparar ['eloquent', 'doctrine', 'pdo']
     *
     * @return BenchmarkResult Resultado de los benchmarks
     */
    public function runBenchmarks(array $comparisons = []): BenchmarkResult;

    /**
     * Ejecuta análisis de calidad con todas las herramientas.
     *
     * @return QualityResult Resultado del análisis de calidad
     */
    public function runQualityAnalysis(): QualityResult;

    /**
     * Genera reporte consolidado de todos los resultados.
     *
     * @param array $results Array con todos los resultados de tests
     *
     * @return Report Reporte consolidado
     */
    public function generateReport(array $results): Report;
}
