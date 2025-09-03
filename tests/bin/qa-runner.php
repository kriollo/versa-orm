#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * CLI Runner para el sistema de QA de VersaORM.
 *
 * Proporciona una interfaz de línea de comandos para ejecutar
 * diferentes tipos de tests y análisis de calidad.
 */

require_once __DIR__ . '/../../vendor/autoload.php';

use VersaORM\Tests\TestManager;

// Configuración por defecto
$config = require __DIR__ . '/../config/qa-config.php';

// Parsear argumentos de línea de comandos
$options = parseArguments($argv);

// Mostrar ayuda si se solicita
if (isset($options['help']) || isset($options['h'])) {
    showHelp();
    exit(0);
}

// Mostrar versión si se solicita
if (isset($options['version']) || isset($options['v'])) {
    echo "VersaORM QA Runner v{$config['version']}\n";
    exit(0);
}

try {
    // Crear instancia del TestManager
    $testManager = new TestManager($config);

    // Determinar qué ejecutar basado en los argumentos
    $command = $options['command'] ?? 'full';

    switch ($command) {
        case 'full':
        case 'all':
            echo "🚀 Ejecutando suite completa de QA...\n";
            $report = $testManager->runFullSuite($options);
            break;

        case 'unit':
            $engine = $options['engine'] ?? 'all';
            echo "🧪 Ejecutando tests unitarios para: {$engine}...\n";
            $result = $testManager->runUnitTests($engine);
            echo $result->getSummary() . "\n";
            exit($result->isSuccessful() ? 0 : 1);

        case 'integration':
            $engine = $options['engine'] ?? 'all';
            echo "🔗 Ejecutando tests de integración para: {$engine}...\n";
            $result = $testManager->runIntegrationTests($engine);
            echo $result->getSummary() . "\n";
            exit($result->isSuccessful() ? 0 : 1);

        case 'benchmarks':
            echo "⚡ Ejecutando benchmarks...\n";
            $comparisons = isset($options['compare']) ? explode(',', $options['compare']) : [];
            $result = $testManager->runBenchmarks($comparisons);
            echo $result->getSummary() . "\n";
            exit(0);

        case 'quality':
            echo "🔍 Ejecutando análisis de calidad...\n";
            $result = $testManager->runQualityAnalysis();
            echo $result->getSummary() . "\n";
            exit($result->passed ? 0 : 1);

        default:
            echo "❌ Comando desconocido: {$command}\n";
            showHelp();
            exit(1);
    }
    // Mostrar resumen del reporte si se ejecutó la suite completa
    $summary = $report->getExecutiveSummary();
    echo "\n📊 Resumen Ejecutivo:\n";
    echo "==================\n";
    echo 'Estado General: ' . getStatusEmoji($summary['overall_status']) . " {$summary['overall_status']}\n";
    echo "Tests Totales: {$summary['total_tests']}\n";
    echo "Tasa de Éxito: {$summary['success_rate']}%\n";
    echo "Puntuación de Calidad: {$summary['quality_score']}/100\n";
    echo "Tiempo de Ejecución: {$summary['execution_time']}s\n";

    if ($summary['critical_alerts'] > 0) {
        echo "🚨 Alertas Críticas: {$summary['critical_alerts']}\n";
    }
    // Mostrar recomendaciones si las hay
    $recommendations = $report->getRecommendations();

    if (!empty($recommendations)) {
        echo "\n💡 Recomendaciones:\n";

        foreach ($recommendations as $recommendation) {
            echo "  • {$recommendation}\n";
        }
    }
    echo "\n📄 Reporte guardado en: tests/reports/\n";
    // Código de salida basado en el estado
    $exitCode = match ($summary['overall_status']) {
        'success', 'warning' => 0,
        'failed' => 1,
        'critical' => 2,
        default => 1,
    };
    exit($exitCode);
} catch (Exception $e) {
    echo "❌ Error durante la ejecución: {$e->getMessage()}\n";

    if (isset($options['debug']) || isset($options['d'])) {
        echo "\n🐛 Stack trace:\n";
        echo $e->getTraceAsString() . "\n";
    }

    exit(1);
}

/**
 * Parsea los argumentos de línea de comandos.
 */
function parseArguments(array $argv): array
{
    $options = [];
    $command = null;
    $counter = count($argv);

    for ($i = 1; $i < $counter; $i++) {
        $arg = $argv[$i];

        if (str_starts_with($arg, '--')) {
            // Argumento largo
            $parts = explode('=', substr($arg, 2), 2);
            $key = $parts[0];
            $value = $parts[1] ?? true;
            $options[$key] = $value;
        } elseif (str_starts_with($arg, '-')) {
            // Argumento corto
            $key = substr($arg, 1);
            $value = true;

            // Verificar si el siguiente argumento es un valor
            if (($i + 1) < count($argv) && !str_starts_with($argv[$i + 1], '-')) {
                $value = $argv[++$i];
            }

            $options[$key] = $value;
        } elseif (!$command) {
            // Comando principal
            $command = $arg;
        }
    }

    if ($command) {
        $options['command'] = $command;
    }

    return $options;
}

/**
 * Muestra la ayuda del comando.
 */
function showHelp(): void
{
    echo <<<'HELP'
        VersaORM QA Runner - Sistema de Testing y QA

        USAGE:
            php tests/bin/qa-runner.php [COMMAND] [OPTIONS]

        COMMANDS:
            full, all           Ejecuta la suite completa de QA (por defecto)
            unit               Ejecuta tests unitarios
            integration        Ejecuta tests de integración
            benchmarks         Ejecuta benchmarks de rendimiento
            quality            Ejecuta análisis de calidad

        OPTIONS:
            --engine=ENGINE    Motor de BD para tests (mysql, postgresql, sqlite, all)
            --compare=ORMS     ORMs para comparar en benchmarks (eloquent,doctrine,pdo)
            --debug, -d        Mostrar información de debug
            --help, -h         Mostrar esta ayuda
            --version, -v      Mostrar versión

        EXAMPLES:
            php tests/bin/qa-runner.php full
            php tests/bin/qa-runner.php unit --engine=mysql
            php tests/bin/qa-runner.php benchmarks --compare=eloquent,doctrine
            php tests/bin/qa-runner.php quality --debug

        EXIT CODES:
            0    Éxito
            1    Fallos en tests o errores
            2    Fallos críticos

        HELP;
}

/**
 * Obtiene emoji para el estado.
 */
function getStatusEmoji(string $status): string
{
    return match ($status) {
        'success' => '✅',
        'warning' => '⚠️',
        'failed' => '❌',
        'critical' => '🚨',
        default => '❓',
    };
}
