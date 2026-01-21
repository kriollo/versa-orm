<?php

declare(strict_types=1);

/**
 * Script para analizar el coverage y mostrar qué áreas necesitan más tests
 *
 * Uso: php scripts/coverage-report.php
 */

// Intentar varios posibles ubicaciones de clover.xml
$possiblePaths = [
    __DIR__ . '/../tests/reports/coverage/sqlite/clover.xml',  // Ubicación por defecto de phpunit.xml
    __DIR__ . '/../build/coverage/clover.xml',
    __DIR__ . '/../build/logs/clover.xml',
    __DIR__ . '/../build/coverage/combined/clover.xml',
];

$cloverFile = null;
foreach ($possiblePaths as $path) {
    if (file_exists($path)) {
        $cloverFile = $path;
        break;
    }
}

if ($cloverFile === null || !file_exists($cloverFile)) {
    echo "❌ No se encontró el archivo de coverage.\n";
    echo "   Ejecuta primero: composer test-coverage\n";
    echo "   Buscando en:\n";
    foreach ($possiblePaths as $path) {
        echo "   - " . $path . " " . (file_exists($path) ? "✓" : "✗") . "\n";
    }
    echo "\n";
    exit(1);
}

echo "\n📁 Leyendo coverage desde: " . basename(dirname($cloverFile)) . "/" . basename($cloverFile) . "\n";


echo "\n╔══════════════════════════════════════════════════════════════╗\n";
echo "║          📊 ANÁLISIS DE COBERTURA DE TESTS                  ║\n";
echo "╚══════════════════════════════════════════════════════════════╝\n\n";

// Parsear el XML
$xml = simplexml_load_file($cloverFile);
$project = $xml->project;

$classes = [];
$totalLines = 0;
$totalCovered = 0;

// Recopilar estadísticas por archivo
foreach ($project->file as $file) {
    $filename = (string) $file['name'];

    // Solo archivos de src/
    if (!str_contains($filename, DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR)) {
        continue;
    }

    $className = basename($filename, '.php');
    $metrics = $file->metrics;

    $lines = (int) $metrics['statements'];
    $covered = (int) $metrics['coveredstatements'];
    $methods = (int) $metrics['methods'];
    $coveredMethods = (int) $metrics['coveredmethods'];

    if ($lines > 0) {
        $totalLines += $lines;
        $totalCovered += $covered;

        $classes[] = [
            'name' => $className,
            'path' => str_replace(__DIR__ . '/../src/', '', $filename),
            'lines' => $lines,
            'covered' => $covered,
            'percent' => round(($covered / $lines) * 100, 2),
            'methods' => $methods,
            'coveredMethods' => $coveredMethods,
            'methodPercent' => $methods > 0 ? round(($coveredMethods / $methods) * 100, 2) : 100,
        ];
    }
}

// Ordenar por porcentaje (menor a mayor)
usort($classes, fn($a, $b) => $a['percent'] <=> $b['percent']);

// Coverage global
$globalPercent = $totalLines > 0 ? round(($totalCovered / $totalLines) * 100, 2) : 0;

echo "🎯 COBERTURA GLOBAL: {$globalPercent}% ({$totalCovered}/{$totalLines} líneas)\n\n";

// Mostrar las 10 clases con menor coverage
echo "🔴 TOP 10 CLASES QUE NECESITAN MÁS TESTS:\n";
echo str_repeat("─", 90) . "\n";
printf("%-40s %10s %12s %15s\n", "Clase", "Coverage", "Líneas", "Métodos");
echo str_repeat("─", 90) . "\n";

foreach (array_slice($classes, 0, 10) as $class) {
    $icon = $class['percent'] < 30 ? '🔴' : ($class['percent'] < 60 ? '🟡' : '🟢');
    printf(
        "%s %-38s %7.2f%% %5d/%5d %7d/%d (%.0f%%)\n",
        $icon,
        $class['name'],
        $class['percent'],
        $class['covered'],
        $class['lines'],
        $class['coveredMethods'],
        $class['methods'],
        $class['methodPercent']
    );
}

echo "\n";

// Clases con buen coverage
echo "✅ TOP 5 CLASES CON MEJOR COVERAGE:\n";
echo str_repeat("─", 90) . "\n";
printf("%-40s %10s %12s %15s\n", "Clase", "Coverage", "Líneas", "Métodos");
echo str_repeat("─", 90) . "\n";

foreach (array_slice(array_reverse($classes), 0, 5) as $class) {
    printf(
        "🟢 %-38s %7.2f%% %5d/%5d %7d/%d (%.0f%%)\n",
        $class['name'],
        $class['percent'],
        $class['covered'],
        $class['lines'],
        $class['coveredMethods'],
        $class['methods'],
        $class['methodPercent']
    );
}

echo "\n";

// Estadísticas por rango
$ranges = [
    'Crítico (0-30%)' => 0,
    'Bajo (30-50%)' => 0,
    'Medio (50-70%)' => 0,
    'Bueno (70-90%)' => 0,
    'Excelente (90-100%)' => 0,
];

foreach ($classes as $class) {
    if ($class['percent'] < 30) {
        $ranges['Crítico (0-30%)']++;
    } elseif ($class['percent'] < 50) {
        $ranges['Bajo (30-50%)']++;
    } elseif ($class['percent'] < 70) {
        $ranges['Medio (50-70%)']++;
    } elseif ($class['percent'] < 90) {
        $ranges['Bueno (70-90%)']++;
    } else {
        $ranges['Excelente (90-100%)']++;
    }
}

echo "📈 DISTRIBUCIÓN DE COBERTURA:\n";
echo str_repeat("─", 60) . "\n";
foreach ($ranges as $label => $count) {
    $bar = str_repeat('█', min(50, (int)($count / count($classes) * 50)));
    printf("%-25s %3d clases %s\n", $label, $count, $bar);
}

echo "\n";
echo "💡 RECOMENDACIONES:\n";
echo str_repeat("─", 60) . "\n";

$criticalCount = $ranges['Crítico (0-30%)'] + $ranges['Bajo (30-50%)'];
if ($criticalCount > 0) {
    echo "1. Priorizar tests para las {$criticalCount} clases con < 50% coverage\n";
}

if ($globalPercent < 80) {
    $needed = 80 - $globalPercent;
    echo "2. Necesitas aumentar ~{$needed}% para alcanzar el 80% (objetivo)\n";
}

echo "3. Revisar el reporte HTML: build/coverage/index.html\n";
echo "4. Ver en Codecov: https://app.codecov.io/gh/kriollo/versa-orm\n";

echo "\n";
echo "Para ver el reporte HTML ejecuta:\n";
echo "  composer test-coverage\n";
echo "  start build/coverage/index.html\n\n";
