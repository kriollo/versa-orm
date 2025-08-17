<?php
/**
 * Script Maestro de Validación para Documentación VersaORM
 *
 * Este script ejecuta todas las validaciones disponibles:
 * - Validación de ejemplos de código
 * - Compatibilidad multi-base de datos
 * - Consistencia de formato
 * - Enlaces internos
 */

declare(strict_types=1);

require_once __DIR__ . '/../../vendor/autoload.php';
require_once __DIR__ . '/validate_documentation.php';
require_once __DIR__ . '/multi_db_validator.php';
require_DIR__ . '/format_checker.php';

class MasterValidator
{
    private array $results = [];
    private bool $verbose;

    public function __construct(bool $verbose = true)
    {
        $this->verbose = $verbose;
    }

    /**
     * Ejecuta todas las validaciones
     */
    public function runAllValidations(): bool
    {
        echo "🚀 VALIDACIÓN COMPLETA DE DOCUMENTACIÓN VERSAORM\n";
        echo str_repeat("=", 60) . "\n\n";

        $startTime = microtime(true);
        $overallSuccess = true;

        // 1. Validación básica de documentación
        echo "1️⃣  VALIDACIÓN BÁSICA DE DOCUMENTACIÓN\n";
        echo str_repeat("-", 40) . "\n";
        $basicSuccess = $this->runBasicValidation();
        $this->results['basic_validation'] = $basicSuccess;
        $overallSuccess = $overallSuccess && $basicSuccess;
        echo "\n";

        // 2. Verificación de formato
        echo "2️⃣  VERIFICACIÓN DE FORMATO\n";
        echo str_repeat("-", 40) . "\n";
        $formatSuccess = $this->runFormatValidation();
        $this->results['format_validation'] = $formatSuccess;
        $overallSuccess = $overallSuccess && $formatSuccess;
        echo "\n";

        // 3. Compatibilidad multi-base de datos
        echo "3️⃣  COMPATIBILIDAD MULTI-BASE DE DATOS\n";
        echo str_repeat("-", 40) . "\n";
        $multiDbSuccess = $this->runMultiDatabaseValidation();
        $this->results['multi_db_validation'] = $multiDbSuccess;
        $overallSuccess = $overallSuccess && $multiDbSuccess;
        echo "\n";

        // 4. Validaciones adicionales
        echo "4️⃣  VALIDACIONES ADICIONALES\n";
        echo str_repeat("-", 40) . "\n";
        $additionalSuccess = $this->runAdditionalValidations();
        $this->results['additional_validation'] = $additionalSuccess;
        $overallSuccess = $overallSuccess && $additionalSuccess;
        echo "\n";

        $endTime = microtime(true);
        $duration = round($endTime - $startTime, 2);

        $this->generateMasterReport($overallSuccess, $duration);

        return $overallSuccess;
    }

    /**
     * Ejecuta validación básica de documentación
     */
    private function runBasicValidation(): bool
    {
        try {
            $validator = new DocumentationValidator();
            return $validator->validateAll();
        } catch (Exception $e) {
            echo "❌ Error en validación básica: " . $e->getMessage() . "\n";
            return false;
        }
    }

    /**
     * Ejecuta verificación de formato
     */
    private function runFormatValidation(): bool
    {
        try {
            $checker = new FormatChecker();
            return $checker->checkAll();
        } catch (Exception $e) {
            echo "❌ Error en verificación de formato: " . $e->getMessage() . "\n";
            return false;
        }
    }

    /**
     * Ejecuta validación multi-base de datos
     */
    private function runMultiDatabaseValidation(): bool
    {
        try {
            $validator = new MultiDatabaseValidator();
            return $validator->validateAllDatabases();
        } catch (Exception $e) {
            echo "❌ Error en validación multi-BD: " . $e->getMessage() . "\n";
            return false;
        }
    }

    /**
     * Ejecuta validaciones adicionales
     */
    private function runAdditionalValidations(): bool
    {
        $success = true;

        // Verificar estructura de directorios
        echo "📁 Verificando estructura de directorios...\n";
        if (!$this->validateDirectoryStructure()) {
            $success = false;
        }

        // Verificar archivos requeridos
        echo "📋 Verificando archivos requeridos...\n";
        if (!$this->validateRequiredFiles()) {
            $success = false;
        }

        // Verificar configuración de ejemplos
        echo "⚙️  Verificando configuración de ejemplos...\n";
        if (!$this->validateExampleConfiguration()) {
            $success = false;
        }

        return $success;
    }

    /**
     * Valida la estructura de directorios
     */
    private function validateDirectoryStructure(): bool
    {
        $requiredDirs = [
            'docs/01-introduccion',
            'docs/02-instalacion',
            'docs/03-basico',
            'docs/04-query-builder',
            'docs/05-relaciones',
            'docs/06-avanzado',
            'docs/07-seguridad-tipado',
            'docs/08-referencia-sql',
            'docs/setup'
        ];

        $missing = [];
        foreach ($requiredDirs as $dir) {
            if (!is_dir(__DIR__ . '/../../' . $dir)) {
                $missing[] = $dir;
            }
        }

        if (empty($missing)) {
            echo "   ✅ Estructura de directorios correcta\n";
            return true;
        } else {
            echo "   ❌ Directorios faltantes: " . implode(', ', $missing) . "\n";
            return false;
        }
    }

    /**
     * Valida archivos requeridos
     */
    private function validateRequiredFiles(): bool
    {
        $requiredFiles = [
            'docs/README.md',
            'docs/setup/setup_database.php',
            'docs/setup/database_config.php',
            'README.md'
        ];

        $missing = [];
        foreach ($requiredFiles as $file) {
            if (!file_exists(__DIR__ . '/../../' . $file)) {
                $missing[] = $file;
            }
        }

        if (empty($missing)) {
            echo "   ✅ Todos los archivos requeridos presentes\n";
            return true;
        } else {
            echo "   ❌ Archivos faltantes: " . implode(', ', $missing) . "\n";
            return false;
        }
    }

    /**
     * Valida configuración de ejemplos
     */
    private function validateExampleConfiguration(): bool
    {
        $configFile = __DIR__ . '/database_config.php';

        if (!file_exists($configFile)) {
            echo "   ❌ Archivo de configuración de ejemplos no encontrado\n";
            return false;
        }

        try {
            $config = require $configFile;
            if (!is_array($config) || empty($config)) {
                echo "   ❌ Configuración de ejemplos inválida\n";
                return false;
            }

            echo "   ✅ Configuración de ejemplos válida\n";
            return true;
        } catch (Exception $e) {
            echo "   ❌ Error cargando configuración: " . $e->getMessage() . "\n";
            return false;
        }
    }

    /**
     * Genera reporte maestro final
     */
    private function generateMasterReport(bool $overallSuccess, float $duration): void
    {
        echo str_repeat("=", 60) . "\n";
        echo "📊 REPORTE FINAL DE VALIDACIÓN\n";
        echo str_repeat("=", 60) . "\n\n";

        // Resumen de resultados
        echo "🎯 Resumen de Validaciones:\n";
        foreach ($this->results as $validation => $success) {
            $status = $success ? '✅' : '❌';
            $name = $this->getValidationName($validation);
            echo "   {$status} {$name}\n";
        }

        echo "\n⏱️  Tiempo total de ejecución: {$duration} segundos\n\n";

        // Resultado final
        if ($overallSuccess) {
            echo "🎉 ¡VALIDACIÓN EXITOSA!\n";
            echo "   ✅ Toda la documentación está correcta y funcional\n";
            echo "   ✅ Los ejemplos funcionan en todas las bases de datos\n";
            echo "   ✅ El formato es consistente en todos los archivos\n";
            echo "   ✅ Todos los enlaces internos funcionan correctamente\n\n";

            echo "🚀 La documentación está lista para producción.\n";
        } else {
            echo "⚠️  VALIDACIÓN CON PROBLEMAS\n";
            echo "   Revisa los reportes individuales para detalles específicos:\n";
            echo "   - docs/setup/validation_report.json\n";
            echo "   - docs/setup/format_report.json\n";
            echo "   - docs/setup/multi_db_report.json\n\n";

            echo "🔧 Corrige los problemas encontrados y vuelve a ejecutar la validación.\n";
        }

        // Guardar reporte maestro
        $this->saveMasterReport($overallSuccess, $duration);
    }

    /**
     * Obtiene nombre legible de validación
     */
    private function getValidationName(string $validation): string
    {
        $names = [
            'basic_validation' => 'Validación Básica',
            'format_validation' => 'Verificación de Formato',
            'multi_db_validation' => 'Compatibilidad Multi-BD',
            'additional_validation' => 'Validaciones Adicionales'
        ];

        return $names[$validation] ?? $validation;
    }

    /**
     * Guarda reporte maestro
     */
    private function saveMasterReport(bool $overallSuccess, float $duration): void
    {
        $report = [
            'timestamp' => date('Y-m-d H:i:s'),
            'overall_success' => $overallSuccess,
            'duration_seconds' => $duration,
            'validations' => $this->results,
            'summary' => [
                'total_validations' => count($this->results),
                'successful_validations' => count(array_filter($this->results)),
                'success_rate' => round((count(array_filter($this->results)) / count($this->results)) * 100, 1)
            ]
        ];

        $reportFile = __DIR__ . '/master_validation_report.json';
        file_put_contents($reportFile, json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

        echo "\n📄 Reporte maestro guardado en: docs/setup/master_validation_report.json\n";
    }

    /**
     * Ejecuta validación rápida (solo básica y formato)
     */
    public function runQuickValidation(): bool
    {
        echo "⚡ VALIDACIÓN RÁPIDA DE DOCUMENTACIÓN\n";
        echo str_repeat("=", 40) . "\n\n";

        $basicSuccess = $this->runBasicValidation();
        $formatSuccess = $this->runFormatValidation();

        $success = $basicSuccess && $formatSuccess;

        echo "\n" . str_repeat("=", 40) . "\n";
        if ($success) {
            echo "✅ Validación rápida exitosa\n";
        } else {
            echo "❌ Problemas encontrados en validación rápida\n";
        }

        return $success;
    }
}

// Función de ayuda
function showHelp(): void
{
    echo "Uso: php run_all_validations.php [opciones]\n\n";
    echo "Opciones:\n";
    echo "  --quick     Ejecuta solo validación básica y formato (más rápido)\n";
    echo "  --help      Muestra esta ayuda\n\n";
    echo "Sin opciones: Ejecuta todas las validaciones (completo)\n";
}

// Ejecutar si se llama directamente
if (basename(__FILE__) === basename($_SERVER['SCRIPT_NAME'])) {
    $options = getopt('', ['quick', 'help']);

    if (isset($options['help'])) {
        showHelp();
        exit(0);
    }

    $validator = new MasterValidator();

    if (isset($options['quick'])) {
        $success = $validator->runQuickValidation();
    } else {
        $success = $validator->runAllValidations();
    }

    exit($success ? 0 : 1);
}
