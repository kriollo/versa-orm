<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use PHPUnit\Framework\TestCase;
use VersaORM\VersaORM;
use VersaORM\VersaORMException;

/**
 * Prueba la creación de archivos de logs ante errores de ejecución.
 */
class LoggingErrorTest extends TestCase
{
    private string $logDir;

    private VersaORM $orm;

    protected function setUp(): void
    {
        $this->logDir = __DIR__ . '/_logs_runtime';
        if (is_dir($this->logDir)) {
            $this->cleanupLogs();
        }
        if (! is_dir($this->logDir)) {
            mkdir($this->logDir, 0775, true);
        }

        $config = [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'debug' => true,
            'log_path' => $this->logDir,
        ];

        $this->orm = new VersaORM($config);

        // Crear esquema mínimo
        $this->orm->schemaCreate('users', [
            ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true, 'nullable' => false],
            ['name' => 'name', 'type' => 'VARCHAR(100)'],
        ]);
        $this->orm->table('users')->insert(['name' => 'Alice']);
    }

    protected function tearDown(): void
    {
        $this->cleanupLogs();
    }

    public function test_error_logs_are_created_on_sql_error(): void
    {
        // 1er error: tabla inexistente
        try {
            $this->orm->table('non_existing_table')->select(['id'])->getAll();
            $this->fail('Se esperaba VersaORMException por tabla inexistente.');
        } catch (VersaORMException $e) {
            $this->assertStringContainsString('non_existing_table', strtolower($e->getMessage()));
        }

        // 2do error: forzar error de sintaxis SQL manual
        try {
            $this->orm->exec('SELECT * FROM users WHERE'); // incompleto
            $this->fail('Se esperaba VersaORMException por SQL inválido.');
        } catch (VersaORMException $e) {
            $msg = strtolower($e->getMessage());
            $this->assertTrue(str_contains($msg, 'syntax') || str_contains($msg, 'incomplete'), 'Mensaje inesperado: ' . $msg);
        }

        $date = date('Y-m-d');
        $summary = $this->logDir . DIRECTORY_SEPARATOR . 'versaorm_errors_' . $date . '.log';
        $detail = $this->logDir . DIRECTORY_SEPARATOR . 'versaorm_errors_detail_' . $date . '.log';

        $this->assertFileExists($summary, 'Archivo de log de resumen no creado');
        $this->assertFileExists($detail, 'Archivo de log detallado no creado');

        $lines = file($summary, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $this->assertGreaterThanOrEqual(2, count($lines), 'Se esperaban al menos 2 líneas en el log de resumen');

        // Validar estructura JSON básica de la primera línea
        $first = json_decode($lines[0], true, 512, JSON_THROW_ON_ERROR);
        foreach (['timestamp', 'error_code', 'message', 'origin', 'query', 'context'] as $key) {
            $this->assertArrayHasKey($key, $first, 'Falta clave ' . $key . ' en la entrada de log');
        }

        // Validar detalle (última línea del archivo detail contiene full_trace)
        $detailLines = file($detail, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $lastDetail = json_decode(end($detailLines), true, 512, JSON_THROW_ON_ERROR);
        $this->assertArrayHasKey('full_trace', $lastDetail, 'No se encontró full_trace en log detallado');
        $this->assertIsArray($lastDetail['full_trace']);
    }

    private function cleanupLogs(): void
    {
        if (! is_dir($this->logDir)) {
            return;
        }
        foreach (glob($this->logDir . DIRECTORY_SEPARATOR . 'versaorm_errors_*') as $f) {
            @unlink($f);
        }
        foreach (glob($this->logDir . DIRECTORY_SEPARATOR . 'versaorm_errors_detail_*') as $f) {
            @unlink($f);
        }
    }
}
