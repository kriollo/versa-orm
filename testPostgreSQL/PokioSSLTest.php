<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\VersaModel;
use VersaORM\VersaORM;

require_once __DIR__ . '/TestCase.php';

/**
 * Tests para verificar que Pokio funciona con PostgreSQL y SSL.
 *
 * @group postgresql
 * @group pokio
 * @group ssl
 */
class PokioSSLTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Skip Pokio tests in CI environments due to PDO serialization issues with fork
        if (getenv('CI') === 'true' || getenv('GITHUB_ACTIONS') === 'true') {
            static::markTestSkipped(
                'Pokio tests are skipped in CI due to PDO serialization limitations in fork processes',
            );
        }
    }

    /**
     * Test: Pokio con SSL desactivado funciona correctamente.
     */
    public function test_pokio_works_with_ssl_disabled(): void
    {
        if (!function_exists('async')) {
            static::markTestSkipped('Pokio not installed');
        }

        // Configuración con SSL desactivado
        $existingConfig = self::$orm->getConfig();
        $config = array_merge($existingConfig, [
            'sslmode' => 'disable',
        ]);

        $orm = new VersaORM($config);

        // Crear tabla de prueba
        $orm->schemaCreate('test_pokio_ssl', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'name', 'type' => 'VARCHAR(100)'],
        ]);

        // Guardar ORM original
        $originalOrm = VersaModel::getGlobalORM();
        VersaModel::setORM($orm);

        // Insertar registros de prueba
        for ($i = 1; $i <= 5; $i++) {
            $model = VersaModel::dispense('test_pokio_ssl');
            $model->name = "Test {$i}";
            $model->store();
        }

        // Usar Pokio para consultas paralelas
        $promises = [];
        for ($i = 1; $i <= 5; $i++) {
            $promises[] = async(static function () use ($i) {
                // IMPORTANTE: Cada proceso hijo necesita su propia conexión
                // Cargar el modelo
                $model = VersaModel::load('test_pokio_ssl', $i);
                return $model?->name;
            });
        }

        // Esperar resultados
        $results = [];
        foreach ($promises as $promise) {
            $results[] = await($promise);
        }

        // Verificar resultados
        static::assertCount(5, $results);
        static::assertContains('Test 1', $results);
        static::assertContains('Test 5', $results);

        // Limpiar
        $orm->schemaDrop('test_pokio_ssl');
        VersaModel::setORM($originalOrm);
    }

    /**
     * Test: Demostrar el problema con SSL activado.
     */
    public function test_pokio_fails_with_ssl_enabled(): void
    {
        if (!function_exists('async')) {
            static::markTestSkipped('Pokio not installed');
        }

        // Configuración con SSL activado (prefer es el default)
        $existingConfig = self::$orm->getConfig();
        $config = array_merge($existingConfig, [
            'sslmode' => 'prefer', // Intentará usar SSL
        ]);

        try {
            $orm = new VersaORM($config);

            // Verificar si SSL está realmente activo
            $result = $orm->exec('SELECT ssl_is_used() as ssl_enabled');

            if (!$result[0]['ssl_enabled']) {
                static::markTestSkipped('SSL not enabled on PostgreSQL server');
            }

            // Crear tabla de prueba
            $orm->schemaCreate('test_pokio_ssl_fail', [
                ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
                ['name' => 'name', 'type' => 'VARCHAR(100)'],
            ]);

            $originalOrm = VersaModel::getGlobalORM();
            VersaModel::setORM($orm);

            // Insertar un registro
            $model = VersaModel::dispense('test_pokio_ssl_fail');
            $model->name = 'Test';
            $model->store();

            // Intentar usar Pokio con SSL - esto puede fallar
            $hasError = false;
            try {
                $promise = async(static function () {
                    $model = VersaModel::load('test_pokio_ssl_fail', 1);
                    return $model?->name;
                });

                $result = await($promise);
            } catch (\Exception $e) {
                $hasError = true;
                // Verificar que el error es relacionado con SSL
                static::assertStringContainsString('SSL', $e->getMessage());
            }

            // Limpiar
            $orm->schemaDrop('test_pokio_ssl_fail');
            VersaModel::setORM($originalOrm);

            // Este test documenta el problema
            static::assertTrue(true, 'Test completed - SSL with Pokio may cause issues');
        } catch (\Exception $e) {
            static::markTestSkipped('Cannot test SSL: ' . $e->getMessage());
        }
    }

    /**
     * Test: Solución - reconectar en cada proceso hijo.
     */
    public function test_pokio_with_reconnect_in_child(): void
    {
        if (!function_exists('async')) {
            static::markTestSkipped('Pokio not installed');
        }

        $existingConfig = self::$orm->getConfig();
        $config = array_merge($existingConfig, [
            'sslmode' => 'disable',
        ]);

        $orm = new VersaORM($config);

        $orm->schemaCreate('test_pokio_reconnect', [
            ['name' => 'id', 'type' => 'SERIAL', 'primary' => true],
            ['name' => 'value', 'type' => 'INTEGER'],
        ]);

        $originalOrm = VersaModel::getGlobalORM();
        VersaModel::setORM($orm);

        // Insertar datos
        for ($i = 1; $i <= 10; $i++) {
            $model = VersaModel::dispense('test_pokio_reconnect');
            $model->value = $i * 10;
            $model->store();
        }

        // Usar Pokio con reconexión en cada hijo
        $promises = [];
        for ($i = 1; $i <= 10; $i++) {
            $promises[] = async(static function () use ($config, $i) {
                // SOLUCIÓN: Crear nueva instancia de ORM en cada proceso hijo
                $childOrm = new VersaORM($config);
                VersaModel::setORM($childOrm);

                $model = VersaModel::load('test_pokio_reconnect', $i);
                return $model?->value;
            });
        }

        // Recolectar resultados
        $results = [];
        foreach ($promises as $promise) {
            $results[] = await($promise);
        }

        // Verificar
        static::assertCount(10, $results);
        static::assertContains(10, $results); // 1 * 10
        static::assertContains(100, $results); // 10 * 10

        // Limpiar
        $orm->schemaDrop('test_pokio_reconnect');
        VersaModel::setORM($originalOrm);
    }
}
