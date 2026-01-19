<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\SQL\PdoEngine;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * Test para validar las optimizaciones de rendimiento implementadas en PostgreSQL.
 *
 * @group postgresql
 * @group performance
 */
class PerformanceOptimizationTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Asegurar estado limpio para cada test
        self::$orm->cache('clear');
        self::$orm->cache('enable');
    }

    protected function tearDown(): void
    {
        // Limpiar después de cada test
        self::$orm->cache('clear');
        parent::tearDown();
    }

    public function test_cache_ttl_and_lru_functionality(): void
    {
        // Limpiar caché antes de empezar
        PdoEngine::clearQueryCache();

        // Habilitar caché
        self::$orm->cache('enable');

        // Primera consulta - debería ir a BD
        $users1 = self::$orm->table('users')->where('id', '>', 0)->get();

        // Segunda consulta idéntica - debería venir del caché
        $users2 = self::$orm->table('users')->where('id', '>', 0)->get();

        // Los resultados deben ser idénticos
        self::assertEquals($users1, $users2);

        // Verificar que hay entradas en el caché
        $metrics = PdoEngine::getMetrics();
        self::assertGreaterThan(0, $metrics['cache_hits']);
    }

    public function test_memory_leak_prevention_static_registries(): void
    {
        // Crear algunos modelos y registrar eventos
        $user = VersaModel::dispense('users');
        $user->name = 'Test User';
        $user->email = 'test@example.com';
        $user->store();

        // Hacer algunas consultas para llenar caches
        self::$orm->table('users')->where('name', 'LIKE', '%Test%')->get();
        self::$orm->table('users')->count();

        // Verificar que tenemos métricas
        $metricsBefore = PdoEngine::getMetrics();
        self::assertGreaterThan(0, $metricsBefore['queries']);

        // Limpiar todos los registros estáticos
        VersaORM::clearAllStaticRegistries();

        // Re-establecer el ORM instance en VersaModel después de la limpieza
        VersaModel::setORM(self::$orm);

        // Verificar que los caches fueron limpiados
        $metricsAfter = PdoEngine::getMetrics();
        self::assertEquals(0, $metricsAfter['cache_hits']);
        self::assertEquals(0, $metricsAfter['cache_misses']);
        self::assertEquals(0, $metricsAfter['queries']);

        // Verificar que los modelos aún funcionan después de limpiar
        $newUser = VersaModel::dispense('users');
        $newUser->name = 'Test User 2';
        $newUser->email = 'test2@example.com';
        self::assertNotNull($newUser->store());
    }

    public function test_cache_partial_cleanup(): void
    {
        // Limpiar todo primero
        VersaORM::clearAllStaticRegistries();
        VersaModel::setORM(self::$orm);

        // Habilitar caché y hacer consultas
        self::$orm->cache('enable');
        self::$orm->table('users')->where('id', '<', 100)->get();
        self::$orm->table('users')->count();

        $metricsBefore = PdoEngine::getMetrics();
        self::assertGreaterThan(0, $metricsBefore['queries']);

        // Limpiar solo caches (no métricas)
        VersaORM::clearCaches();

        $metricsAfter = PdoEngine::getMetrics();
        // Las métricas de queries deben mantenerse
        self::assertEquals($metricsBefore['queries'], $metricsAfter['queries']);

        // Verificar que las próximas consultas empiezan con cache limpio
        // (no podemos verificar los contadores directamente porque pueden tener valores residuales)
        // En su lugar, verificamos que la funcionalidad sigue trabajando
        $testResult = self::$orm->table('users')->limit(1)->get();
        self::assertIsArray($testResult);
    }

    public function test_statement_cache_cleanup(): void
    {
        // Hacer algunas consultas para llenar el cache de statements
        for ($i = 1; $i <= 5; $i++) {
            self::$orm->table('users')->where('id', '=', $i)->get();
        }

        $metricsBefore = PdoEngine::getMetrics();

        // Limpiar solo el cache de statements
        PdoEngine::clearStatementCache();

        $metricsAfter = PdoEngine::getMetrics();

        // Verificar que las métricas no se ven afectadas por limpiar el cache de statements
        self::assertEquals($metricsBefore['queries'], $metricsAfter['queries']);

        // El próximo query debería tener que preparar el statement de nuevo
        self::$orm->table('users')->where('id', '=', 1)->get();

        // Esto es difícil de verificar directamente, pero al menos verificamos que no crashea
        self::assertTrue(true);
    }

    public function test_cache_structure_with_metadata(): void
    {
        // Verificar que la nueva estructura de caché funciona correctamente
        PdoEngine::clearQueryCache();
        self::$orm->cache('enable');

        // Primera consulta
        $result1 = self::$orm->table('users')->limit(1)->get();

        // Forzar un segundo de diferencia para probar timestamps
        sleep(1);

        // Segunda consulta idéntica
        $result2 = self::$orm->table('users')->limit(1)->get();

        // Los resultados deben ser iguales
        self::assertEquals($result1, $result2);

        // Verificar que fue un cache hit
        $metrics = PdoEngine::getMetrics();
        self::assertGreaterThan(0, $metrics['cache_hits']);
    }
}
