<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

require_once __DIR__ . '/bootstrap.php';

/**
 * @group mysql
 */
class HydrationMetricsTest extends TestCase
{
    public function testHydrationFastPathAndMetrics(): void
    {
        self::$orm->metricsReset();
        $before = self::$orm->metrics();
        self::assertIsArray($before);
        self::assertArrayHasKey('hydration_fastpath_uses', $before);
        self::assertSame(0, $before['hydration_fastpath_uses']);

        // Fast-path elegible: VersaModel base, select '*', sin relaciones
        $all = self::$orm->table('users')->findAll();
        self::assertNotEmpty($all);
        $after = self::$orm->metrics();
        self::assertGreaterThanOrEqual(1, $after['hydration_fastpath_uses']);
        self::assertGreaterThan(0, $after['hydration_fastpath_rows']);
        self::assertGreaterThan(0, $after['hydration_fastpath_ms']);
        self::assertGreaterThan(0, $after['objects_hydrated']);

        // Uso de first (fast-path single row) y ver incremento de objetos
        $beforeObjs = $after['objects_hydrated'];
        $one        = self::$orm->table('users')->first();
        self::assertNotNull($one);
        $after2 = self::$orm->metrics();
        self::assertGreaterThan($beforeObjs, $after2['objects_hydrated']);
    }
}
