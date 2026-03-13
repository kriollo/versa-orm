<?php

declare(strict_types=1);

namespace VersaORM\Tests\Mysql;

require_once __DIR__ . '/bootstrap.php';

/**
 * @group mysql
 */
class HydrationMetricsTest extends TestCase
{
    public function test_hydration_fast_path_and_metrics(): void
    {
        self::$orm->metricsReset();
        $before = self::$orm->metrics();
        static::assertIsArray($before);
        static::assertArrayHasKey('hydration_fastpath_uses', $before);
        static::assertSame(0, $before['hydration_fastpath_uses']);

        // Fast-path elegible: VersaModel base, select '*', sin relaciones
        $all = self::$orm->table('users')->findAll();
        static::assertNotEmpty($all);
        $after = self::$orm->metrics();
        static::assertGreaterThanOrEqual(1, $after['hydration_fastpath_uses']);
        static::assertGreaterThan(0, $after['hydration_fastpath_rows']);
        static::assertGreaterThan(0, $after['hydration_fastpath_ms']);
        static::assertGreaterThan(0, $after['objects_hydrated']);

        // Uso de first (fast-path single row) y ver incremento de objetos
        $beforeObjs = $after['objects_hydrated'];
        $one = self::$orm->table('users')->first();
        static::assertNotNull($one);
        $after2 = self::$orm->metrics();
        static::assertGreaterThan($beforeObjs, $after2['objects_hydrated']);
    }
}
