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
        $this->assertIsArray($before);
        $this->assertArrayHasKey('hydration_fastpath_uses', $before);
        $this->assertSame(0, $before['hydration_fastpath_uses']);

        // Fast-path elegible: VersaModel base, select '*', sin relaciones
        $all = self::$orm->table('users')->findAll();
        $this->assertNotEmpty($all);
        $after = self::$orm->metrics();
        $this->assertGreaterThanOrEqual(1, $after['hydration_fastpath_uses']);
        $this->assertGreaterThan(0, $after['hydration_fastpath_rows']);
        $this->assertGreaterThan(0, $after['hydration_fastpath_ms']);
        $this->assertGreaterThan(0, $after['objects_hydrated']);

        // Uso de first (fast-path single row) y ver incremento de objetos
        $beforeObjs = $after['objects_hydrated'];
        $one = self::$orm->table('users')->first();
        $this->assertNotNull($one);
        $after2 = self::$orm->metrics();
        $this->assertGreaterThan($beforeObjs, $after2['objects_hydrated']);
    }
}
