<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\PdoEngine;

/**
 * @group sqlite
 */
final class PdoEngineMetricsTest extends TestCase
{
    public function test_metrics_and_hydration_recording(): void
    {
        PdoEngine::resetMetrics();

        $config = ['driver' => 'sqlite', 'database' => ':memory:'];
        $engine = new PdoEngine($config);

        // Use execute('raw', ['query' => '...']) which PdoEngine expects to record a query
        $res = $engine->execute('raw', ['query' => 'SELECT 1', 'bindings' => []]);

        $metrics = PdoEngine::getMetrics();
        $this->assertArrayHasKey('queries', $metrics);
        $this->assertGreaterThanOrEqual(1, $metrics['queries']);

        // Record hydration and verify metrics updated
        PdoEngine::recordHydration(5, 12.3);
        $metrics = PdoEngine::getMetrics();
        $this->assertEquals(5, $metrics['objects_hydrated']);
        $this->assertGreaterThanOrEqual(12.3, $metrics['hydration_ms']);

        // Record fast hydration and verify it increments fastpath counters and accumulates
        PdoEngine::recordHydrationFast(2, 1.1);
        $metrics = PdoEngine::getMetrics();
        $this->assertEquals(1, $metrics['hydration_fastpath_uses']);
        $this->assertEquals(2, $metrics['hydration_fastpath_rows']);

        // Reset and ensure metrics are zeroed
        PdoEngine::resetMetrics();
        $metrics = PdoEngine::getMetrics();
        $this->assertEquals(0, $metrics['queries']);
        $this->assertEquals(0, $metrics['objects_hydrated']);
    }
}
