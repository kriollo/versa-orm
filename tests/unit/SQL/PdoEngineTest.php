<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\PdoEngine;

/**
 * @group sqlite
 */
final class PdoEngineTest extends TestCase
{
    public function setUp(): void
    {
        // Asegurar estado limpio entre tests
        PdoEngine::resetMetrics();
    }

    public function test_metrics_start_empty_and_record_hydration(): void
    {
        $metrics = PdoEngine::getMetrics();

        $this->assertIsArray($metrics);
        $this->assertSame(0, $metrics['queries']);
        $this->assertSame(0, $metrics['objects_hydrated']);

        // record single hydration
        PdoEngine::recordHydration(3, 12.5);

        $metricsAfter = PdoEngine::getMetrics();
        $this->assertSame(3, $metricsAfter['objects_hydrated']);
        $this->assertGreaterThanOrEqual(12.5, $metricsAfter['hydration_ms']);
    }

    public function test_record_hydration_fast_accumulates_and_calls_recordHydration(): void
    {
        $before = PdoEngine::getMetrics();
        $this->assertSame(0, $before['hydration_fastpath_uses']);

        PdoEngine::recordHydrationFast(5, 7.2);

        $after = PdoEngine::getMetrics();
        $this->assertSame(1, $after['hydration_fastpath_uses']);
        $this->assertSame(5, $after['hydration_fastpath_rows']);
        $this->assertGreaterThanOrEqual(7.2, $after['hydration_fastpath_ms']);
        // also accumulated in general hydration metrics
        $this->assertSame(5, $after['objects_hydrated']);
        $this->assertGreaterThanOrEqual(7.2, $after['hydration_ms']);
    }

    public function test_reset_metrics_clears_counts(): void
    {
        PdoEngine::recordHydration(2, 1.1);
        PdoEngine::recordHydrationFast(4, 2.2);

        $m = PdoEngine::getMetrics();
        $this->assertGreaterThan(0, $m['objects_hydrated']);

        PdoEngine::resetMetrics();

        $cleared = PdoEngine::getMetrics();
        $this->assertSame(0, $cleared['objects_hydrated']);
        $this->assertSame(0, $cleared['hydration_fastpath_uses']);
    }
}
