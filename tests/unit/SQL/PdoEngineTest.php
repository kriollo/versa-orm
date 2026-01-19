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

        static::assertIsArray($metrics);
        static::assertSame(0, $metrics['queries']);
        static::assertSame(0, $metrics['objects_hydrated']);

        // record single hydration
        PdoEngine::recordHydration(3, 12.5);

        $metricsAfter = PdoEngine::getMetrics();
        static::assertSame(3, $metricsAfter['objects_hydrated']);
        static::assertGreaterThanOrEqual(12.5, $metricsAfter['hydration_ms']);
    }

    public function test_record_hydration_fast_accumulates_and_calls_recordHydration(): void
    {
        $before = PdoEngine::getMetrics();
        static::assertSame(0, $before['hydration_fastpath_uses']);

        PdoEngine::recordHydrationFast(5, 7.2);

        $after = PdoEngine::getMetrics();
        static::assertSame(1, $after['hydration_fastpath_uses']);
        static::assertSame(5, $after['hydration_fastpath_rows']);
        static::assertGreaterThanOrEqual(7.2, $after['hydration_fastpath_ms']);
        // also accumulated in general hydration metrics
        static::assertSame(5, $after['objects_hydrated']);
        static::assertGreaterThanOrEqual(7.2, $after['hydration_ms']);
    }

    public function test_reset_metrics_clears_counts(): void
    {
        PdoEngine::recordHydration(2, 1.1);
        PdoEngine::recordHydrationFast(4, 2.2);

        $m = PdoEngine::getMetrics();
        static::assertGreaterThan(0, $m['objects_hydrated']);

        PdoEngine::resetMetrics();

        $cleared = PdoEngine::getMetrics();
        static::assertSame(0, $cleared['objects_hydrated']);
        static::assertSame(0, $cleared['hydration_fastpath_uses']);
    }
}
