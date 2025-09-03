<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../vendor/autoload.php';

use VersaORM\SQL\PdoEngine;

class PdoEngineMetricsCacheTest extends TestCase
{
    public function setUp(): void
    {
        // reset metrics between tests
        PdoEngine::resetMetrics();
    }

    public function testMetricsRecordingAndReset(): void
    {
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:'];
        $engine = new PdoEngine($cfg);

        $metrics = PdoEngine::getMetrics();
        static::assertIsArray($metrics);
        static::assertArrayHasKey('queries', $metrics);

        // Record hydration with positive and non-positive counts
        PdoEngine::recordHydration(3, 10.0);
        PdoEngine::recordHydration(0, 5.0); // no-op

        $m2 = PdoEngine::getMetrics();
        static::assertSame(3, $m2['objects_hydrated']);

        PdoEngine::resetMetrics();
        $m3 = PdoEngine::getMetrics();
        static::assertSame(0, $m3['objects_hydrated']);
    }

    public function testCacheEnableClearStatus(): void
    {
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:'];
        $engine = new PdoEngine($cfg);

        $res = $engine->execute('cache', ['action' => 'enable']);
        static::assertSame('cache enabled', $res);

        $status = $engine->execute('cache', ['action' => 'status']);
        static::assertIsInt($status);

        $cleared = $engine->execute('cache', ['action' => 'clear']);
        static::assertSame('cache cleared', $cleared);
    }
}
