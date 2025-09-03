<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\PdoEngine;
use VersaORM\VersaORMException;

if (!class_exists(PdoEngineExtraTest::class)) {
    /**
     * @group sqlite
     */
    final class PdoEngineExtraTest extends TestCase
    {
        public function testCacheEnableDisableClearStatusAndInvalidateSqlite(): void
        {
            $engine = new PdoEngine(['driver' => 'sqlite', 'database' => ':memory:']);

            // status initially int (entries count)
            $status = $engine->execute('cache', ['action' => 'status']);
            $this->assertIsInt($status);

            $res = $engine->execute('cache', ['action' => 'enable']);
            $this->assertSame('cache enabled', $res);

            $stats = $engine->execute('cache', ['action' => 'stats']);
            $this->assertIsArray($stats);
            $this->assertArrayHasKey('enabled', $stats);

            // invalidate with no criteria on sqlite should skip
            $inv = $engine->execute('cache', ['action' => 'invalidate']);
            $this->assertSame('cache invalidation skipped (no criteria)', $inv);

            // clear should work
            $clear = $engine->execute('cache', ['action' => 'clear']);
            $this->assertSame('cache cleared', $clear);

            // unsupported action throws
            $this->expectException(VersaORMException::class);
            $engine->execute('cache', ['action' => 'unsupported_action_zz']);
        }

        public function testHydrationMetricsAndReset(): void
        {
            PdoEngine::resetMetrics();
            $m = PdoEngine::getMetrics();
            $this->assertIsArray($m);
            $this->assertSame(0, $m['objects_hydrated']);

            PdoEngine::recordHydration(3, 12.34);
            $m2 = PdoEngine::getMetrics();
            $this->assertSame(3, $m2['objects_hydrated']);
            $this->assertEqualsWithDelta(12.34, $m2['hydration_ms'], 0.001);

            PdoEngine::recordHydrationFast(2, 5.5);
            $m3 = PdoEngine::getMetrics();
            $this->assertSame(5, $m3['objects_hydrated']);
            $this->assertSame(1, $m3['hydration_fastpath_uses']);
            $this->assertSame(2, $m3['hydration_fastpath_rows']);
        }

        public function testForceDisconnectAndSetLogger(): void
        {
            $engine = new PdoEngine(['driver' => 'sqlite', 'database' => ':memory:']);

            $called = [];
            $engine->setLogger(function (string $msg, array $ctx = []) use (&$called) {
                $called[] = $msg;
            });

            // forceDisconnect should not throw
            $engine->forceDisconnect();

            $this->assertIsArray($called);
        }
    }
}
