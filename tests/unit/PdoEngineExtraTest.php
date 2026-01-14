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
            self::assertIsInt($status);

            $res = $engine->execute('cache', ['action' => 'enable']);
            self::assertSame('cache enabled', $res);

            $stats = $engine->execute('cache', ['action' => 'stats']);
            self::assertIsArray($stats);
            self::assertArrayHasKey('enabled', $stats);

            // invalidate with no criteria on sqlite should skip
            $inv = $engine->execute('cache', ['action' => 'invalidate']);
            self::assertSame('cache invalidation skipped (no criteria)', $inv);

            // clear should work
            $clear = $engine->execute('cache', ['action' => 'clear']);
            self::assertSame('cache cleared', $clear);

            // unsupported action throws
            $this->expectException(VersaORMException::class);
            $engine->execute('cache', ['action' => 'unsupported_action_zz']);
        }

        public function testHydrationMetricsAndReset(): void
        {
            PdoEngine::resetMetrics();
            $m = PdoEngine::getMetrics();
            self::assertIsArray($m);
            self::assertSame(0, $m['objects_hydrated']);

            PdoEngine::recordHydration(3, 12.34);
            $m2 = PdoEngine::getMetrics();
            self::assertSame(3, $m2['objects_hydrated']);
            self::assertEqualsWithDelta(12.34, $m2['hydration_ms'], 0.001);

            PdoEngine::recordHydrationFast(2, 5.5);
            $m3 = PdoEngine::getMetrics();
            self::assertSame(5, $m3['objects_hydrated']);
            self::assertSame(1, $m3['hydration_fastpath_uses']);
            self::assertSame(2, $m3['hydration_fastpath_rows']);
        }

        public function testForceDisconnectAndSetLogger(): void
        {
            $engine = new PdoEngine(['driver' => 'sqlite', 'database' => ':memory:']);

            $called = [];
            $engine->setLogger(static function (string $msg, array $ctx = []) use (&$called) {
                $called[] = $msg;
            });

            // forceDisconnect should not throw
            $engine->forceDisconnect();

            self::assertIsArray($called);
        }
    }
}
