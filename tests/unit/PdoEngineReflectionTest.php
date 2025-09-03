<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\PdoEngine;
use VersaORM\VersaORMException;

final class PdoEngineReflectionTest extends TestCase
{
    public function setUp(): void
    {
        // Asegurar metrics limpias entre tests
        PdoEngine::resetMetrics();
    }

    public function test_cache_enable_clear_and_invalidation_with_sqlite()
    {
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:'];
        $engine = new PdoEngine($cfg);

        // enable cache
        static::assertSame('cache enabled', $engine->execute('cache', ['action' => 'enable']));

        // crear tabla y datos via raw
        $engine->execute('raw', [
            'query' => 'CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)',
            'bindings' => [],
        ]);
        $engine->execute('raw', ['query' => "INSERT INTO users (name) VALUES ('Alice')", 'bindings' => []]);

        // primera lectura (llenará la cache)
        $rows = $engine->execute('raw', ['query' => 'SELECT * FROM users', 'bindings' => []]);
        static::assertIsArray($rows);
        static::assertCount(1, $rows);

        // stats debe indicar enabled true y al menos 1 entrada
        $stats = $engine->execute('cache', ['action' => 'stats']);
        static::assertIsArray($stats);
        static::assertArrayHasKey('enabled', $stats);
        static::assertTrue($stats['enabled']);

        // invalidate without criteria on sqlite debe devolver mensaje benigno
        static::assertSame('cache invalidation skipped (no criteria)', $engine->execute('cache', [
            'action' => 'invalidate',
        ]));

        // clear cache
        static::assertSame('cache cleared', $engine->execute('cache', ['action' => 'clear']));
        static::assertSame(0, $engine->execute('cache', ['action' => 'status']));
    }

    public function test_metrics_recording_and_force_disconnect()
    {
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:'];
        $engine = new PdoEngine($cfg);

        $metrics = PdoEngine::getMetrics();
        static::assertIsArray($metrics);
        static::assertSame(0, $metrics['queries']);

        // crear tabla y ejecutar una consulta para incrementar métricas
        $engine->execute('raw', ['query' => 'CREATE TABLE t1 (id INTEGER PRIMARY KEY, v INT)', 'bindings' => []]);
        $engine->execute('raw', ['query' => 'INSERT INTO t1 (v) VALUES (1)', 'bindings' => []]);
        $res = $engine->execute('raw', ['query' => 'SELECT * FROM t1', 'bindings' => []]);

        $metrics2 = PdoEngine::getMetrics();
        static::assertGreaterThanOrEqual(1, $metrics2['queries']);

        // forceDisconnect no debe lanzar
        $engine->forceDisconnect();
        static::assertTrue(true);
    }

    public function test_cache_invalid_action_throws()
    {
        $this->expectException(VersaORMException::class);
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:'];
        $engine = new PdoEngine($cfg);
        $engine->execute('cache', ['action' => 'nope']);
    }
}
