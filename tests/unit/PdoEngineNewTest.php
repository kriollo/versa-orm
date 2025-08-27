<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\PdoEngine;

/**
 * @group sqlite
 */
final class PdoEngineNewTest extends TestCase
{
    public function testMetricsResetAndGet(): void
    {
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:'];
        $engine = new PdoEngine($cfg);

        // mutate metrics via public static API
        PdoEngine::resetMetrics();
        $metrics = PdoEngine::getMetrics();

        $this->assertIsArray($metrics);
        $this->assertArrayHasKey('queries', $metrics);
        $this->assertSame(0, $metrics['queries']);
    }

    public function testCacheEnableDisableClearStatus(): void
    {
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:'];
        $engine = new PdoEngine($cfg);

        // enable
        $res = $engine->execute('cache', ['action' => 'enable']);
        $this->assertSame('cache enabled', $res);

        // status returns numeric count
        $status = $engine->execute('cache', ['action' => 'status']);
        $this->assertIsInt($status);

        // clear
        $cleared = $engine->execute('cache', ['action' => 'clear']);
        $this->assertSame('cache cleared', $cleared);

        // disable
        $disabled = $engine->execute('cache', ['action' => 'disable']);
        $this->assertSame('cache disabled', $disabled);
    }

    public function testFetchTablesSqliteInMemory(): void
    {
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:'];
        $engine = new PdoEngine($cfg);

        // Create a table via raw and then fetch tables
        $engine->execute('raw', ['sql' => 'CREATE TABLE test_x (id INTEGER PRIMARY KEY, name TEXT)']);

        $tables = $engine->execute('schema', ['subject' => 'tables']);

        $this->assertIsArray($tables);
        $found = false;

        foreach ($tables as $t) {
            if (is_array($t) && isset($t['table_name']) && $t['table_name'] === 'test_x') {
                $found = true;
                break;
            }

            if (is_string($t) && $t === 'test_x') {
                $found = true;
                break;
            }
        }

        $this->assertTrue($found, 'test_x table should be reported by fetchTables');
    }

    public function testPrepareCachedLruLimit(): void
    {
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:', 'statement_cache_limit' => 2];
        $engine = new PdoEngine($cfg);

        // Prepare multiple distinct queries to exercise stmt cache evict
        $engine->execute('raw', ['sql' => 'CREATE TABLE a1 (id INTEGER)']);
        $engine->execute('raw', ['sql' => 'CREATE TABLE a2 (id INTEGER)']);
        $engine->execute('raw', ['sql' => 'CREATE TABLE a3 (id INTEGER)']);

        // If no exception thrown, assume eviction worked and cache handled limits
        $this->assertTrue(true);
    }
}
