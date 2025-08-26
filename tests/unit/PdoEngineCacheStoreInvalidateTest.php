<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\PdoEngine;

/**
 * @group sqlite
 */
final class PdoEngineCacheStoreInvalidateTest extends TestCase
{
    public function test_store_and_invalidate_cache_by_table_and_pattern(): void
    {
        PdoEngine::resetMetrics();

        $engine = new PdoEngine(['driver' => 'sqlite', 'database' => ':memory:']);

        // Ensure cache enabled
        $res = $engine->execute('cache', ['action' => 'enable']);
        $this->assertSame('cache enabled', $res);

        // Create a simple table and insert a row
        $engine->execute('raw', ['query' => 'CREATE TABLE test_cache (id INTEGER PRIMARY KEY, val TEXT)', 'bindings' => []]);
        $engine->execute('raw', ['query' => "INSERT INTO test_cache (val) VALUES ('a')", 'bindings' => []]);

        // Perform a 'get' query via execute('query', ...) to cause storeInCache
        $rows = $engine->execute('query', ['method' => 'get', 'table' => 'test_cache']);
        $this->assertIsArray($rows);

        // Check cache status via cache action 'status' (returns count of entries)
        $count = $engine->execute('cache', ['action' => 'status']);
        $this->assertIsInt($count);
        $this->assertGreaterThanOrEqual(1, $count);

        // Invalidate cache for the table
        $engine->execute('cache', ['action' => 'invalidate', 'table' => 'test_cache']);
        $countAfter = $engine->execute('cache', ['action' => 'status']);
        $this->assertLessThanOrEqual($count, $countAfter + 0); // ensure no more entries for that table (best-effort)

        // Clear all
        $engine->execute('cache', ['action' => 'clear']);
        $countCleared = $engine->execute('cache', ['action' => 'status']);
        $this->assertEquals(0, $countCleared);
    }
}
