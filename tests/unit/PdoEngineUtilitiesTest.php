<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\PdoEngine;

/**
 * @group sqlite
 */
final class PdoEngineUtilitiesTest extends TestCase
{
    protected function tearDown(): void
    {
        // Asegurar estado limpio entre tests
        PdoEngine::resetMetrics();
        // Limpiar caché estática usando reflexión
        $ref = new ReflectionClass(PdoEngine::class);
        $prop = $ref->getProperty('queryCache');
        $prop->setAccessible(true);
        $prop->setValue([]);
        $idx = $ref->getProperty('tableKeyIndex');
        $idx->setAccessible(true);
        $idx->setValue([]);
    }

    public function test_metrics_and_hydration_accumulate(): void
    {
        $m = PdoEngine::getMetrics();
        self::assertIsArray($m);

        PdoEngine::resetMetrics();
        $m2 = PdoEngine::getMetrics();
        self::assertSame(0, $m2['objects_hydrated']);

        PdoEngine::recordHydration(3, 5.5);
        $after = PdoEngine::getMetrics();
        self::assertSame(3, $after['objects_hydrated']);
        self::assertEqualsWithDelta(5.5, $after['hydration_ms'], 0.001);

        PdoEngine::recordHydrationFast(2, 1.25);
        $fast = PdoEngine::getMetrics();
        self::assertSame(5, $fast['objects_hydrated']);
        self::assertGreaterThanOrEqual(1, $fast['hydration_fastpath_uses']);
    }

    public function test_make_cache_key_and_extract_tables(): void
    {
        $engine = new PdoEngine(['driver' => 'sqlite']);
        $ref = new ReflectionClass($engine);

        $mk = $ref->getMethod('makeCacheKey');
        $mk->setAccessible(true);

        $key1 = $mk->invoke($engine, 'SELECT * FROM users WHERE id = ?', [1], 'first');
        $key2 = $mk->invoke($engine, 'SELECT * FROM users WHERE id = ?', [1], 'first');
        self::assertSame($key1, $key2, 'Same inputs must produce same cache key');

        $ext = $ref->getMethod('extractTablesFromSql');
        $ext->setAccessible(true);

        $tables = $ext->invoke($engine, 'SELECT u.id, p.name FROM users u JOIN posts p ON p.user_id = u.id');
        self::assertIsArray($tables);
        self::assertContains('users', $tables);
        self::assertContains('posts', $tables);
    }

    public function test_store_in_cache_indexes_table_keys(): void
    {
        $engine = new PdoEngine(['driver' => 'sqlite']);
        $ref = new ReflectionClass($engine);

        $store = $ref->getMethod('storeInCache');
        $store->setAccessible(true);

        $sql = 'SELECT * FROM users WHERE active = 1';
        $store->invoke($engine, $sql, [], 'get', [['id' => 1]]);

        $prop = $ref->getProperty('queryCache');
        $prop->setAccessible(true);
        $cache = $prop->getValue();
        self::assertNotEmpty($cache);

        $idx = $ref->getProperty('tableKeyIndex');
        $idx->setAccessible(true);
        $tableIndex = $idx->getValue();
        self::assertArrayHasKey('users', $tableIndex);
        self::assertNotEmpty($tableIndex['users']);
    }
}
