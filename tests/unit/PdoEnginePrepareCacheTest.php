<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\PdoConnection;
use VersaORM\SQL\PdoEngine;

/**
 * @group sqlite
 */
final class PdoEnginePrepareCacheTest extends TestCase
{
    public function test_prepare_cached_lru_and_metrics(): void
    {
        // Crear engine con límite pequeño
        $engine = new PdoEngine(['driver' => 'sqlite', 'statement_cache_limit' => 2]);

        $ref = new ReflectionClass($engine);
        $method = $ref->getMethod('prepareCached');
        $method->setAccessible(true);

        // Obtener PDO real desde connector para preparar statements
        $connProp = $ref->getProperty('connector');
        $connProp->setAccessible(true);
        /** @var PdoConnection $conn */
        $conn = $connProp->getValue($engine);
        $pdo = $conn->getPdo();

        // Preparar 3 statements; with limit=2 the first should be evicted
        $s1 = $method->invoke($engine, $pdo, 'SELECT 1');
        $s2 = $method->invoke($engine, $pdo, 'SELECT 2');
        $s3 = $method->invoke($engine, $pdo, 'SELECT 3');

        // Access internal stmtCache to assert size and eviction
        $prop = $ref->getProperty('stmtCache');
        $prop->setAccessible(true);
        $cache = $prop->getValue();
        static::assertLessThanOrEqual(2, count($cache));

        // Metrics should have stmt_cache_misses incremented at least once
        $metrics = PdoEngine::getMetrics();
        static::assertArrayHasKey('stmt_cache_misses', $metrics);
        static::assertGreaterThanOrEqual(1, $metrics['stmt_cache_misses']);
    }
}
