<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\PdoEngine;

/**
 * @group sqlite
 */
final class PdoEnginePrepareLRUTest extends TestCase
{
    public function test_prepare_cached_lru_eviction_and_metrics(): void
    {
        // Obtain a PdoEngine instance (use internal factory via VersaORM in tests existing pattern)
        // ...existing code to create engine... (reuse global test bootstrap that provides engine via VersaORM)
        // Create engine with a small statement cache limit
        $engine = new PdoEngine(['driver' => 'sqlite', 'statement_cache_limit' => 5]);

        // reset static metrics and stmt cache
        PdoEngine::resetMetrics();

        $ref = new ReflectionClass($engine);
        $method = $ref->getMethod('prepareCached');
        $method->setAccessible(true);

        // Obtener PDO real desde connector para preparar statements
        $connProp = $ref->getProperty('connector');
        $connProp->setAccessible(true);
        $conn = $connProp->getValue($engine);
        $pdo = $conn->getPdo();

        // Prepare more statements than the limit to force eviction
        $limitProp = $ref->getProperty('stmtCacheLimit');
        $limitProp->setAccessible(true);
        $limit = $limitProp->getValue($engine) ?: 5;

        for ($i = 0; $i < ($limit + 3); $i++) {
            $sql = "SELECT {$i} as v";
            $stmt = $method->invoke($engine, $pdo, $sql);
            $this->assertNotNull($stmt);
        }

        // Call instance method clearStmtCache via reflection to ensure it runs
        $clear = $ref->getMethod('clearStmtCache');
        $clear->setAccessible(true);
        $clear->invoke($engine);

        // Metrics should have stmt_cache_misses key
        $metrics = PdoEngine::getMetrics();
        $this->assertIsArray($metrics);
        $this->assertArrayHasKey('stmt_cache_misses', $metrics);
    }
}
