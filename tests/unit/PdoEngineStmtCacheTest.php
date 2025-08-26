<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\PdoEngine;

/**
 * @group sqlite
 */
final class PdoEngineStmtCacheTest extends TestCase
{
    public function test_stmt_cache_lru_and_metrics(): void
    {
        // Reset global metrics/state
        PdoEngine::resetMetrics();

        $config = ['driver' => 'sqlite', 'database' => ':memory:', 'statement_cache_limit' => 3];
        $engine = new PdoEngine($config);

        // Force some prepares with different SQL texts to populate stmt cache
        $pdo = (new ReflectionClass($engine))->getProperty('connector');
        $pdo->setAccessible(true);
        $connector = $pdo->getValue($engine);
        $getPdo = new ReflectionMethod(get_class($connector), 'getPdo');
        $getPdo->setAccessible(true);
        $dbh = $getPdo->invoke($connector);

        // Ensure stmt cache limit is set to 3 via constructor config
        $prepare = new ReflectionMethod(PdoEngine::class, 'prepareCached');
        $prepare->setAccessible(true);

        // Prepare 4 distinct statements to force eviction (limit=3)
        $prepare->invoke($engine, $dbh, 'SELECT 1');
        $prepare->invoke($engine, $dbh, 'SELECT 2');
        $prepare->invoke($engine, $dbh, 'SELECT 3');

        // After 3 prepares, stmt_cache_misses should be 3
        $metrics = PdoEngine::getMetrics();
        $this->assertGreaterThanOrEqual(3, $metrics['stmt_cache_misses']);

        // Access one of the earlier statements to create an LRU hit
        $prepare->invoke($engine, $dbh, 'SELECT 2');

        $metrics = PdoEngine::getMetrics();
        $this->assertGreaterThanOrEqual(1, $metrics['stmt_cache_hits']);

        // Add a fourth distinct statement to trigger eviction
        $prepare->invoke($engine, $dbh, 'SELECT 4');

        // Ensure stmt cache misses increased (>=4)
        $metrics = PdoEngine::getMetrics();
        $this->assertGreaterThanOrEqual(4, $metrics['stmt_cache_misses']);

        // Reset metrics and verify cleared
        PdoEngine::resetMetrics();
        $metrics = PdoEngine::getMetrics();
        $this->assertEquals(0, $metrics['stmt_cache_hits']);
        $this->assertEquals(0, $metrics['stmt_cache_misses']);
    }
}
