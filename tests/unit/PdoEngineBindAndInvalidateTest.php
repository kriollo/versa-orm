<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PDO;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use VersaORM\SQL\PdoEngine;

/**
 * @group sqlite
 */
final class PdoEngineBindAndInvalidateTest extends TestCase
{
    public function test_bind_and_execute_and_invalidate_cache(): void
    {
        $engine = new PdoEngine(['driver' => 'sqlite']);
        $ref = new ReflectionClass($engine);

        $bind = $ref->getMethod('bindAndExecute');
        $bind->setAccessible(true);

        // Prepare a simple statement via connector PDO
        $connProp = $ref->getProperty('connector');
        $connProp->setAccessible(true);
        $conn = $connProp->getValue($engine);
        $pdo = $conn->getPdo();

        $stmt = $pdo->prepare('SELECT ? as v');
        $bind->invoke($engine, $stmt, [42]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        static::assertIsArray($row);

        // Test cache invalidation path: storeInCache then invalidateCacheForTable via reflection
        $store = $ref->getMethod('storeInCache');
        $store->setAccessible(true);
        $store->invoke($engine, 'SELECT * FROM users', [], 'get', [['id' => 1]]);

        $idxProp = $ref->getProperty('tableKeyIndex');
        $idxProp->setAccessible(true);
        $idx = $idxProp->getValue();
        static::assertArrayHasKey('users', $idx);

        $invalidate = $ref->getMethod('invalidateCacheForTable');
        $invalidate->setAccessible(true);
        $invalidate->invoke(null, 'users');

        $qc = $ref->getProperty('queryCache');
        $qc->setAccessible(true);
        $cache = $qc->getValue();
        static::assertEmpty($cache);
    }
}
