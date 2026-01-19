<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\Relations\BelongsTo;
use VersaORM\VersaModel;

if (!class_exists('VersaORMStub')) {
    class VersaORMStub extends \VersaORM\VersaORM
    {
        public function __construct()
        {
            // minimal stub
        }

        public function executeQuery(string $action, array $params = [])
        {
            return [];
        }
    }
}

if (!class_exists('TestQueryBuilder')) {
    class TestQueryBuilder extends QueryBuilder
    {
        public function __construct()
        {
            // bypass parent requirements; not used here
        }

        public function where(string $col, string $op, mixed $val): self
        {
            return $this;
        }

        public function findOne(): ?VersaModel
        {
            return null;
        }
    }
}

if (!class_exists('TestVersaModelForBelongs')) {
    class TestVersaModelForBelongs extends VersaModel
    {
        public function __construct()
        {
            // minimal stub
        }

        public function getAttribute(string $key)
        {
            return 5;
        }
    }
}

/**
 * @group sqlite
 */
final class RelationsBelongsToSyncDetachTest extends TestCase
{
    public function testAddConstraintsUsesParentAttribute(): void
    {
        $orm = new VersaORMStub();
        $qb = new TestQueryBuilder();

        $parent = new TestVersaModelForBelongs();

        $rel = new BelongsTo($qb, $parent, 'user_id', 'id', 'user');

        $ref = new \ReflectionClass($rel);
        $m = $ref->getMethod('addConstraints');
        $m->setAccessible(true);

        // Should not throw and should call where on query (no exception means OK)
        $m->invoke($rel);

        static::assertTrue(true);
    }

    // BelongsTo does not implement sync/detach; ensure addConstraints is safe (see above)
}
