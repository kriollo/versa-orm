<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\Relations\Relation;
use VersaORM\VersaModel;

/**
 * @group sqlite
 */
final class RelationTest extends TestCase
{
    // Concrete minimal implementation to exercise the abstract methods
    public function testAddConstraintsIsAppliedAndGetResultsReturnsQueryResult(): void
    {
        // Create a concrete anonymous subclass of Relation
        $qb = $this->createMock(QueryBuilder::class);
        $parent = $this->createMock(VersaModel::class);

        // Expect where() to be called once by addConstraints()
        $qb->expects($this->once())->method('where')->with('foo', '=', 'bar');

        // get() should return a predictable result
        $qb->method('get')->willReturn(['item1', 'item2']);

        $relation = new class($qb, $parent) extends Relation {
            public function getResults(): mixed
            {
                // ensure constraints are applied
                $this->addConstraints();

                return $this->query->get();
            }

            protected function addConstraints(): void
            {
                $this->query->where('foo', '=', 'bar');
            }
        };

        $res = $relation->getResults();
        static::assertSame(['item1', 'item2'], $res);
    }
}
