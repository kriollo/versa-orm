<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\Relations\Relation;
use VersaORM\VersaModel;

// Dummy model that uses HasRelationships via VersaModel methods
class DummyRelationModel extends VersaModel
{
    public function __construct() {}

    // create a dummy relation method that returns a Relation-like object
    public function fakeRelation(): Relation
    {
        $qb = $this->newQuery();

        return new class($qb, $this) extends Relation {
            public function getResults(): mixed
            {
                return ['a'];
            }

            protected function addConstraints(): void
            {
                // no-op
            }
        };
    }
}

/**
 * @group sqlite
 */
final class HasRelationshipsTest extends TestCase
{
    public function testRelationLoadingAndSetRelation(): void
    {
        $m = new DummyRelationModel();

        static::assertFalse($m->relationLoaded('fakeRelation'));

        $m->setRelation('fakeRelation', ['x']);

        static::assertTrue($m->relationLoaded('fakeRelation'));
        static::assertSame(['x'], $m->getRelationValue('fakeRelation'));
        static::assertArrayHasKey('fakeRelation', $m->getRelations());
    }

    public function testCallMissingMethodThrows(): void
    {
        $this->expectException(Exception::class);
        $m = new DummyRelationModel();
        $m->nonexistentRelation();
    }
}
