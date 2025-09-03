<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\Relations\BelongsTo;
use VersaORM\VersaModel;

class QBStubForBelongs extends QueryBuilder
{
    public array $called = [];

    public function __construct()
    {
        // bypass parent
    }

    public function where(string $column, string $op, $val): self
    {
        $this->called[] = ['where', $column, $op, $val];

        return $this;
    }

    public function findOne(): null|VersaModel
    {
        $this->called[] = ['findOne'];

        return null;
    }
}

class ModelStubForRel extends VersaModel
{
    private array $attrs = [];

    public function __construct(array $attrs = [])
    {
        $this->attrs = $attrs;
    }

    public function getAttribute(string $key)
    {
        return $this->attrs[$key] ?? null;
    }
}

/**
 * @group sqlite
 */
final class RelationsBelongsToTest extends TestCase
{
    public function testBelongsToAddsConstraintsAndDelegates(): void
    {
        $qb = new QBStubForBelongs();
        $parent = new ModelStubForRel(['author_id' => 7]);

        $rel = new BelongsTo($qb, $parent, 'author_id', 'id', 'author');

        // calling query() should add constraints
        $q = $rel->query();
        $this->assertSame($qb, $q);
        $this->assertEquals(['where', 'id', '=', 7], $qb->called[0]);

        // calling getResults triggers findOne()
        $qb->called = [];
        $res = $rel->getResults();
        $this->assertNull($res);
        $this->assertEquals('findOne', $qb->called[1][0]);
    }
}
