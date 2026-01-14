<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\Relations\HasOne;
use VersaORM\VersaModel;

class QBStubForHasOne extends QueryBuilder
{
    public array $called = [];

    public function __construct()
    {
        // parent signature: ($orm, string $table, ?string $modelClass = null)
        parent::__construct([], 'children');
    }

    public function where(string $column, string $op, $val): self
    {
        $this->called[] = ['where', $column, $op, $val];

        return $this;
    }

    public function findOne(): ?VersaModel
    {
        $this->called[] = ['findOne'];

        return null;
    }
}

class ModelStubForHasOne extends VersaModel
{
    private array $attrs = [];

    public function __construct(array $attrs = [])
    {
        parent::__construct('parents', null);
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
final class RelationsHasOneTest extends TestCase
{
    public function testHasOneAddsConstraintsAndDelegates(): void
    {
        $qb = new QBStubForHasOne();
        $parent = new ModelStubForHasOne(['id' => 99]);

        $rel = new HasOne($qb, $parent, 'owner_id', 'id');

        $q = $rel->query();
        self::assertSame($qb, $q);
        self::assertSame(['where', 'owner_id', '=', 99], $qb->called[0]);

        $qb->called = [];
        $res = $rel->getResults();
        self::assertNull($res);
        self::assertSame('findOne', $qb->called[1][0]);
    }
}
