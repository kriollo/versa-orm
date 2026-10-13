<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

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

    public function findOne(): ?VersaModel
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
        static::assertSame($qb, $q);
        static::assertSame(['where', 'id', '=', 7], $qb->called[0]);

        // getResults() delega en findOne() SIN volver a aplicar las restricciones.
        // Antes el assert apuntaba a called[1] porque addConstraints() se ejecutaba en
        // cada entrada (query(), __call(), getResults()) y acumulaba un WHERE duplicado;
        // ese índice [1] era precisamente el síntoma del bug.
        $qb->called = [];
        $res = $rel->getResults();
        static::assertNull($res);
        static::assertSame('findOne', $qb->called[0][0]);
        static::assertCount(1, $qb->called, 'getResults() no debe reaplicar el WHERE');
    }
}
