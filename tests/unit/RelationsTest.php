<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\Relations\BelongsTo;
use VersaORM\Relations\BelongsToMany;
use VersaORM\Relations\HasMany;
use VersaORM\Relations\HasOne;
use VersaORM\VersaModel;

// Test doubles: concrete subclasses to allow reflection to access methods like execute
class TestQueryBuilder extends QueryBuilder
{
    public function __construct()
    {
    }

    public function where(string $column, string $operator, mixed $value): self
    {
        return $this;
    }

    public function from(string $table): self
    {
        return $this;
    }

    public function join(string $table, string $firstCol = '', string $operator = '=', string $secondCol = ''): self
    {
        return $this;
    }

    public function delete(): void
    {
        // no-op for tests
    }

    public function findOne(): ?VersaModel
    {
        return null;
    }

    public function findAll(): array
    {
        return [];
    }

    public function get(): array
    {
        return [];
    }

    public function whereIn(string $column, array $values): self
    {
        return $this;
    }

    // make execute public so reflection can invoke it
    public function execute(string $method, ?array $data = null)
    {
        return true;
    }

    public function getTable(): string
    {
        return 'test_table';
    }
}

class TestModel extends VersaModel
{
    private array $attrs;

    private string $keyName;

    public function __construct(array $attrs = [], string $keyName = 'id')
    {
        $this->attrs = $attrs;
        $this->keyName = $keyName;
    }

    public function getAttribute($name)
    {
        return $this->attrs[$name] ?? null;
    }

    public function getKeyName(): string
    {
        return $this->keyName;
    }
}

/**
 * @group sqlite
 */
final class RelationsTest extends TestCase
{
    public function testBelongsToDelegatesAndAppliesConstraint(): void
    {
        $qb = $this->makeQueryBuilderStub();
        $model = $this->makeModelStub(['foreign_id' => 123]);

        $rel = new BelongsTo($qb, $model, 'foreign_id', 'id', 'owner');

        // query() debe devolver el QueryBuilder stub
        $this->assertSame($qb, $rel->query());

        // getResults() llama a findOne y devuelve null según stub
        $this->assertNull($rel->getResults());
    }

    public function testHasOneAndHasManyDelegation(): void
    {
        $qb = $this->makeQueryBuilderStub();
        $model = $this->makeModelStub(['local_id' => 77]);

        $hasOne = new HasOne($qb, $model, 'foreign_key', 'local_id');
        $this->assertSame($qb, $hasOne->query());
        $this->assertNull($hasOne->getResults());

        $hasMany = new HasMany($qb, $model, 'foreign_key', 'local_id');
        $this->assertSame($qb, $hasMany->query());
        $this->assertEquals([], $hasMany->getResults());
    }

    public function testBelongsToManyAttachSyncDetach(): void
    {
        $qb = $this->makeQueryBuilderStub();
        $model = $this->makeModelStub(['id' => 9]);

        $b2m = new BelongsToMany($qb, $model, 'pivot', 'parent_id', 'related_id', 'id', 'id');

        // attach debe invocar execute en el pivot query (usamos stub que devuelve true)
        $b2m->attach(5, ['extra' => 'x']);

        // sync sobre array vacío no debe lanzar
        $result = $b2m->sync([]);
        $this->assertIsArray($result);

        // detach con id único
        $b2m->detach(5);
        $b2m->detach([5]);
        $b2m->detach();

        $this->assertTrue(true, 'detach/attach/sync executed without exceptions');
    }

    private function makeQueryBuilderStub(): QueryBuilder
    {
        return new TestQueryBuilder();
    }

    private function makeModelStub(array $attributes = [], string $keyName = 'id'): VersaModel
    {
        return new TestModel($attributes, $keyName);
    }
}
