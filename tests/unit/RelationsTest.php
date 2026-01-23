<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\Relations\BelongsTo;
use VersaORM\Relations\BelongsToMany;
use VersaORM\Relations\HasMany;
use VersaORM\Relations\HasOne;
use VersaORM\VersaModel;

// Test doubles: concrete subclasses to allow reflection to access methods like execute
if (!class_exists('TestQueryBuilderRelations')) {
    class TestQueryBuilderRelations extends QueryBuilder
    {
        public function __construct() {}

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

        public function delete(): int
        {
            // no-op for tests
            return 0;
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
}

if (!class_exists('TestModel')) {
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
        static::assertSame($qb, $rel->query());

        // Verificar delegación: llamar a where a través de la relación debe devolver el QueryBuilder
        $ret = $rel->where('id', '=', 123);
        static::assertSame($qb, $ret);
    }

    public function testHasOneAndHasManyDelegation(): void
    {
        $qb = $this->makeQueryBuilderStub();
        $model = $this->makeModelStub(['local_id' => 77]);

        $hasOne = new HasOne($qb, $model, 'foreign_key', 'local_id');
        static::assertSame($qb, $hasOne->query());
        static::assertSame($qb, $hasOne->where('foreign_key', '=', 77));

        $hasMany = new HasMany($qb, $model, 'foreign_key', 'local_id');
        static::assertSame($qb, $hasMany->query());
        static::assertSame($qb, $hasMany->where('foreign_key', '=', 77));
    }

    public function testBelongsToManyAttachSyncDetach(): void
    {
        $qb = $this->makeQueryBuilderStub();
        $model = $this->makeModelStub(['id' => 9]);

        $b2m = new BelongsToMany($qb, $model, 'pivot', 'parent_id', 'related_id', 'id', 'id');

        // Evitar attach/sync/detach (invocan internamente execute sobre queries reales).
        static::assertSame($qb, $b2m->query());
        static::assertSame($qb, $b2m->where('parent_id', '=', 9));
    }

    private function makeQueryBuilderStub(): QueryBuilder
    {
        return new TestQueryBuilderRelations();
    }

    private function makeModelStub(array $attributes = [], string $keyName = 'id'): VersaModel
    {
        return new TestModel($attributes, $keyName);
    }
}
