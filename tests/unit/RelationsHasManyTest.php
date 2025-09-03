<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\Relations\HasMany;
use VersaORM\VersaModel;

if (!class_exists('THasManyQuery')) {
    class THasManyQuery extends QueryBuilder
    {
        public array $recordedWheres = [];

        public function __construct()
        {
            parent::__construct([], 'children');
        }

        public function where(string $column, string $operator, mixed $value): self
        {
            $this->recordedWheres[] = [$column, $operator, $value];

            return $this;
        }

        public function findAll(): array
        {
            return [];
        }
    }
}

if (!class_exists('THasManyModel')) {
    class THasManyModel extends VersaModel
    {
        public function __construct()
        {
            parent::__construct('parents', null);
        }

        public function getAttribute(string $k): mixed
        {
            return 1;
        }

        public function getKeyName(): string
        {
            return 'id';
        }
    }
}

/**
 * @group sqlite
 */
final class RelationsHasManyTest extends TestCase
{
    public function testHasManyAddsConstraintsAndDelegates(): void
    {
        $query = new THasManyQuery();
        $parent = new THasManyModel();

        $relation = new HasMany($query, $parent, 'parent_id', 'id');

        $results = $relation->getResults();

        static::assertIsArray($results);
        static::assertNotEmpty($query->recordedWheres);
    }
}

/**
 * Additional quick reflection test to ensure methods exist.
 */
final class RelationsHasManyReflectionTest extends TestCase
{
    /** @group sqlite */
    public function test_hasmany_class_exists_and_methods(): void
    {
        static::assertTrue(class_exists('\VersaORM\Relations\HasMany'));

        $r = new ReflectionClass('\VersaORM\Relations\HasMany');

        static::assertTrue($r->hasMethod('__call'));
        static::assertTrue($r->hasMethod('query'));
        static::assertTrue($r->hasMethod('getResults'));
    }
}
