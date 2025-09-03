<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\VersaModel;

if (!class_exists('TBtmQuery')) {
    class TBtmQuery extends QueryBuilder
    {
        public array $called = [];

        public function __construct()
        {
            parent::__construct([], 'related');
        }

        public function from(string $table): self
        {
            $this->called[] = ['from', $table];

            return $this;
        }

        public function where(string $column, string $operator, mixed $value): self
        {
            $this->called[] = ['where', $column, $operator, $value];

            return $this;
        }

        public function get(): array
        {
            return [];
        }

        // QueryBuilder::delete(): void in real class, keep signature compatible
        public function delete(): void
        {
            $this->called[] = ['delete'];
        }

        // execute is protected in QueryBuilder; attach uses reflection to call it
        protected function execute(string $action, array $params = [])
        {
            $this->called[] = ['execute', $action, $params];

            return [];
        }
    }
}

if (!class_exists('TBtmModel')) {
    class TBtmModel extends VersaModel
    {
        public function __construct()
        {
            parent::__construct('parent', null);
        }

        public function getAttribute(string $k): mixed
        {
            return 7;
        }

        public function getKeyName(): string
        {
            return 'id';
        }
    }
}

/** @group sqlite */
final class RelationsBelongsToManyTest extends TestCase
{
    public function test_attach_invokes_execute_on_pivot_query(): void
    {
        $query = new TBtmQuery();
        $parent = new TBtmModel();

        $relation = new \VersaORM\Relations\BelongsToMany(
            $query,
            $parent,
            'pivot',
            'parent_id',
            'related_id',
            'id',
            'id',
        );

        // attach should call from(...) then call execute via reflection
        $relation->attach(42, ['extra' => 'x']);

        static::assertNotEmpty($query->called);
        // Expect at least a 'from' and an 'execute' recorded
        static::assertSame('from', $query->called[0][0]);
        $foundExecute = false;
        foreach ($query->called as $c) {
            if ($c[0] === 'execute') {
                $foundExecute = true;
                break;
            }
        }
        static::assertTrue($foundExecute);
    }
}

/**
 * Reflection-based quick checks for BelongsToMany methods.
 */
final class RelationsBelongsToManyReflectionTest extends TestCase
{
    /** @group sqlite */
    public function test_belongstomany_class_exists_and_methods(): void
    {
        static::assertTrue(class_exists('\VersaORM\Relations\BelongsToMany'));

        $r = new ReflectionClass('\VersaORM\Relations\BelongsToMany');

        static::assertTrue($r->hasMethod('__call'));
        static::assertTrue($r->hasMethod('query'));
        static::assertTrue($r->hasMethod('getResults'));
        static::assertTrue($r->hasMethod('attach'));
        static::assertTrue($r->hasMethod('sync'));
        static::assertTrue($r->hasMethod('detach'));
        static::assertTrue($r->hasMethod('addConstraints'));
    }
}
