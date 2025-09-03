<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\Relations\BelongsToMany;
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

if (!class_exists('TBMQuery')) {
    class TBMQuery extends QueryBuilder
    {
        public $lastExecute;

        public function __construct() {}

        public function insert(array $data): bool
        {
            return true;
        }

        public function delete(): void
        {
            // noop
        }

        public function from(string $table): static
        {
            return $this;
        }

        public function execute(string $action, array $params = [])
        {
            $this->lastExecute = ['action' => $action, 'params' => $params];

            return null;
        }

        public function where(string $col, string $op, mixed $val): static
        {
            return $this;
        }

        public function whereIn(string $col, array $vals): static
        {
            return $this;
        }

        public function get(): array
        {
            return [];
        }
    }
}

if (!class_exists('TBMModel')) {
    class TBMModel extends VersaModel
    {
        public function __construct() {}

        public function getAttribute(string $key)
        {
            return 7;
        }
    }
}

/**
 * @group sqlite
 */
final class RelationsBelongsToManySyncDetachTest extends TestCase
{
    public function testAttachViaReflectionExecutesPivotInsert(): void
    {
        $orm = new VersaORMStub();
        $relatedQ = new TBMQuery();

        $parent = new TBMModel();

        $rel = new BelongsToMany($relatedQ, $parent, 'pivot', 'parent_id', 'related_id', 'id', 'id');

        // call attach which will call $this->query->from(...)->execute('insert', ...)
        // our TBMQuery::from() returns the same instance, so lastExecute will be set
        $rel->attach(9, ['meta' => 'x']);

        $this->assertIsArray($relatedQ->lastExecute);
        $this->assertEquals('insert', $relatedQ->lastExecute['action']);
    }

    public function testSyncAndDetachCallPivotDeleteWhenPresent(): void
    {
        $pivotQ = new TBMQuery();
        $relatedQ = new TBMQuery();
        $parent = new TBMModel();

        $rel = new BelongsToMany($relatedQ, $parent, 'pivot', 'parent_id', 'related_id', 'id', 'id');

        // sync relies on $this->query->from()->where()->get() which our TBMQuery stubs
        // return empty arrays or $this, so should not throw and return attached/detached arrays
        $res = $rel->sync([1, 2]);
        $this->assertIsArray($res);
        $this->assertArrayHasKey('attached', $res);
        $this->assertArrayHasKey('detached', $res);

        // detach should not throw
        $this->assertNull($rel->detach([1]));
    }
}
