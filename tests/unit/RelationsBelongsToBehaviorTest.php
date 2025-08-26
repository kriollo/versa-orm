<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

// Stubs para usar en los tests: declarar en el espacio global para evitar clases anidadas
if (! class_exists('TestQueryBuilder')) {
    class TestQueryBuilder extends \VersaORM\QueryBuilder
    {
        public array $recordedWheres = [];

        public function __construct()
        {
            parent::__construct([], 'related');
        }

        // Firma compatible con QueryBuilder::where(string, string, mixed): self
        public function where(string $column, string $operator, mixed $value): self
        {
            $this->recordedWheres[] = [$column, $operator, $value];

            return $this;
        }

        // Firma compatible con QueryBuilder::findOne(): ?\VersaORM\VersaModel
        public function findOne(): ?\VersaORM\VersaModel
        {
            return new TestVersaModel();
        }
    }
}

if (! class_exists('TestVersaModel')) {
    class TestVersaModel extends \VersaORM\VersaModel
    {
        public function __construct()
        {
            parent::__construct('parents', null);
        }

        public function getAttribute(string $k): mixed
        {
            return 123;
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
final class RelationsBelongsToBehaviorTest extends TestCase
{
    public function test_addConstraints_and_query_delegate(): void
    {
        $query = new TestQueryBuilder();
        $parent = new TestVersaModel();

        // BelongsTo constructor requiere 5 args: query, parent, foreignKey, ownerKey, relationName
        $relation = new \VersaORM\Relations\BelongsTo($query, $parent, 'foreign', 'local', 'relation');

        // call protected addConstraints via reflection
        $r = new ReflectionClass($relation);
        $m = $r->getMethod('addConstraints');
        $m->setAccessible(true);
        $m->invoke($relation);

        // after addConstraints the query should have recorded a where
        $this->assertNotEmpty($query->recordedWheres);

        // calling getResults should call findOne and return a VersaModel instance
        $result = $relation->getResults();
        $this->assertInstanceOf(\VersaORM\VersaModel::class, $result);
    }
}
