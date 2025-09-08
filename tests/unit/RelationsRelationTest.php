<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\Relations\Relation;
use VersaORM\VersaModel;

/**
 * @group sqlite
 */
final class RelationsRelationTest extends TestCase
{
    public function testConcreteRelationImplementsAbstractMethods(): void
    {
        // Crear stub de QueryBuilder y VersaModel mínimos usando stdClass proxies
        $qb = $this->createMock(QueryBuilder::class);
        $parent = $this->createMock(VersaModel::class);

        $concrete = new class($qb, $parent) extends Relation {
            protected function addConstraints(): void
            {
                // no-op para la prueba
            }

            public function getResults(): mixed
            {
                return ['ok'];
            }
        };

        self::assertSame(['ok'], $concrete->getResults());
    }
}
