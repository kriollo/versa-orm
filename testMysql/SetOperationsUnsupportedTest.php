<?php

declare(strict_types=1);

namespace VersaORM\Tests\MySQL;

use VersaORM\QueryBuilder;
use VersaORM\VersaORMException;

/**
 * MySQL en la ruta PDO actual: INTERSECT / EXCEPT no soportados -> deben lanzar excepción.
 * Verificamos que UNION / UNION ALL sigan operativos (ya cubierto en otros tests) y las negativas aquí.
 */
class SetOperationsUnsupportedTest extends TestCase
{
    public function testIntersectUnsupported(): void
    {
        $this->expectException(VersaORMException::class);
        $qb1 = new QueryBuilder(self::$orm, 'users');
        $qb2 = new QueryBuilder(self::$orm, 'users');
        $qb1->intersect($qb2);
    }

    public function testExceptUnsupported(): void
    {
        $this->expectException(VersaORMException::class);
        $qb1 = new QueryBuilder(self::$orm, 'users');
        $qb2 = new QueryBuilder(self::$orm, 'users');
        $qb1->except($qb2);
    }
}
