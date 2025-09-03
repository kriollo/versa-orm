<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\QueryBuilder;
use VersaORM\VersaORMException;

/**
 * SQLite no soporta INTERSECT/EXCEPT ALL en todas las variantes de forma homogénea en este modo.
 * Verificamos que UNION / UNION ALL funcionen y que INTERSECT / EXCEPT lancen excepción coherente.
 */
class SetOperationsTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        self::$orm->schemaDrop('set_ops_a');
        self::$orm->schemaDrop('set_ops_b');
        self::$orm->schemaCreate(
            'set_ops_a',
            [
                ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
                ['name' => 'value', 'type' => 'INTEGER'],
            ],
            ['if_not_exists' => true],
        );
        self::$orm->schemaCreate(
            'set_ops_b',
            [
                ['name' => 'id', 'type' => 'INTEGER', 'primary' => true, 'autoIncrement' => true],
                ['name' => 'value', 'type' => 'INTEGER'],
            ],
            ['if_not_exists' => true],
        );
        foreach ([1, 2, 2, 3] as $v) {
            self::$orm->table('set_ops_a')->insert(['value' => $v]);
        }
        foreach ([2, 3, 4] as $v) {
            self::$orm->table('set_ops_b')->insert(['value' => $v]);
        }
    }

    protected function tearDown(): void
    {
        self::$orm->schemaDrop('set_ops_a');
        self::$orm->schemaDrop('set_ops_b');
    }

    public function test_union_basic(): void
    {
        $qb = new QueryBuilder(self::$orm, 'set_ops_a');
        $rows = $qb->union([
            ['sql' => 'SELECT value FROM set_ops_a', 'bindings' => []],
            ['sql' => 'SELECT value FROM set_ops_b', 'bindings' => []],
        ], false);
        $values = array_map(static fn($r) => (int) $r['value'], $rows);
        sort($values);
        $unique = array_values(array_unique($values));
        sort($unique);
        static::assertSame($unique, $values, 'UNION debe eliminar duplicados');
    }

    public function test_union_all_basic(): void
    {
        $qb = new QueryBuilder(self::$orm, 'set_ops_a');
        $rows = $qb->union([
            ['sql' => 'SELECT value FROM set_ops_a', 'bindings' => []],
            ['sql' => 'SELECT value FROM set_ops_b', 'bindings' => []],
        ], true);
        $values = array_map(static fn($r) => (int) $r['value'], $rows);
        static::assertGreaterThan(count(array_unique($values)), count($values), 'UNION ALL debe conservar duplicados');
    }

    public function test_intersect_unsupported(): void
    {
        $this->expectException(VersaORMException::class);
        $qb1 = new QueryBuilder(self::$orm, 'set_ops_a');
        $qb2 = new QueryBuilder(self::$orm, 'set_ops_b');
        $qb1->intersect($qb2);
    }

    public function test_except_unsupported(): void
    {
        $this->expectException(VersaORMException::class);
        $qb1 = new QueryBuilder(self::$orm, 'set_ops_a');
        $qb2 = new QueryBuilder(self::$orm, 'set_ops_b');
        $qb1->except($qb2);
    }
}
