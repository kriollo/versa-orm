<?php

declare(strict_types=1);

namespace VersaORM\Tests\PostgreSQL;

use VersaORM\QueryBuilder;

/**
 * Pruebas para operaciones de conjuntos (UNION / INTERSECT / EXCEPT) en modo PDO.
 * Solo PostgreSQL debe soportar INTERSECT / EXCEPT (y variantes ALL) en esta capa.
 */
class SetOperationsTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Aseguramos tablas básicas
        self::$orm->schemaDrop('set_ops_a');
        self::$orm->schemaDrop('set_ops_b');
        self::$orm->schemaCreate(
            'set_ops_a',
            [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true],
                ['name' => 'value', 'type' => 'INT'],
            ],
            ['if_not_exists' => true],
        );
        self::$orm->schemaCreate(
            'set_ops_b',
            [
                ['name' => 'id', 'type' => 'INT', 'primary' => true, 'autoIncrement' => true],
                ['name' => 'value', 'type' => 'INT'],
            ],
            ['if_not_exists' => true],
        );
        // Insertar datos con solapamientos y duplicados
        foreach ([1, 2, 2, 3, 5] as $v) {
            self::$orm->table('set_ops_a')->insert(['value' => $v]);
        }
        foreach ([2, 2, 3, 4, 6] as $v) {
            self::$orm->table('set_ops_b')->insert(['value' => $v]);
        }
    }

    protected function tearDown(): void
    {
        self::$orm->schemaDrop('set_ops_a');
        self::$orm->schemaDrop('set_ops_b');
    }

    public function test_union_all_keeps_duplicates(): void
    {
        $qb = new QueryBuilder(self::$orm, 'set_ops_a');
        $result = $qb->union([
            ['sql' => 'SELECT value FROM set_ops_a', 'bindings' => []],
            ['sql' => 'SELECT value FROM set_ops_b', 'bindings' => []],
        ], true); // UNION ALL
        $values = array_map(static fn($r) => (int) $r['value'], $result);
        // Conteo esperado: 5 + 5 = 10 filas (sin eliminar duplicados)
        static::assertCount(10, $values, 'UNION ALL debe conservar duplicados');
    }

    public function test_union_removes_duplicates(): void
    {
        $qb = new QueryBuilder(self::$orm, 'set_ops_a');
        $result = $qb->union([
            ['sql' => 'SELECT value FROM set_ops_a', 'bindings' => []],
            ['sql' => 'SELECT value FROM set_ops_b', 'bindings' => []],
        ], false); // UNION
        $values = array_map(static fn($r) => (int) $r['value'], $result);
        $unique = array_values(array_unique($values));
        sort($unique);
        $expected = [1, 2, 3, 4, 5, 6];
        static::assertSame($expected, $unique, 'UNION debe eliminar duplicados');
        static::assertCount(count($unique), $values, 'No deben existir duplicados tras UNION');
    }

    public function test_intersect_removes_non_common(): void
    {
        $qb1 = new QueryBuilder(self::$orm, 'set_ops_a');
        $qb1->select(['value']);
        $qb2 = new QueryBuilder(self::$orm, 'set_ops_b');
        $qb2->select(['value']);
        $result = $qb1->intersect($qb2, false);
        $values = array_map(static fn($r) => (int) $r['value'], $result);
        sort($values);
        // Intersección sin duplicados: valores comunes {2,3}
        static::assertSame([2, 3], $values);
    }

    public function test_intersect_all_keeps_duplicate_overlap(): void
    {
        $qb1 = new QueryBuilder(self::$orm, 'set_ops_a');
        $qb1->select(['value']);
        $qb2 = new QueryBuilder(self::$orm, 'set_ops_b');
        $qb2->select(['value']);
        $result = $qb1->intersect($qb2, true);
        $values = array_map(static fn($r) => (int) $r['value'], $result);
        sort($values);
        // Duplicados comunes: el valor 2 aparece al menos dos veces en ambos -> debería aparecer min(2,2)=2 veces + 3 una vez => [2,2,3]
        static::assertSame([2, 2, 3], $values);
    }

    public function test_except_removes_right_side(): void
    {
        $qb1 = new QueryBuilder(self::$orm, 'set_ops_a');
        $qb1->select(['value']);
        $qb2 = new QueryBuilder(self::$orm, 'set_ops_b');
        $qb2->select(['value']);
        $result = $qb1->except($qb2, false);
        $values = array_map(static fn($r) => (int) $r['value'], $result);
        sort($values);
        // A \ B sin duplicados: A={1,2,2,3,5}, B={2,2,3,4,6} => {1,5}
        static::assertSame([1, 5], $values);
    }

    public function test_except_all_keeps_residual_multiplicities(): void
    {
        $qb1 = new QueryBuilder(self::$orm, 'set_ops_a');
        $qb1->select(['value']);
        $qb2 = new QueryBuilder(self::$orm, 'set_ops_b');
        $qb2->select(['value']);
        $result = $qb1->except($qb2, true);
        $values = array_map(static fn($r) => (int) $r['value'], $result);
        sort($values);
        // A \ B con multiplicidades: para 2 min(A:2,B:2)=2 se eliminan; para 3 min(A:1,B:1)=1 se elimina -> queda [1,5]
        static::assertSame([1, 5], $values);
    }
}
