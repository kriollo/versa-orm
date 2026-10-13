<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use VersaORM\QueryBuilder;

/**
 * @group sqlite
 */
final class QueryBuilderWhereEdgeCasesTest extends TestCase
{
    public function test_various_where_types_and_bindings(): void
    {
        $qb = new QueryBuilder(null, 'products');
        $qb
            ->select(['id'])
            ->where('price', '>', 10)
            ->orWhere('stock', '<', 5)
            ->whereIn('category', [1, 2, 3])
            ->whereNull('deleted_at')
            ->whereBetween('created_at', '2020-01-01', '2020-12-31');

        $ref = new ReflectionClass($qb);
        $m = $ref->getMethod('buildSelectSQL');
        $m->setAccessible(true);

        $res = $m->invoke($qb);
        static::assertIsArray($res);
        static::assertArrayHasKey('sql', $res);
        static::assertArrayHasKey('bindings', $res);

        $sql = $res['sql'];
        $bindings = $res['bindings'];

        static::assertStringContainsString('WHERE', $sql);
        static::assertStringContainsString('IN', $sql);
        static::assertStringContainsString('BETWEEN', $sql);
        static::assertIsArray($bindings);
        // price > 10 should add 10 somewhere in bindings; category IN should include 1,2,3
        static::assertContains(10, $bindings);

        // Los valores de whereIn se expanden a un placeholder por valor. Antes llegaban
        // anidados como un único binding de tipo array, que es justamente el bug:
        // 'IN (?)' con un array por valor nunca puede ejecutarse.
        static::assertStringContainsString('IN (?, ?, ?)', $sql);
        // El assertSame exacto ya prueba que ningún binding es un array.
        static::assertSame([10, 5, 1, 2, 3, '2020-01-01', '2020-12-31'], $bindings);
    }
}
