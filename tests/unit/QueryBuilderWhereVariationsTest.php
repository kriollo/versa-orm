<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;

/**
 * @group sqlite
 */
final class QueryBuilderWhereVariationsTest extends TestCase
{
    public function test_build_select_with_various_where_types(): void
    {
        $qb = new QueryBuilder(null, 'items');

        // Compose diverse where clauses
        $qb
            ->select(['id', 'sku'])
            ->where('id', '>', 10)
            ->orWhere('sku', 'LIKE', 'ABC%')
            ->whereIn('id', [11, 12, 13])
            ->whereNull('deleted_at')
            ->whereBetween('qty', 1, 100);

        $ref = new ReflectionClass($qb);
        $m = $ref->getMethod('buildSelectSQL');
        $m->setAccessible(true);

        $res = $m->invoke($qb);

        static::assertIsArray($res);
        static::assertArrayHasKey('sql', $res);
        static::assertArrayHasKey('bindings', $res);

        $sql = strtoupper($res['sql']);
        $bindings = $res['bindings'];

        static::assertStringContainsString('WHERE', $sql);
        static::assertStringContainsString('IN', $sql);
        static::assertStringContainsString('BETWEEN', $sql);
        static::assertIsArray($bindings);
        static::assertNotEmpty($bindings);
    }
}
