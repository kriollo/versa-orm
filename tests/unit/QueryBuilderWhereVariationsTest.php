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

        self::assertIsArray($res);
        self::assertArrayHasKey('sql', $res);
        self::assertArrayHasKey('bindings', $res);

        $sql = strtoupper($res['sql']);
        $bindings = $res['bindings'];

        self::assertStringContainsString('WHERE', $sql);
        self::assertStringContainsString('IN', $sql);
        self::assertStringContainsString('BETWEEN', $sql);
        self::assertIsArray($bindings);
        self::assertNotEmpty($bindings);
    }
}
