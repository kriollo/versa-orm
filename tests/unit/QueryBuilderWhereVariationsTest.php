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
        $qb->select(['id', 'sku'])
            ->where('id', '>', 10)
            ->orWhere('sku', 'LIKE', 'ABC%')
            ->whereIn('id', [11, 12, 13])
            ->whereNull('deleted_at')
            ->whereBetween('qty', 1, 100);

        $ref = new ReflectionClass($qb);
        $m = $ref->getMethod('buildSelectSQL');
        $m->setAccessible(true);

        $res = $m->invoke($qb);

        $this->assertIsArray($res);
        $this->assertArrayHasKey('sql', $res);
        $this->assertArrayHasKey('bindings', $res);

        $sql = strtoupper($res['sql']);
        $bindings = $res['bindings'];

        $this->assertStringContainsString('WHERE', $sql);
        $this->assertStringContainsString('IN', $sql);
        $this->assertStringContainsString('BETWEEN', $sql);
        $this->assertIsArray($bindings);
        $this->assertNotEmpty($bindings);
    }
}
