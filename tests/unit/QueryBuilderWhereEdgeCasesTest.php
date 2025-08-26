<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;

/**
 * @group sqlite
 */
final class QueryBuilderWhereEdgeCasesTest extends TestCase
{
    public function test_various_where_types_and_bindings(): void
    {
        $qb = new QueryBuilder(null, 'products');
        $qb->select(['id'])->where('price', '>', 10)
            ->orWhere('stock', '<', 5)
            ->whereIn('category', [1, 2, 3])
            ->whereNull('deleted_at')
            ->whereBetween('created_at', '2020-01-01', '2020-12-31');

        $ref = new ReflectionClass($qb);
        $m = $ref->getMethod('buildSelectSQL');
        $m->setAccessible(true);

        $res = $m->invoke($qb);
        $this->assertIsArray($res);
        $this->assertArrayHasKey('sql', $res);
        $this->assertArrayHasKey('bindings', $res);

        $sql = $res['sql'];
        $bindings = $res['bindings'];

        $this->assertStringContainsString('WHERE', $sql);
        $this->assertStringContainsString('IN', $sql);
        $this->assertStringContainsString('BETWEEN', $sql);
        $this->assertIsArray($bindings);
        // price > 10 should add 10 somewhere in bindings; category IN should include 1,2,3
        self::assertContains(10, $bindings);

        // category IN bindings may be nested as an array; ensure at least one binding array contains 1
        $found = false;
        foreach ($bindings as $b) {
            if (is_array($b) && in_array(1, $b, true)) {
                $found = true;
                break;
            }
        }
        self::assertTrue($found, 'Expected to find value 1 inside nested bindings (IN clause)');
    }
}
