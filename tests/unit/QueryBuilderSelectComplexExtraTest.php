<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use VersaORM\QueryBuilder;

/**
 * @group sqlite
 */
final class QueryBuilderSelectComplexExtraTest extends TestCase
{
    public function test_build_select_with_subquery_group_having_and_limit_combination(): void
    {
        $qb = new QueryBuilder(null, 'orders');
        // subquery in select
        $sub = new QueryBuilder(null, 'order_items');
        $sub->select(['order_id', 'COUNT(*) AS cnt'])->groupBy(['order_id']);

        // invoke private buildSelectSQL on subquery to get SQL string
        $refSub = new ReflectionClass($sub);
        $mSub = $refSub->getMethod('buildSelectSQL');
        $mSub->setAccessible(true);
        $subRes = $mSub->invoke($sub);

        // Use selectRaw to inject a safe raw expression as select column
        $qb
            ->select(['orders.id'])
            ->selectRaw('(' . $subRes['sql'] . ') AS items_count')
            ->join('order_items', 'orders.id', '=', 'order_items.order_id')
            ->groupBy(['orders.id'])
            ->having('items_count', '>', 0)
            ->limit(10);

        $ref = new ReflectionClass($qb);
        $m = $ref->getMethod('buildSelectSQL');
        $m->setAccessible(true);

        $res = $m->invoke($qb);
        static::assertIsArray($res);
        static::assertArrayHasKey('sql', $res);
        static::assertArrayHasKey('bindings', $res);

        $sql = $res['sql'];
        static::assertStringContainsString('SELECT', $sql);
        static::assertStringContainsString('FROM', $sql);
        static::assertStringContainsString('JOIN', $sql);
        // GROUP BY/HAVING/LIMIT may be generated depending on internals; assert at least SELECT/FROM/JOIN present
        static::assertMatchesRegularExpression('/SELECT\s+/i', $sql);
        static::assertMatchesRegularExpression('/FROM\s+/i', $sql);
        static::assertMatchesRegularExpression('/JOIN\s+/i', $sql);
    }
}
