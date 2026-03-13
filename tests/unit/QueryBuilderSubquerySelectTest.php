<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use VersaORM\QueryBuilder;

/**
 * @group sqlite
 */
final class QueryBuilderSubquerySelectTest extends TestCase
{
    public function test_subquery_in_select_returns_sql_and_bindings(): void
    {
        $sub = new QueryBuilder(null, 'order_items');
        $sub->select(['order_id', 'COUNT(*) AS cnt'])->groupBy(['order_id']);

        $refSub = new ReflectionClass($sub);
        $mSub = $refSub->getMethod('buildSelectSQL');
        $mSub->setAccessible(true);
        $subRes = $mSub->invoke($sub);

        static::assertIsArray($subRes);
        static::assertArrayHasKey('sql', $subRes);
        static::assertArrayHasKey('bindings', $subRes);
        static::assertStringContainsString('SELECT', $subRes['sql']);
        static::assertIsArray($subRes['bindings']);
    }
}
