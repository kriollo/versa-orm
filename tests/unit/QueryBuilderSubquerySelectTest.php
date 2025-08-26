<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
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

        $this->assertIsArray($subRes);
        $this->assertArrayHasKey('sql', $subRes);
        $this->assertArrayHasKey('bindings', $subRes);
        $this->assertStringContainsString('SELECT', $subRes['sql']);
        $this->assertIsArray($subRes['bindings']);
    }
}
