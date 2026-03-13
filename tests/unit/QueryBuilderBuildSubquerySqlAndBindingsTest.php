<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\VersaORM;

class VersaORMStub2 extends VersaORM
{
    public function __construct() {}

    public function executeQuery(string $action, array $params = [])
    {
        return [];
    }
}

/**
 * @group sqlite
 */
final class QueryBuilderBuildSubquerySqlAndBindingsTest extends TestCase
{
    public function testBuildSubquerySqlAndBindingsProducesSqlAndBindings(): void
    {
        $orm = new VersaORMStub2();
        $qb = new QueryBuilder($orm, 'orders');

        // Configure inner builder
        $inner = new QueryBuilder($orm, 'items');
        $inner->select(['id', 'price']);
        $inner->where('price', '>', 100);
        $inner->groupBy(['category']);
        $inner->having('price', '>', 1000);
        $inner->orderBy('id', 'desc');
        $inner->limit(10);

        $ref = new \ReflectionClass($qb);
        $m = $ref->getMethod('buildSubquerySqlAndBindings');
        $m->setAccessible(true);

        $res = $m->invoke($qb, $inner);

        static::assertIsArray($res);
        static::assertArrayHasKey('sql', $res);
        static::assertArrayHasKey('bindings', $res);
        static::assertStringContainsString('SELECT id, price FROM items', $res['sql']);
        static::assertStringContainsString('WHERE price > ?', $res['sql']);
        static::assertStringContainsString('GROUP BY category', $res['sql']);
        static::assertStringContainsString('HAVING price > ?', $res['sql']);
        static::assertStringContainsString('ORDER BY id DESC', $res['sql']);
        static::assertStringContainsString('LIMIT 10', $res['sql']);
        static::assertSame([100, 1000], $res['bindings']);
    }
}
