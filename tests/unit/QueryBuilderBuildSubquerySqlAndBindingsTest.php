<?php

declare(strict_types=1);

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

        $this->assertIsArray($res);
        $this->assertArrayHasKey('sql', $res);
        $this->assertArrayHasKey('bindings', $res);
        $this->assertStringContainsString('SELECT id, price FROM items', $res['sql']);
        $this->assertStringContainsString('WHERE price > ?', $res['sql']);
        $this->assertStringContainsString('GROUP BY category', $res['sql']);
        $this->assertStringContainsString('HAVING price > ?', $res['sql']);
        $this->assertStringContainsString('ORDER BY id DESC', $res['sql']);
        $this->assertStringContainsString('LIMIT 10', $res['sql']);
        $this->assertEquals([100, 1000], $res['bindings']);
    }
}
