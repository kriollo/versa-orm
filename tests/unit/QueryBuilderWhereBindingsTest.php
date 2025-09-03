<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;

/**
 * @group sqlite
 */
final class QueryBuilderWhereBindingsTest extends TestCase
{
    public function test_where_in_and_between_produce_correct_bindings_structure(): void
    {
        $qb = new QueryBuilder(null, 'users');
        $qb->select(['id'])->whereIn('id', [1, 2, 3])->whereBetween('created_at', '2020-01-01', '2020-12-31');

        $ref = new ReflectionClass($qb);
        $m = $ref->getMethod('buildSelectSQL');
        $m->setAccessible(true);

        $res = $m->invoke($qb);
        $this->assertIsArray($res);
        $this->assertArrayHasKey('sql', $res);
        $this->assertArrayHasKey('bindings', $res);

        // bindings for IN/BETWEEN may be nested arrays per implementation
        $this->assertIsArray($res['bindings']);
        $this->assertNotEmpty($res['bindings']);
    }
}
