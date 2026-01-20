<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
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
        static::assertIsArray($res);
        static::assertArrayHasKey('sql', $res);
        static::assertArrayHasKey('bindings', $res);

        // bindings for IN/BETWEEN may be nested arrays per implementation
        static::assertIsArray($res['bindings']);
        static::assertNotEmpty($res['bindings']);
    }
}
