<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;

/**
 * @group sqlite
 */
final class QueryBuilderPrivateTest extends TestCase
{
    public function test_is_safe_identifier_and_raw_expression(): void
    {
        $qb = new QueryBuilder(null, 'users');
        $ref = new ReflectionClass($qb);

        $isSafe = $ref->getMethod('isSafeIdentifier');
        $isSafe->setAccessible(true);

        static::assertTrue($isSafe->invoke($qb, 'users'));
        static::assertFalse($isSafe->invoke($qb, 'users; DROP TABLE'));

        $isRaw = $ref->getMethod('isSafeRawExpression');
        $isRaw->setAccessible(true);

        static::assertTrue($isRaw->invoke($qb, 'COUNT(*)'));
        static::assertFalse($isRaw->invoke($qb, '1=1; DROP TABLE'));
    }

    public function test_build_subquery_sql_and_bindings(): void
    {
        $qb = new QueryBuilder(null, 'users');
        $qb->select(['id', 'name'])->where('id', '=', 5);

        $ref = new ReflectionClass($qb);
        $method = $ref->getMethod('buildSubquerySqlAndBindings');
        $method->setAccessible(true);

        // Build subquery from the same builder
        $res = $method->invoke($qb, $qb);

        static::assertIsArray($res);
        static::assertArrayHasKey('sql', $res);
        static::assertArrayHasKey('bindings', $res);
        $sql = $res['sql'];
        $bindings = $res['bindings'];

        static::assertIsString($sql);
        static::assertIsArray($bindings);
        static::assertStringContainsString('FROM', $sql);
        static::assertContains(5, $bindings);
    }

    public function test_build_select_sql_returns_sql_and_bindings(): void
    {
        $qb = new QueryBuilder(null, 'users');
        $qb->select(['id'])->where('active', '=', true);
        $ref = new ReflectionClass($qb);
        $m = $ref->getMethod('buildSelectSQL');
        $m->setAccessible(true);

        $res2 = $m->invoke($qb);
        static::assertIsArray($res2);
        static::assertArrayHasKey('sql', $res2);
        static::assertArrayHasKey('bindings', $res2);
        $sql = $res2['sql'];
        $bindings = $res2['bindings'];
        static::assertIsString($sql);
        static::assertIsArray($bindings);
    }
}
