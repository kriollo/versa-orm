<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;

/**
 * @group sqlite
 */
final class QueryBuilderSelectComplexTest extends TestCase
{
    public function test_build_select_with_joins_groupby_having_and_limit(): void
    {
        $qb = new QueryBuilder(null, 'users');

        // Build a moderately complex query via public API
        $qb
            ->select(['users.id', 'users.name'])
            ->join('profiles', 'users.id', '=', 'profiles.user_id')
            ->groupBy(['users.id'])
            ->having('COUNT(profiles.id)', '>', 1)
            ->orderBy('users.id', 'desc')
            ->limit(10);

        $ref = new ReflectionClass($qb);
        $m = $ref->getMethod('buildSelectSQL');
        $m->setAccessible(true);

        $res = $m->invoke($qb);

        self::assertIsArray($res);
        self::assertArrayHasKey('sql', $res);
        self::assertArrayHasKey('bindings', $res);

        $sql = $res['sql'];
        $bindings = $res['bindings'];

        self::assertIsString($sql);
        self::assertIsArray($bindings);
        $upper = strtoupper($sql);
        self::assertStringContainsString('SELECT', $upper);
        self::assertStringContainsString('FROM', $upper);
        self::assertStringContainsString('JOIN', $upper);
    }
}
