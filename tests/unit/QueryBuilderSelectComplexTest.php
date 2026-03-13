<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
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

        static::assertIsArray($res);
        static::assertArrayHasKey('sql', $res);
        static::assertArrayHasKey('bindings', $res);

        $sql = $res['sql'];
        $bindings = $res['bindings'];

        static::assertIsString($sql);
        static::assertIsArray($bindings);
        $upper = strtoupper($sql);
        static::assertStringContainsString('SELECT', $upper);
        static::assertStringContainsString('FROM', $upper);
        static::assertStringContainsString('JOIN', $upper);
    }
}
