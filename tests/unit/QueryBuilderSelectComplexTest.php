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

        $this->assertIsArray($res);
        $this->assertArrayHasKey('sql', $res);
        $this->assertArrayHasKey('bindings', $res);

        $sql = $res['sql'];
        $bindings = $res['bindings'];

        $this->assertIsString($sql);
        $this->assertIsArray($bindings);
        $upper = strtoupper($sql);
        $this->assertStringContainsString('SELECT', $upper);
        $this->assertStringContainsString('FROM', $upper);
        $this->assertStringContainsString('JOIN', $upper);
    }
}
