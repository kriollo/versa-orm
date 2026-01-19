<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;

/**
 * @group sqlite
 */
final class QueryBuilderIsSafeIdentifierTest extends TestCase
{
    public function test_is_safe_identifier_allows_valid_and_rejects_malicious(): void
    {
        $qb = new QueryBuilder(null, 'users');

        $ref = new ReflectionClass($qb);
        $m = $ref->getMethod('isSafeIdentifier');
        $m->setAccessible(true);

        static::assertTrue($m->invoke($qb, '*'));
        static::assertTrue($m->invoke($qb, 'users.name'));
        static::assertFalse($m->invoke($qb, 'name; DROP TABLE users;'));
        static::assertFalse($m->invoke($qb, 'name -- comment'));
    }
}
