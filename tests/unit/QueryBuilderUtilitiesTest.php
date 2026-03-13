<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\VersaORMException;

/**
 * @group sqlite
 */
final class QueryBuilderUtilitiesTest extends TestCase
{
    public function test_invalid_table_identifier_throws(): void
    {
        $this->expectException(VersaORMException::class);
        // Unsafe table name with semicolon should be rejected
        new QueryBuilder(null, 'users; DROP TABLE users');
    }

    public function test_select_raw_rejects_empty_or_unsafe(): void
    {
        $qb = new QueryBuilder(null, 'users');

        $this->expectException(VersaORMException::class);
        $qb->selectRaw('');
    }

    public function test_where_raw_rejects_unsafe(): void
    {
        $qb = new QueryBuilder(null, 'users');

        $this->expectException(VersaORMException::class);
        $qb->whereRaw('1=1; DROP TABLE users');
    }
}
