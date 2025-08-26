<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\Dialects\MySQLDialect;
use VersaORM\SQL\Dialects\PostgreSQLDialect;
use VersaORM\SQL\Dialects\SQLiteDialect;

/**
 * @group sqlite
 */
final class DialectsTest extends TestCase
{
    public function test_sqlite_quote_and_limit_offset(): void
    {
        $d = new SQLiteDialect();

        $this->assertEquals('"col"', $d->quoteIdentifier('col'));
        $this->assertStringContainsString('LIMIT 10', $d->compileLimitOffset(10, 0));
        $this->assertStringContainsString('OFFSET 5', $d->compileLimitOffset(10, 5));
    }

    public function test_mysql_quote_and_limit_offset(): void
    {
        $d = new MySQLDialect();

        $this->assertEquals('`col`', $d->quoteIdentifier('col'));
        $this->assertStringContainsString('LIMIT 5', $d->compileLimitOffset(5, 0));
    }

    public function test_pg_quote_and_limit_offset(): void
    {
        $d = new PostgreSQLDialect();

        $this->assertEquals('"col"', $d->quoteIdentifier('col'));
        // Postgres may compile LIMIT/OFFSET differently but should include LIMIT
        $this->assertStringContainsString('LIMIT', $d->compileLimitOffset(3, 1));
    }
}
