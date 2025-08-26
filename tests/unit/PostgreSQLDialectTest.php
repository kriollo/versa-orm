<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\Dialects\PostgreSQLDialect;

/**
 * @group sqlite
 */
final class PostgreSQLDialectTest extends TestCase
{
    public function test_postgres_dialect_basic(): void
    {
        $d = new PostgreSQLDialect();

        $this->assertEquals('*', $d->quoteIdentifier('*'));
        $this->assertStringContainsString('"col"', $d->quoteIdentifier('col'));
        $this->assertStringContainsString('"t".*', $d->quoteIdentifier('t.*'));

        $this->assertEquals('?', $d->placeholder(1));

        $this->assertEquals('', $d->compileLimitOffset(null, null));
        $this->assertStringContainsString('LIMIT 10', $d->compileLimitOffset(10, null));
        $this->assertStringContainsString('LIMIT 10 OFFSET 5', $d->compileLimitOffset(10, 5));

        $this->assertEquals('postgres', $d->getName());
    }
}
