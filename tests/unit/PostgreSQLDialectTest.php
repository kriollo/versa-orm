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

        self::assertSame('*', $d->quoteIdentifier('*'));
        self::assertStringContainsString('"col"', $d->quoteIdentifier('col'));
        self::assertStringContainsString('"t".*', $d->quoteIdentifier('t.*'));

        self::assertSame('?', $d->placeholder(1));

        self::assertSame('', $d->compileLimitOffset(null, null));
        self::assertStringContainsString('LIMIT 10', $d->compileLimitOffset(10, null));
        self::assertStringContainsString('LIMIT 10 OFFSET 5', $d->compileLimitOffset(10, 5));

        self::assertSame('postgres', $d->getName());
    }
}
