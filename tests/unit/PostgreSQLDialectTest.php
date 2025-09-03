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

        static::assertSame('*', $d->quoteIdentifier('*'));
        static::assertStringContainsString('"col"', $d->quoteIdentifier('col'));
        static::assertStringContainsString('"t".*', $d->quoteIdentifier('t.*'));

        static::assertSame('?', $d->placeholder(1));

        static::assertSame('', $d->compileLimitOffset(null, null));
        static::assertStringContainsString('LIMIT 10', $d->compileLimitOffset(10, null));
        static::assertStringContainsString('LIMIT 10 OFFSET 5', $d->compileLimitOffset(10, 5));

        static::assertSame('postgres', $d->getName());
    }
}
