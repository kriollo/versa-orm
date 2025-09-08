<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\Dialects\MySQLDialect;

/**
 * @group sqlite
 */
final class MySQLDialectTest extends TestCase
{
    public function test_mysql_dialect_basic(): void
    {
        $d = new MySQLDialect();

        self::assertSame('*', $d->quoteIdentifier('*'));
        self::assertSame('`col`', $d->quoteIdentifier('col'));
        self::assertSame('`t`.*', $d->quoteIdentifier('t.*'));

        self::assertSame('?', $d->placeholder(1));

        self::assertSame('', $d->compileLimitOffset(null, null));
        self::assertStringContainsString('LIMIT 10', $d->compileLimitOffset(10, null));
        self::assertStringContainsString('LIMIT 10 OFFSET 5', $d->compileLimitOffset(10, 5));

        self::assertSame('mysql', $d->getName());
    }
}
