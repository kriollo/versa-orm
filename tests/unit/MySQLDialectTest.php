<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

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

        static::assertSame('*', $d->quoteIdentifier('*'));
        static::assertSame('`col`', $d->quoteIdentifier('col'));
        static::assertSame('`t`.*', $d->quoteIdentifier('t.*'));

        static::assertSame('?', $d->placeholder(1));

        static::assertSame('', $d->compileLimitOffset(null, null));
        static::assertStringContainsString('LIMIT 10', $d->compileLimitOffset(10, null));
        static::assertStringContainsString('LIMIT 10 OFFSET 5', $d->compileLimitOffset(10, 5));

        static::assertSame('mysql', $d->getName());
    }
}
