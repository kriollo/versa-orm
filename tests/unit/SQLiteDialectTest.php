<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\Dialects\SQLiteDialect;

/**
 * @group sqlite
 */
final class SQLiteDialectTest extends TestCase
{
    public function test_quoteIdentifier_and_placeholder_and_limits(): void
    {
        $d = new SQLiteDialect();

        self::assertSame('*', $d->quoteIdentifier('*'));
        self::assertSame('"col"', $d->quoteIdentifier('col'));
        self::assertSame('"t".*', $d->quoteIdentifier('t.*'));

        self::assertSame('?', $d->placeholder(1));

        self::assertSame('', $d->compileLimitOffset(null, null));
        self::assertSame(' LIMIT 10', $d->compileLimitOffset(10, null));
        self::assertSame(' LIMIT 10 OFFSET 5', $d->compileLimitOffset(10, 5));

        self::assertSame('sqlite', $d->getName());
    }
}
