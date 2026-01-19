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

        static::assertSame('*', $d->quoteIdentifier('*'));
        static::assertSame('"col"', $d->quoteIdentifier('col'));
        static::assertSame('"t".*', $d->quoteIdentifier('t.*'));

        static::assertSame('?', $d->placeholder(1));

        static::assertSame('', $d->compileLimitOffset(null, null));
        static::assertSame(' LIMIT 10', $d->compileLimitOffset(10, null));
        static::assertSame(' LIMIT 10 OFFSET 5', $d->compileLimitOffset(10, 5));

        static::assertSame('sqlite', $d->getName());
    }
}
