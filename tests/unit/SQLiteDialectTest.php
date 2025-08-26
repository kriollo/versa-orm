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

        $this->assertEquals('*', $d->quoteIdentifier('*'));
        $this->assertEquals('"col"', $d->quoteIdentifier('col'));
        $this->assertEquals('"t".*', $d->quoteIdentifier('t.*'));

        $this->assertEquals('?', $d->placeholder(1));

        $this->assertEquals('', $d->compileLimitOffset(null, null));
        $this->assertEquals(' LIMIT 10', $d->compileLimitOffset(10, null));
        $this->assertEquals(' LIMIT 10 OFFSET 5', $d->compileLimitOffset(10, 5));

        $this->assertEquals('sqlite', $d->getName());
    }
}
