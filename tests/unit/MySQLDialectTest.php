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

        $this->assertEquals('*', $d->quoteIdentifier('*'));
        $this->assertEquals('`col`', $d->quoteIdentifier('col'));
        $this->assertEquals('`t`.*', $d->quoteIdentifier('t.*'));

        $this->assertEquals('?', $d->placeholder(1));

        $this->assertEquals('', $d->compileLimitOffset(null, null));
        $this->assertStringContainsString('LIMIT 10', $d->compileLimitOffset(10, null));
        $this->assertStringContainsString('LIMIT 10 OFFSET 5', $d->compileLimitOffset(10, 5));

        $this->assertEquals('mysql', $d->getName());
    }
}
