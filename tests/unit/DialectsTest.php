<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VersaORM\SQL\Dialects\MySQLDialect;
use VersaORM\SQL\Dialects\PostgreSQLDialect;

require_once __DIR__ . '/../../vendor/autoload.php';

class DialectsTest extends TestCase
{
    public function testMySQLQuoteIdentifier(): void
    {
        $d = new MySQLDialect();

        self::assertSame('`id`', $d->quoteIdentifier('id'));
        self::assertSame('`table`.*', $d->quoteIdentifier('table.*'));
        self::assertSame('*', $d->quoteIdentifier('*'));
    }

    public function testPostgresQuoteIdentifier(): void
    {
        $d = new PostgreSQLDialect();

        self::assertSame('"id"', $d->quoteIdentifier('id'));
        self::assertSame('"table".*', $d->quoteIdentifier('table.*'));
        self::assertSame('*', $d->quoteIdentifier('*'));
    }

    public function testCompileLimitOffsetAndPlaceholder(): void
    {
        $m = new MySQLDialect();
        $p = new PostgreSQLDialect();

        self::assertSame('?', $m->placeholder(1));
        self::assertSame('?', $p->placeholder(2));

        self::assertSame(' LIMIT 10 OFFSET 5', $m->compileLimitOffset(10, 5));
        self::assertSame(' LIMIT 10', $m->compileLimitOffset(10, null));
        self::assertSame('', $m->compileLimitOffset(null, null));
    }
}
