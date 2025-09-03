<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\VersaORM;

/**
 * @group sqlite
 */
final class VersaORMMinimalTest extends TestCase
{
    public function testExecAndTable(): void
    {
        $orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
        static::assertNull($orm->exec('CREATE TABLE t_minimal (id INTEGER PRIMARY KEY, name TEXT)'));
        static::assertNull($orm->exec('INSERT INTO t_minimal (name) VALUES (?)', ['Z']));
        $rows = $orm->exec('SELECT name FROM t_minimal');
        static::assertIsArray($rows);

        $qb = $orm->table('t_minimal');
        static::assertInstanceOf(QueryBuilder::class, $qb);
    }
}
