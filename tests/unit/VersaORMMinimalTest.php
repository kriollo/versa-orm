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
        $this->assertNull($orm->exec('CREATE TABLE t_minimal (id INTEGER PRIMARY KEY, name TEXT)'));
        $this->assertNull($orm->exec('INSERT INTO t_minimal (name) VALUES (?)', ['Z']));
        $rows = $orm->exec('SELECT name FROM t_minimal');
        $this->assertIsArray($rows);

        $qb = $orm->table('t_minimal');
        $this->assertInstanceOf(QueryBuilder::class, $qb);
    }
}
