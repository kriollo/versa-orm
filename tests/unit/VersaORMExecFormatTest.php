<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../vendor/autoload.php';

use VersaORM\VersaORM;

class VersaORMExecFormatTest extends TestCase
{
    public function testExecSelectReturnsRows(): void
    {
        $orm = new VersaORM();
        $orm->setConfig(['driver' => 'sqlite', 'database' => ':memory:']);

        // Create a table and insert one row using exec (non-SELECT returns null)
        $orm->exec('CREATE TABLE t1 (id INTEGER PRIMARY KEY, name TEXT)');
        $orm->exec('INSERT INTO t1 (name) VALUES (?)', ['Alice']);

        $rows = $orm->exec('SELECT id, name FROM t1');
        $this->assertIsArray($rows);
        $this->assertCount(1, $rows);
        $this->assertSame('Alice', $rows[0]['name']);
    }

    public function testIsRawQueryDDLDetection(): void
    {
        $orm = new VersaORM();
        $orm->setConfig(['driver' => 'sqlite', 'database' => ':memory:']);

        // Using exec with DDL should be detected and follow freeze rules; but here no freeze => ok
        $res = $orm->exec('CREATE TABLE if not exists tmp (id INTEGER)');
        $this->assertNull($res);
    }

    public function testValidateInputRejectsInvalidAction(): void
    {
        $orm = new VersaORM();
        $orm->setConfig(['driver' => 'sqlite', 'database' => ':memory:']);

        // Call via reflection to reach private validateInput indirectly by calling execute with invalid action
        $this->expectException(\VersaORM\VersaORMException::class);
        $ref = new \ReflectionClass($orm);
        $m = $ref->getMethod('execute');
        $m->setAccessible(true);
        $m->invoke($orm, 'bad_action', []);
    }
}
