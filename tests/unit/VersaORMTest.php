<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use VersaORM\QueryBuilder;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/**
 * @group sqlite
 */
final class VersaORMTest extends TestCase
{
    public function testExecSelectAndNonSelect(): void
    {
        $orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);

        $res = $orm->exec('CREATE TABLE t_versao_test (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)');
        $this->assertNull($res);

        $ins = $orm->exec('INSERT INTO t_versao_test (name) VALUES (?)', ['Alice']);
        $this->assertNull($ins);

        $rows = $orm->exec('SELECT id, name FROM t_versao_test');
        $this->assertIsArray($rows);
        $this->assertCount(1, $rows);
        $this->assertArrayHasKey('name', $rows[0]);
        $this->assertSame('Alice', $rows[0]['name']);
    }

    public function testTableReturnsQueryBuilder(): void
    {
        $orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
        $qb = $orm->table('any_table');
        $this->assertInstanceOf(QueryBuilder::class, $qb);
    }

    public function testSetAndGetTimezone(): void
    {
        $orm = new VersaORM();
        $orm->setTimezone('UTC');
        $this->assertSame('UTC', $orm->getTimezone());

        $orm->setTimezone('America/Mexico_City');
        $this->assertSame('America/Mexico_City', $orm->getTimezone());
    }

    public function testRawAliasCallsExec(): void
    {
        $orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
        $res = $orm->raw('SELECT 1 as v');
        $this->assertIsArray($res);
        $this->assertSame('1', (string) $res[0]['v']);
    }

    public function testSetAndGetConfig(): void
    {
        $orm = new VersaORM();
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:'];
        $orm->setConfig($cfg);
        $this->assertSame($cfg, $orm->getConfig());
    }

    public function testMetricsAndResetAreCallable(): void
    {
        $orm = new VersaORM(['engine' => 'pdo']);

        $metrics = $orm->metrics();
        $this->assertIsArray($metrics);

        $orm->metricsReset();
        $this->assertTrue(true);
    }

    public function testAddTypeConverterDelegatesToVersaModel(): void
    {
        $orm = new VersaORM();

        // Ensure delegation does not throw
        VersaModel::addTypeConverter('test_conv', function ($s, $p, $v) {
            return $v;
        }, null);
        $orm->addTypeConverter('test_conv2', function ($s, $p, $v) {
            return $v;
        }, null);

        $this->assertTrue(true);
    }
}
