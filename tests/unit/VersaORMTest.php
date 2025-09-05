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
        static::assertNull($res);

        $ins = $orm->exec('INSERT INTO t_versao_test (name) VALUES (?)', ['Alice']);
        static::assertNull($ins);

        $rows = $orm->exec('SELECT id, name FROM t_versao_test');
        static::assertIsArray($rows);
        static::assertCount(1, $rows);
        static::assertArrayHasKey('name', $rows[0]);
        static::assertSame('Alice', $rows[0]['name']);
    }

    public function testTableReturnsQueryBuilder(): void
    {
        $orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
        $qb = $orm->table('any_table');
        static::assertInstanceOf(QueryBuilder::class, $qb);
    }

    public function testSetAndGetTimezone(): void
    {
        $orm = new VersaORM();
        $orm->setTimezone('UTC');
        static::assertSame('UTC', $orm->getTimezone());

        $orm->setTimezone('America/Mexico_City');
        static::assertSame('America/Mexico_City', $orm->getTimezone());
    }

    public function testRawAliasCallsExec(): void
    {
        $orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
        $res = $orm->raw('SELECT 1 as v');
        static::assertIsArray($res);
        static::assertSame('1', (string) $res[0]['v']);
    }

    public function testSetAndGetConfig(): void
    {
        $orm = new VersaORM();
        $cfg = ['driver' => 'sqlite', 'database' => ':memory:'];
        $orm->setConfig($cfg);
        static::assertSame($cfg, $orm->getConfig());
    }

    public function testMetricsAndResetAreCallable(): void
    {
        $orm = new VersaORM(['engine' => 'pdo']);

        $metrics = $orm->metrics();
        static::assertIsArray($metrics);

        $orm->metricsReset();
        static::assertTrue(true);
    }

    public function testAddTypeConverterDelegatesToVersaModel(): void
    {
        $orm = new VersaORM();

        // Ensure delegation does not throw
        VersaModel::addTypeConverter('test_conv', fn($s, $p, $v) => $v, null);
        $orm->addTypeConverter('test_conv2', fn($s, $p, $v) => $v, null);

        static::assertTrue(true);
    }
}
