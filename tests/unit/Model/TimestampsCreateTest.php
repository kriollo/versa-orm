<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit\Model;

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/** @group sqlite */
final class TimestampsCreateTest extends TestCase
{
    private static ?VersaORM $orm = null;

    public static function setUpBeforeClass(): void
    {
        self::$orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
        VersaModel::setORM(self::$orm);

        // Create test table
        self::$orm->exec('CREATE TABLE test_timestamps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            created_at TEXT,
            updated_at TEXT
        )');
    }

    public function test_insert_sets_created_and_updated_timestamps(): void
    {
        // Usar el ORM configurado por TestCase (createSchema se ejecuta en setUp)
        $model = VersaModel::dispense('test_timestamps');
        $model->name = 'foo';

        $id = $model->store();

        static::assertNotNull($id);
        $row = self::$orm->exec('SELECT * FROM test_timestamps WHERE id = ?', [$id]);
        static::assertIsArray($row);
        static::assertNotEmpty($row);
        $record = $row[0];
        static::assertArrayHasKey('created_at', $record);
        static::assertArrayHasKey('updated_at', $record);
    }
}
