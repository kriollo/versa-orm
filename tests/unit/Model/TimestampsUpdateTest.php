<?php

declare(strict_types=1);

namespace VersaORM\Tests\Unit\Model;

use PHPUnit\Framework\TestCase;
use VersaORM\VersaModel;
use VersaORM\VersaORM;

/** @group sqlite */
final class TimestampsUpdateTest extends TestCase
{
    private static ?VersaORM $orm = null;

    public static function setUpBeforeClass(): void
    {
        self::$orm = new VersaORM(['driver' => 'sqlite', 'database' => ':memory:']);
        VersaModel::setORM(self::$orm);

        // Create test table
        self::$orm->exec('CREATE TABLE test_timestamps_update (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            created_at TEXT,
            updated_at TEXT
        )');
    }

    public function test_update_changes_updated_at(): void
    {
        $model = VersaModel::dispense('test_timestamps_update');
        $model->name = 'initial';

        $id = $model->store();
        static::assertNotNull($id);

        $rowBefore = self::$orm->exec('SELECT * FROM test_timestamps_update WHERE id = ?', [$id]);
        static::assertNotEmpty($rowBefore);
        $before = $rowBefore[0]['updated_at'] ?? null;
        // small sleep to ensure timestamp difference
        usleep(50000);
        $model->name = 'changed';
        $model->store();

        $rowAfter = self::$orm->exec('SELECT * FROM test_timestamps_update WHERE id = ?', [$id]);
        static::assertNotEmpty($rowAfter);
        $after = $rowAfter[0]['updated_at'] ?? null;

        static::assertNotNull($before);
        static::assertNotNull($after);
        static::assertNotSame($before, $after, 'updated_at should change after update');
    }
}
