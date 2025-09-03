<?php

declare(strict_types=1);

namespace VersaORM\Tests\SQLite;

use VersaORM\VersaModel;

/** @group sqlite */
final class TimestampsCreateTest extends TestCase
{
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
